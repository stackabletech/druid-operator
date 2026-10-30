use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::{
    crd::authentication::oidc,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
    v2::{builder::pod::container::EnvVarSet, types::kubernetes::SecretName},
};

use super::{ConstructOidcWellKnownUrlSnafu, Error, OidcVolumesSnafu};
use crate::{
    authentication::DruidClientAuthenticationOptions,
    crd::{
        COOKIE_PASSPHRASE_ENV, COOKIE_PASSPHRASE_SECRET_KEY, env_var_reference,
        security::add_cert_to_jvm_trust_store_cmd,
    },
};

const OIDC_AUTHORIZER: &str = "OidcAuthorizer";

/// Creates OIDC authenticator config using the pac4j extension for Druid: <https://druid.apache.org/docs/latest/development/extensions-core/druid-pac4j>.
fn add_authenticator_config(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    oidc: &DruidClientAuthenticationOptions,
    config: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    let well_known_url = &provider
        .well_known_config_url()
        .context(ConstructOidcWellKnownUrlSnafu)?;

    let (oidc_client_id_env, oidc_client_secret_env) =
        oidc::v1alpha1::AuthenticationProvider::client_credentials_env_names(
            &oidc.client_credentials_secret_ref,
        );

    let mut scopes = provider.scopes.clone();
    scopes.extend_from_slice(&oidc.extra_scopes);

    config.insert(
        "druid.auth.authenticator.Oidc.type".to_string(),
        r#"pac4j"#.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Oidc.authorizerName".to_string(),
        OIDC_AUTHORIZER.to_string(),
    );
    config.insert(
        "druid.auth.pac4j.cookiePassphrase".to_string(),
        env_var_reference(&*COOKIE_PASSPHRASE_ENV),
    );
    config.insert(
        "druid.auth.pac4j.oidc.clientID".to_string(),
        env_var_reference(oidc_client_id_env),
    );
    config.insert(
        "druid.auth.pac4j.oidc.clientSecret".to_string(),
        env_var_reference(oidc_client_secret_env),
    );
    config.insert(
        "druid.auth.pac4j.oidc.discoveryURI".to_string(),
        well_known_url.to_string(),
    );
    config.insert(
        "druid.auth.pac4j.oidc.oidcClaim".to_string(),
        provider.principal_claim.to_string(),
    );
    config.insert("druid.auth.pac4j.oidc.scope".to_string(), scopes.join(" "));

    let method_string = oidc
        .product_specific_fields
        .client_authentication_method
        .as_ref();
    config.insert(
        "druid.auth.pac4j.oidc.clientAuthenticationMethod".to_string(),
        method_string.to_string(),
    );

    super::set_authenticator_chain(config, &["Oidc"]);

    Ok(())
}

/// Creates the OIDC parts of the runtime.properties config file. A role that does not
/// authenticate its users with OIDC (`oidc_enabled` false) gets the system authenticator only.
pub(super) fn generate_runtime_properties_config(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    oidc: &DruidClientAuthenticationOptions,
    oidc_enabled: bool,
    config: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    if oidc_enabled {
        add_authenticator_config(provider, oidc, config)?;
        super::add_authorizer_config(config, OIDC_AUTHORIZER);
    } else {
        super::set_authenticator_chain(config, &[]);
    }
    Ok(())
}

pub(super) fn main_container_commands(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    command: &mut Vec<String>,
) {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.extend(add_cert_to_jvm_trust_store_cmd(&tls_ca_cert_mount_path))
    }
}

/// Mounts the OIDC credentials secret and the auto-generated internal secret containing the
/// cookie passphrase. Nothing for a role that does not authenticate its users with OIDC
/// (`oidc_enabled` false).
pub(super) fn get_env_var_mounts(
    oidc_enabled: bool,
    oidc: &DruidClientAuthenticationOptions,
    internal_secret_name: &SecretName,
) -> EnvVarSet {
    let mut env_vars = EnvVarSet::new();
    if oidc_enabled {
        for env_var in oidc::v1alpha1::AuthenticationProvider::client_credentials_env_var_mounts(
            oidc.client_credentials_secret_ref.to_owned(),
        ) {
            env_vars = env_vars.with_env_var(env_var).expect(
                "env_var name is valid because it is either OIDC_<16-hex-characters>_CLIENT_ID \
                 or OIDC_<16-hex-characters>_CLIENT_SECRET",
            );
        }
        env_vars = env_vars.with_secret_key_ref(
            &COOKIE_PASSPHRASE_ENV,
            internal_secret_name,
            &COOKIE_PASSPHRASE_SECRET_KEY,
        );
    }
    env_vars
}

/// The volumes of the OIDC provider's TLS CA certificate, if it has one, and their mounts.
pub(super) fn volumes_and_mounts(
    provider: &oidc::v1alpha1::AuthenticationProvider,
) -> Result<(Vec<Volume>, Vec<VolumeMount>), Error> {
    provider.tls.volumes_and_mounts().context(OidcVolumesSnafu)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use stackable_operator::commons::tls_verification::{
        CaCert, Tls, TlsClientDetails, TlsServerVerification, TlsVerification,
    };

    use super::*;

    fn test_provider(root_path: String) -> oidc::v1alpha1::AuthenticationProvider {
        oidc::v1alpha1::AuthenticationProvider::new(
            "keycloak.mycorp.org".to_owned().try_into().unwrap(),
            Some(443),
            root_path,
            TlsClientDetails {
                tls: Some(Tls {
                    verification: TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::WebPki {},
                    }),
                }),
            },
            "preferred_username".to_owned(),
            vec!["openid".to_owned()],
            Some(oidc::v1alpha1::IdentityProviderHint::Keycloak),
        )
    }

    fn test_options() -> DruidClientAuthenticationOptions {
        DruidClientAuthenticationOptions {
            client_credentials_secret_ref: "nifi-keycloak-client".to_owned(),
            extra_scopes: vec![],
            product_specific_fields: oidc::v1alpha1::ClientAuthenticationMethodOption {
                client_authentication_method:
                    oidc::v1alpha1::ClientAuthenticationMethod::ClientSecretPost,
            },
        }
    }

    #[rstest]
    #[case("/realms/sdp")]
    #[case("/realms/sdp/")]
    #[case("/realms/sdp/////")]
    fn test_add_authenticator_config(#[case] root_path: String) {
        let provider = test_provider(root_path);
        let oidc = test_options();
        let mut properties = BTreeMap::new();

        add_authenticator_config(&provider, &oidc, &mut properties)
            .expect("OIDC config adding failed");

        assert_eq!(
            properties.get("druid.auth.authenticator.Oidc.type"),
            Some(&"pac4j".to_owned())
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.oidcClaim"),
            Some(&"preferred_username".to_owned())
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.scope"),
            Some(&"openid".to_owned())
        );
        assert_eq!(
            properties.get("druid.auth.authenticator.Oidc.authorizerName"),
            Some(&"OidcAuthorizer".to_owned())
        );
        assert_eq!(
            properties.get("druid.auth.authenticatorChain"),
            Some(&"[\"DruidSystemAuthenticator\", \"Oidc\"]".to_owned())
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.discoveryURI"),
            Some(
                &"https://keycloak.mycorp.org/realms/sdp/.well-known/openid-configuration"
                    .to_owned()
            )
        );

        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.clientAuthenticationMethod"),
            Some(&"client_secret_post".to_owned())
        );
        assert!(properties.contains_key("druid.auth.pac4j.oidc.clientID"));
        assert!(properties.contains_key("druid.auth.pac4j.oidc.clientSecret"));
        assert!(properties.contains_key("druid.auth.pac4j.cookiePassphrase"));
    }

    /// The MiddleManager must not get an Oidc authenticator/authorizer, only the Druid system
    /// authenticator in the chain (OIDC on MiddleManagers breaks coordinator<->mm ingest).
    #[test]
    fn middlemanager_is_not_configured_for_oidc() {
        let provider = test_provider("/realms/sdp".to_owned());
        let oidc = test_options();
        let mut config = BTreeMap::new();

        generate_runtime_properties_config(&provider, &oidc, false, &mut config)
            .expect("generate runtime properties");

        assert_eq!(
            config.get("druid.auth.authenticatorChain"),
            Some(&r#"["DruidSystemAuthenticator"]"#.to_owned())
        );
        assert!(!config.contains_key("druid.auth.authenticator.Oidc.type"));
        assert!(!config.contains_key("druid.auth.authorizers"));
    }

    /// Every non-MiddleManager role gets the full Oidc authenticator and authorizer.
    #[test]
    fn non_middlemanager_is_configured_for_oidc() {
        let provider = test_provider("/realms/sdp".to_owned());
        let oidc = test_options();
        let mut config = BTreeMap::new();

        generate_runtime_properties_config(&provider, &oidc, true, &mut config)
            .expect("generate runtime properties");

        assert_eq!(
            config.get("druid.auth.authenticator.Oidc.type"),
            Some(&"pac4j".to_owned())
        );
        assert_eq!(
            config.get("druid.auth.authenticator.Oidc.authorizerName"),
            Some(&"OidcAuthorizer".to_owned())
        );
        assert!(config.contains_key("druid.auth.authorizers"));
    }

    fn internal_secret_name() -> SecretName {
        SecretName::from_str_unsafe("internal-secret")
    }

    /// The MiddleManager mounts no OIDC env vars (OIDC is not configured on it).
    #[test]
    fn middlemanager_gets_no_oidc_env_vars() {
        let oidc = test_options();

        let envs = get_env_var_mounts(false, &oidc, &internal_secret_name());

        assert!(envs.iter().next().is_none());
    }

    /// Non-MiddleManager roles mount the OIDC credentials and the cookie-passphrase env var.
    #[test]
    fn non_middlemanager_gets_oidc_env_vars() {
        let oidc = test_options();

        let envs = get_env_var_mounts(true, &oidc, &internal_secret_name());

        assert!(
            envs.get(&COOKIE_PASSPHRASE_ENV).is_some(),
            "expected the cookie passphrase env var to be mounted"
        );
    }
}
