use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::{
    builder::pod::{PodBuilder, container::ContainerBuilder},
    crd::authentication::oidc,
    k8s_openapi::api::core::v1::EnvVar,
};

use super::{AddOidcVolumesSnafu, ConstructOidcWellKnownUrlSnafu, Error};
use crate::{
    crd::{COOKIE_PASSPHRASE_ENV, DruidRole, security::add_cert_to_jvm_trust_store_cmd},
    internal_secret::env_var_from_secret,
};

/// Type alias for Druid's OIDC client authentication options, opting in to the
/// `clientAuthenticationMethod` field via [`oidc::v1alpha1::ClientAuthenticationMethodOption`].
pub type DruidClientAuthenticationOptions =
    oidc::v1alpha1::ClientAuthenticationOptions<oidc::v1alpha1::ClientAuthenticationMethodOption>;

/// Creates OIDC authenticator config using the pac4j extension for Druid: <https://druid.apache.org/docs/latest/development/extensions-core/druid-pac4j>.
fn add_authenticator_config(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    oidc: &DruidClientAuthenticationOptions,
    config: &mut BTreeMap<String, Option<String>>,
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
        Some(r#"pac4j"#.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Oidc.authorizerName".to_string(),
        Some(r#"OidcAuthorizer"#.to_string()),
    );
    config.insert(
        "druid.auth.pac4j.cookiePassphrase".to_string(),
        Some(format!("${{env:{COOKIE_PASSPHRASE_ENV}}}").to_string()),
    );
    config.insert(
        "druid.auth.pac4j.oidc.clientID".to_string(),
        Some(format!("${{env:{oidc_client_id_env}}}").to_string()),
    );
    config.insert(
        "druid.auth.pac4j.oidc.clientSecret".to_string(),
        Some(format!("${{env:{oidc_client_secret_env}}}").to_string()),
    );
    config.insert(
        "druid.auth.pac4j.oidc.discoveryURI".to_string(),
        Some(well_known_url.to_string()),
    );
    config.insert(
        "druid.auth.pac4j.oidc.oidcClaim".to_string(),
        Some(provider.principal_claim.to_string()),
    );
    config.insert(
        "druid.auth.pac4j.oidc.scope".to_string(),
        Some(scopes.join(" ")),
    );

    // Serialize the enum to get the snake_case string representation
    let method_string =
        serde_json::to_value(oidc.product_specific_fields.client_authentication_method)
            .expect("serializing ClientAuthenticationMethod to string");
    let method_string = method_string
        .as_str()
        .expect("ClientAuthenticationMethod should serialize to a string");
    config.insert(
        "druid.auth.pac4j.oidc.clientAuthenticationMethod".to_string(),
        Some(method_string.to_string()),
    );

    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["DruidSystemAuthenticator", "Oidc"]"#.to_string()),
    );

    Ok(())
}

fn add_authorizer_config(config: &mut BTreeMap<String, Option<String>>) {
    config.insert(
        "druid.auth.authorizers".to_string(),
        Some(r#"["OidcAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
    );
    config.insert(
        "druid.auth.authorizer.OidcAuthorizer.type".to_string(),
        Some(r#"allowAll"#.to_string()),
    );
}

/// Creates the OIDC parts of the runtime.properties config file.
/// OIDC authentication is not configured on middlemanagers, because end users don't interact with them directly using the web console and
/// turning on OIDC will lead to problems with the communication with coordinators during data ingest.
pub fn generate_runtime_properties_config(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    oidc: &DruidClientAuthenticationOptions,
    role: &DruidRole,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    match role {
        DruidRole::MiddleManager => {
            config.insert(
                "druid.auth.authenticatorChain".to_string(),
                Some(r#"["DruidSystemAuthenticator"]"#.to_string()),
            );
        }
        _ => {
            add_authenticator_config(provider, oidc, config)?;
            add_authorizer_config(config)
        }
    }
    Ok(())
}

pub fn main_container_commands(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    command: &mut Vec<String>,
) {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.extend(add_cert_to_jvm_trust_store_cmd(&tls_ca_cert_mount_path))
    }
}

/// Mounts the OIDC credentials secret and the auto-generated internal secret containing the cookie passphrase.
/// Not necessary on middlemanagers, because OIDC is not configured on them.
pub fn get_env_var_mounts(
    role: &DruidRole,
    oidc: &DruidClientAuthenticationOptions,
    internal_secret_name: &str,
) -> Vec<EnvVar> {
    let mut envs = vec![];
    match role {
        DruidRole::MiddleManager => (),
        _ => {
            envs.extend(
                oidc::v1alpha1::AuthenticationProvider::client_credentials_env_var_mounts(
                    oidc.client_credentials_secret_ref.to_owned(),
                ),
            );
            envs.push(env_var_from_secret(
                internal_secret_name,
                None,
                COOKIE_PASSPHRASE_ENV,
            ))
        }
    }
    envs
}

pub fn add_volumes_and_mounts(
    provider: &oidc::v1alpha1::AuthenticationProvider,
    pb: &mut PodBuilder,
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
) -> Result<(), Error> {
    provider
        .tls
        .add_volumes_and_mounts(pb, vec![cb_druid, cb_prepare])
        .context(AddOidcVolumesSnafu)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use stackable_operator::commons::tls_verification::{Tls, TlsClientDetails};

    use super::*;

    #[rstest]
    #[case("/realms/sdp")]
    #[case("/realms/sdp/")]
    #[case("/realms/sdp/////")]
    fn test_add_authenticator_config(#[case] root_path: String) {
        use stackable_operator::{
            commons::tls_verification::{CaCert, TlsServerVerification, TlsVerification},
            crd::authentication::oidc,
        };

        let mut properties = BTreeMap::new();
        let provider = oidc::v1alpha1::AuthenticationProvider::new(
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
        );
        let oidc = DruidClientAuthenticationOptions {
            client_credentials_secret_ref: "nifi-keycloak-client".to_owned(),
            extra_scopes: vec![],
            product_specific_fields: oidc::v1alpha1::ClientAuthenticationMethodOption {
                client_authentication_method:
                    oidc::v1alpha1::ClientAuthenticationMethod::ClientSecretPost,
            },
        };

        add_authenticator_config(&provider, &oidc, &mut properties)
            .expect("OIDC config adding failed");

        assert_eq!(
            properties.get("druid.auth.authenticator.Oidc.type"),
            Some(&Some("pac4j".to_owned()))
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.oidcClaim"),
            Some(&Some("preferred_username".to_owned()))
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.scope"),
            Some(&Some("openid".to_owned()))
        );
        assert_eq!(
            properties.get("druid.auth.authenticator.Oidc.authorizerName"),
            Some(&Some("OidcAuthorizer".to_owned()))
        );
        assert_eq!(
            properties.get("druid.auth.authenticatorChain"),
            Some(&Some("[\"DruidSystemAuthenticator\", \"Oidc\"]".to_owned()))
        );
        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.discoveryURI"),
            Some(&Some(
                "https://keycloak.mycorp.org/realms/sdp/.well-known/openid-configuration"
                    .to_owned()
            ))
        );

        assert_eq!(
            properties.get("druid.auth.pac4j.oidc.clientAuthenticationMethod"),
            Some(&Some("client_secret_post".to_owned()))
        );
        assert!(properties.contains_key("druid.auth.pac4j.oidc.clientID"));
        assert!(properties.contains_key("druid.auth.pac4j.oidc.clientSecret"));
        assert!(properties.contains_key("druid.auth.pac4j.cookiePassphrase"));
    }
}
