//! Build-side rendering of the validated authentication decision
//! ([`DruidAuthenticationConfig`]).
//!
//! These functions turn the validated authentication decision into Kubernetes/config artifacts
//! (runtime.properties, container commands, volumes and mounts, env vars). They live in the build
//! step so the validated [`DruidAuthenticationConfig`] type carries no rendering logic.

use std::collections::BTreeMap;

use snafu::Snafu;
use stackable_operator::{
    builder::pod::{PodBuilder, container::ContainerBuilder},
    k8s_openapi::api::core::v1::EnvVar,
};

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::validate::ValidatedCluster,
    crd::{DruidRole, env_var_reference, security::INTERNAL_INITIAL_CLIENT_PASSWORD_ENV},
    internal_secret::{build_shared_internal_secret_name, env_var_from_secret},
};

pub mod ldap;
pub mod oidc;

// It seems this needs to be the same password for Druid to work, so we re-use the existing env variable.
const ESCALATOR_INTERNAL_CLIENT_PASSWORD_ENV: &str = INTERNAL_INITIAL_CLIENT_PASSWORD_ENV;

// Authorizer/authenticator names and types used in the Druid runtime.properties auth config.
// These are shared across the LDAP and OIDC providers (in the child modules).
const DRUID_SYSTEM_AUTHORIZER: &str = "DruidSystemAuthorizer";
const DRUID_SYSTEM_AUTHENTICATOR: &str = "DruidSystemAuthenticator";
/// The `allowAll` authorizer type.
const AUTHORIZER_TYPE_ALLOW_ALL: &str = "allowAll";
/// The `basic` authenticator/escalator type.
const AUTHENTICATOR_TYPE_BASIC: &str = "basic";

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to create LDAP endpoint url."))]
    ConstructLdapEndpointUrl {
        source: stackable_operator::crd::authentication::ldap::v1alpha1::Error,
    },

    #[snafu(display("failed to create the OIDC well-known url."))]
    ConstructOidcWellKnownUrl {
        source: stackable_operator::crd::authentication::oidc::v1alpha1::Error,
    },

    #[snafu(display("failed to add LDAP Volumes and VolumeMounts to the Pod and containers"))]
    AddLdapVolumes {
        source: stackable_operator::crd::authentication::ldap::v1alpha1::Error,
    },

    #[snafu(display("failed to add OIDC Volumes and VolumeMounts to the Pod and containers"))]
    AddOidcVolumes {
        source: stackable_operator::commons::tls_verification::TlsClientDetailsError,
    },

    #[snafu(display(
        "failed to access bind credentials although they are required for LDAP to work"
    ))]
    MissingLdapBindCredentials,
}

/// Configures the given provider authorizer (e.g. `"LdapAuthorizer"`) alongside the Druid system
/// authorizer, both with the `allowAll` authorizer type. Shared by the LDAP and OIDC providers.
fn add_authorizer_config(config: &mut BTreeMap<String, String>, authorizer_name: &str) {
    config.insert(
        "druid.auth.authorizers".to_string(),
        format!(r#"["{authorizer_name}", "{DRUID_SYSTEM_AUTHORIZER}"]"#),
    );
    config.insert(
        format!("druid.auth.authorizer.{authorizer_name}.type"),
        AUTHORIZER_TYPE_ALLOW_ALL.to_string(),
    );
}

/// Sets `druid.auth.authenticatorChain` to the Druid system authenticator followed by the given
/// provider authenticators (e.g. `["Ldap"]`). Shared by the LDAP and OIDC providers.
fn set_authenticator_chain(
    config: &mut BTreeMap<String, String>,
    provider_authenticators: &[&str],
) {
    let authenticators: Vec<String> = std::iter::once(DRUID_SYSTEM_AUTHENTICATOR)
        .chain(provider_authenticators.iter().copied())
        .map(|name| format!("\"{name}\""))
        .collect();
    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        format!("[{}]", authenticators.join(", ")),
    );
}

/// Creates the authentication and authorization parts of the runtime.properties config file.
/// Configuration related to TLS authentication is added in `controller::build::security`.
pub fn generate_runtime_properties_config(
    auth: &DruidAuthenticationConfig,
    role: &DruidRole,
) -> Result<BTreeMap<String, String>> {
    let mut config: BTreeMap<String, String> = BTreeMap::new();

    match auth {
        DruidAuthenticationConfig::Ldap { provider } => {
            generate_common_runtime_properties_config(&mut config);
            ldap::generate_runtime_properties_config(provider, &mut config)?
        }
        DruidAuthenticationConfig::Oidc { provider, oidc } => {
            generate_common_runtime_properties_config(&mut config);
            oidc::generate_runtime_properties_config(provider, oidc, role, &mut config)?
        }
        DruidAuthenticationConfig::Tls {} => (),
    }
    Ok(config)
}

/// Creates authentication config that is required by LDAP and OIDC and doesn't depend on user input.
fn generate_common_runtime_properties_config(config: &mut BTreeMap<String, String>) {
    add_druid_system_authenticator_config(config);
    add_escalator_config(config);

    config.insert(
        "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
        AUTHORIZER_TYPE_ALLOW_ALL.to_string(),
    );
}

pub fn main_container_commands(auth: &DruidAuthenticationConfig) -> Vec<String> {
    let mut command = vec![];
    if let DruidAuthenticationConfig::Oidc { provider, .. } = auth {
        oidc::main_container_commands(provider, &mut command)
    }
    command
}

pub fn prepare_container_commands(auth: &DruidAuthenticationConfig) -> Vec<String> {
    let mut command = vec![];
    if let DruidAuthenticationConfig::Ldap { provider } = auth {
        ldap::prepare_container_commands(provider, &mut command)
    }
    command
}

pub fn get_env_var_mounts(
    auth: &DruidAuthenticationConfig,
    cluster: &ValidatedCluster,
    role: &DruidRole,
) -> Vec<EnvVar> {
    let mut envs = vec![];
    let internal_secret_name = build_shared_internal_secret_name(cluster);
    envs.push(env_var_from_secret(
        &internal_secret_name,
        None,
        INTERNAL_INITIAL_CLIENT_PASSWORD_ENV,
    ));

    if let DruidAuthenticationConfig::Oidc { oidc, .. } = auth {
        envs.extend(oidc::get_env_var_mounts(role, oidc, &internal_secret_name))
    }
    envs
}

pub fn add_volumes_and_mounts(
    auth: &DruidAuthenticationConfig,
    pb: &mut PodBuilder,
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
) -> Result<()> {
    match auth {
        DruidAuthenticationConfig::Ldap { provider } => {
            ldap::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
        }
        DruidAuthenticationConfig::Oidc { provider, .. } => {
            oidc::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
        }
        DruidAuthenticationConfig::Tls {} => Ok(()),
    }
}

/// Creates the authenticatior config for the internal communication by Druid processes using basic auth.
/// When using LDAP or OIDC the DruidSystemAuthenticator is always tried first and skipped if no basic auth credentials were supplied.
/// We don't want to create an admin user for the internal authentication, so this line is left out of the config:
/// # druid.auth.authenticator.DruidSystemAuthenticator.initialAdminPassword: XXX
fn add_druid_system_authenticator_config(config: &mut BTreeMap<String, String>) {
    config.insert(
        "druid.auth.authenticator.DruidSystemAuthenticator.type".to_string(),
        AUTHENTICATOR_TYPE_BASIC.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.DruidSystemAuthenticator.credentialsValidator.type".to_string(),
        "metadata".to_string(),
    );

    config.insert(
        "druid.auth.authenticator.DruidSystemAuthenticator.initialInternalClientPassword"
            .to_string(),
        env_var_reference(INTERNAL_INITIAL_CLIENT_PASSWORD_ENV),
    );
    config.insert(
        "druid.auth.authenticator.DruidSystemAuthenticator.authorizerName".to_string(),
        DRUID_SYSTEM_AUTHORIZER.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.DruidSystemAuthenticator.skipOnFailure".to_string(),
        "true".to_string(),
    );
}

/// Creates the escalator config: <https://druid.apache.org/docs/latest/operations/auth/#escalator>.
/// This configures Druid processes to use the basic auth authentication added in `add_druid_system_authenticator_config` for internal communication.
fn add_escalator_config(config: &mut BTreeMap<String, String>) {
    config.insert(
        "druid.escalator.type".to_string(),
        AUTHENTICATOR_TYPE_BASIC.to_string(),
    );
    config.insert(
        "druid.escalator.internalClientUsername".to_string(),
        "druid_system".to_string(),
    );
    config.insert(
        "druid.escalator.internalClientPassword".to_string(),
        env_var_reference(ESCALATOR_INTERNAL_CLIENT_PASSWORD_ENV),
    );
    config.insert(
        "druid.escalator.authorizerName".to_string(),
        DRUID_SYSTEM_AUTHORIZER.to_string(),
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crd::authentication::{AuthenticationClassResolved, AuthenticationClassesResolved};

    fn ldap_auth_config() -> DruidAuthenticationConfig {
        DruidAuthenticationConfig::from_auth_classes(AuthenticationClassesResolved {
            auth_classes: vec![AuthenticationClassResolved::Ldap {
                auth_class_name: "ldap".to_string(),
                provider: serde_yaml::from_str::<
                    stackable_operator::crd::authentication::ldap::v1alpha1::AuthenticationProvider,
                >(
                    "
                hostname: openldap
                searchBase: ou=users,dc=example,dc=org
                searchFilter: (uid=%s)
                ",
                )
                .unwrap(),
            }],
        })
        .unwrap()
    }

    #[test]
    fn test_ldap_config_is_added() {
        let got = generate_runtime_properties_config(&ldap_auth_config(), &DruidRole::Coordinator)
            .unwrap();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }

    /// The Druid system authenticator, escalator and system authorizer are always configured
    /// alongside the provider-specific (LDAP/OIDC) config.
    #[test]
    fn common_system_auth_config_is_added() {
        let got = generate_runtime_properties_config(&ldap_auth_config(), &DruidRole::Coordinator)
            .unwrap();

        assert_eq!(
            got.get("druid.auth.authenticator.DruidSystemAuthenticator.type"),
            Some(&"basic".to_owned())
        );
        assert_eq!(
            got.get("druid.auth.authenticator.DruidSystemAuthenticator.authorizerName"),
            Some(&"DruidSystemAuthorizer".to_owned())
        );
        assert_eq!(got.get("druid.escalator.type"), Some(&"basic".to_owned()));
        assert_eq!(
            got.get("druid.auth.authorizer.DruidSystemAuthorizer.type"),
            Some(&"allowAll".to_owned())
        );
    }

    /// Pure TLS authentication is rendered in `controller::build::security`, so the auth module
    /// contributes nothing to runtime.properties.
    #[test]
    fn tls_only_produces_no_runtime_properties() {
        let got = generate_runtime_properties_config(
            &DruidAuthenticationConfig::Tls {},
            &DruidRole::Broker,
        )
        .unwrap();

        assert!(got.is_empty());
    }
}
