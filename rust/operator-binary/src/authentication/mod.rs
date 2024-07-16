use std::collections::BTreeMap;

use snafu::Snafu;
use stackable_druid_crd::{
    authentication::{AuthenticationClassResolved, AuthenticationClassesResolved},
    security::{ESCALATOR_INTERNAL_CLIENT_PASSWORD_ENV, INTERNAL_INITIAL_CLIENT_PASSWORD_ENV},
    DruidCluster, DruidRole,
};
use stackable_operator::{
    builder::pod::{container::ContainerBuilder, PodBuilder},
    commons::authentication::{
        ldap::AuthenticationProvider as LdapAuthenticationProvider,
        oidc::{AuthenticationProvider as OidcAuthenticationProvider, ClientAuthenticationOptions},
    },
    k8s_openapi::api::core::v1::EnvVar,
};

pub mod ldap;
pub mod oidc;

use crate::internal_secret::{build_shared_internal_secret_name, env_var_from_secret};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to create LDAP endpoint url."))]
    CreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
    #[snafu(display("failed to create LDAP endpoint url."))]
    CreateOidcEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
    #[snafu(display("failed to add LDAP Volumes and VolumeMounts to the Pod and containers"))]
    AddLdapVolumes {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
    #[snafu(display("failed to add OIDC Volumes and VolumeMounts to the Pod and containers"))]
    AddOidcVolumes {
        source: stackable_operator::commons::authentication::tls::TlsClientDetailsError,
    },
    #[snafu(display(
        "failed to access bind credentials although they are required for LDAP to work"
    ))]
    MissingLdapBindCredentials,
}

#[derive(Clone, Debug)]
pub enum DruidAuthenticationConfig {
    Tls {},
    Ldap {
        auth_class_name: String,
        provider: LdapAuthenticationProvider,
    },
    Oidc {
        auth_class_name: String,
        provider: OidcAuthenticationProvider,
        oidc: ClientAuthenticationOptions,
    },
}

impl DruidAuthenticationConfig {
    pub fn try_from(
        auth_classes_resolved: AuthenticationClassesResolved,
    ) -> Result<Option<Self>, Error> {
        // Currently only one auth mechanism is supported in Druid. This is checked in
        // rust/crd/src/authentication.rs and just a fail-safe here. For Future changes,
        // this is not just a "from" without error handling
        match auth_classes_resolved.auth_classes.first() {
            None => Ok(None),
            Some(auth_class_resolved) => match &auth_class_resolved {
                AuthenticationClassResolved::Tls { .. } => Ok(Some(Self::Tls {})),
                AuthenticationClassResolved::Ldap {
                    auth_class_name,
                    provider,
                } => Ok(Some(Self::Ldap {
                    auth_class_name: auth_class_name.to_string(),
                    provider: provider.clone(),
                })),
                AuthenticationClassResolved::Oidc {
                    auth_class_name,
                    provider,
                    oidc,
                } => Ok(Some(Self::Oidc {
                    auth_class_name: auth_class_name.to_string(),
                    provider: provider.clone(),
                    oidc: oidc.clone(),
                })),
            },
        }
    }

    /// Creates the authentication and authorization parts of the runtime.properties config file.
    /// Configuration related to TLS authentication is added in `crd/security.rs`
    pub fn generate_runtime_properties_config(
        &self,
        role: &DruidRole,
    ) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        match self {
            DruidAuthenticationConfig::Ldap { provider, .. } => {
                self.generate_common_runtime_properties_config(&mut config);
                ldap::generate_runtime_properties_config(provider, &mut config)?
            }
            DruidAuthenticationConfig::Oidc { provider, oidc, .. } => {
                self.generate_common_runtime_properties_config(&mut config);
                oidc::generate_runtime_properties_config(provider, oidc, role, &mut config)?
            }
            DruidAuthenticationConfig::Tls { .. } => (),
        }
        Ok(config)
    }

    /// Creates authentication config that is required by LDAP and OIDC and doesn't depend on user input.
    fn generate_common_runtime_properties_config(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
    ) {
        self.add_druid_system_authenticator_config(config);
        self.add_escalator_config(config);

        config.insert(
            "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
    }

    pub fn main_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let DruidAuthenticationConfig::Oidc {
            auth_class_name,
            provider,
            ..
        } = self
        {
            oidc::main_container_commands(auth_class_name, provider, &mut command)
        }
        command
    }

    pub fn prepare_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let DruidAuthenticationConfig::Ldap {
            auth_class_name,
            provider,
        } = self
        {
            ldap::prepare_container_commands(auth_class_name, provider, &mut command)
        }
        command
    }

    pub fn get_env_var_mounts(&self, druid: &DruidCluster, role: &DruidRole) -> Vec<EnvVar> {
        let mut envs = vec![];
        let internal_secret_name = build_shared_internal_secret_name(druid);
        envs.push(env_var_from_secret(
            &internal_secret_name,
            None,
            INTERNAL_INITIAL_CLIENT_PASSWORD_ENV,
        ));

        if let DruidAuthenticationConfig::Oidc { oidc, .. } = self {
            envs.extend(oidc::get_env_var_mounts(role, oidc, &internal_secret_name))
        }
        envs
    }

    pub fn add_volumes_and_mounts(
        &self,
        pb: &mut PodBuilder,
        cb_druid: &mut ContainerBuilder,
        cb_prepare: &mut ContainerBuilder,
    ) -> Result<(), Error> {
        match self {
            DruidAuthenticationConfig::Ldap { provider, .. } => {
                ldap::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
            }
            DruidAuthenticationConfig::Oidc { provider, .. } => {
                oidc::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
            }
            DruidAuthenticationConfig::Tls { .. } => Ok(()),
        }
    }

    /// Creates the authenticatior config for the internal communication by Druid processes using basic auth.
    /// When using LDAP or OIDC the DruidSystemAuthenticator is always tried first and skipped if no basic auth credentials were supplied.
    /// We don't want to create an admin user for the internal authentication, so this line is left out of the config:
    /// # druid.auth.authenticator.DruidSystemAuthenticator.initialAdminPassword: XXX
    fn add_druid_system_authenticator_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        const PREFIX: &str = "druid.auth.authenticator.DruidSystemAuthenticator";

        config.insert(format!("{PREFIX}.type"), Some("basic".to_string()));
        config.insert(
            format!("{PREFIX}.credentialsValidator.type"),
            Some("metadata".to_string()),
        );

        config.insert(
            format!("{PREFIX}.initialInternalClientPassword"),
            Some(format!("${{env:{INTERNAL_INITIAL_CLIENT_PASSWORD_ENV}}}").to_string()),
        );
        config.insert(
            format!("{PREFIX}.authorizerName"),
            Some("DruidSystemAuthorizer".to_string()),
        );
        config.insert(format!("{PREFIX}.skipOnFailure"), Some("true".to_string()));
    }

    /// Creates the escalator config: https://druid.apache.org/docs/latest/operations/auth/#escalator.
    /// This configures Druid processes to use the basic auth authentication added in `add_druid_system_authenticator_config` for internal communication.
    fn add_escalator_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            "druid.escalator.type".to_string(),
            Some("basic".to_string()),
        );
        config.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some("druid_system".to_string()),
        );
        config.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some(format!("${{env:{ESCALATOR_INTERNAL_CLIENT_PASSWORD_ENV}}}").to_string()),
        );
        config.insert(
            "druid.escalator.authorizerName".to_string(),
            Some("DruidSystemAuthorizer".to_string()),
        );
    }
}

#[cfg(test)]
mod test {
    use stackable_operator::commons::authentication::ldap::AuthenticationProvider as LdapAuthenticationProvider;

    use super::*;

    #[test]
    fn test_ldap_config_is_added() {
        let auth_config = DruidAuthenticationConfig::try_from(AuthenticationClassesResolved {
            auth_classes: vec![AuthenticationClassResolved::Ldap {
                auth_class_name: "ldap".to_string(),
                provider: serde_yaml::from_str::<LdapAuthenticationProvider>(
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
        .unwrap();

        let role = DruidRole::Coordinator;

        let got = auth_config
            .generate_runtime_properties_config(&role)
            .unwrap();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
