use std::collections::BTreeMap;

use snafu::Snafu;
use stackable_druid_crd::{
    authentication::{AuthenticationClassResolved, AuthenticationClassesResolved},
    DruidCluster, DruidRole, ENV_INTERNAL_SECRET,
};
use stackable_operator::{
    builder::pod::{container::ContainerBuilder, PodBuilder},
    commons::authentication::{
        ldap,
        oidc::{self, ClientAuthenticationOptions},
    },
    k8s_openapi::api::core::v1::EnvVar,
};

pub mod ldap_;
pub mod oidc_;

use crate::internal_secret::{build_shared_internal_secret_name, env_var_from_secret};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    CreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
    #[snafu(display("Failed to create LDAP endpoint url."))]
    CreateOidcEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
    #[snafu(display("Failed to add LDAP Volumes and VolumeMounts to the Pod and containers"))]
    AddLdapVolumes {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
    #[snafu(display("Failed to add OIDC Volumes and VolumeMounts to the Pod and containers"))]
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
        provider: ldap::AuthenticationProvider,
    },
    Oidc {
        auth_class_name: String,
        provider: oidc::AuthenticationProvider,
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

    pub fn generate_runtime_properties_config(
        &self,
        role: &DruidRole,
    ) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        self.add_druid_system_authenticator_config(&mut config);
        self.add_escalator_config(&mut config);

        config.insert(
            "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );

        match self {
            DruidAuthenticationConfig::Ldap { provider, .. } => {
                ldap_::generate_runtime_properties_config(provider, &mut config)?
            }
            DruidAuthenticationConfig::Oidc { provider, oidc, .. } => {
                oidc_::generate_runtime_properties_config(provider, oidc, role, &mut config)?
            }
            DruidAuthenticationConfig::Tls { .. } => (),
        }
        Ok(config)
    }

    pub fn main_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let DruidAuthenticationConfig::Oidc {
            auth_class_name,
            provider,
            ..
        } = self
        {
            oidc_::main_container_commands(auth_class_name, provider, &mut command)
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
            ldap_::prepare_container_commands(auth_class_name, provider, &mut command)
        }
        command
    }

    pub fn get_env_var_mounts(&self, druid: &DruidCluster, role: &DruidRole) -> Vec<EnvVar> {
        let mut envs = vec![];
        let internal_secret_name = build_shared_internal_secret_name(druid);
        envs.push(env_var_from_secret(
            &internal_secret_name,
            None,
            ENV_INTERNAL_SECRET,
        ));

        if let DruidAuthenticationConfig::Oidc { oidc, .. } = self {
            envs.extend(oidc_::get_env_var_mounts(role, oidc, &internal_secret_name))
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
                ldap_::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
            }
            DruidAuthenticationConfig::Oidc { provider, .. } => {
                oidc_::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare)
            }
            DruidAuthenticationConfig::Tls { .. } => Ok(()),
        }
    }

    fn add_druid_system_authenticator_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        const PREFIX: &str = "druid.auth.authenticator.DruidSystemAuthenticator";

        config.insert(format!("{PREFIX}.type"), Some("basic".to_string()));
        config.insert(
            format!("{PREFIX}.credentialsValidator.type"),
            Some("metadata".to_string()),
        );

        // this line is left out, as we don't want to create an admin user
        // # druid.auth.authenticator.DruidSystemAuthenticator.initialAdminPassword: XXX

        config.insert(
            format!("{PREFIX}.initialInternalClientPassword"),
            Some(r#"${env:INTERNAL_SECRET}"#.to_string()),
        );
        config.insert(
            format!("{PREFIX}.authorizerName"),
            Some("DruidSystemAuthorizer".to_string()),
        );
        config.insert(format!("{PREFIX}.skipOnFailure"), Some("true".to_string()));
    }

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
            Some(r#"${env:INTERNAL_SECRET}"#.to_string()),
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
