use std::collections::BTreeMap;

use snafu::Snafu;
use stackable_druid_crd::{
    authentication::ResolvedAuthenticationClass, DruidCluster, DruidRole, ENV_INTERNAL_SECRET,
};
use stackable_operator::{
    builder::pod::{container::ContainerBuilder, PodBuilder},
    k8s_openapi::api::core::v1::EnvVar,
};

use crate::internal_secret::{build_shared_internal_secret_name, env_var_from_secret};

pub mod ldap;
pub mod oidc;

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
pub struct DruidAuthenticationSettings {
    pub resolved_auth_class: ResolvedAuthenticationClass,
}

impl DruidAuthenticationSettings {
    pub fn new_from(
        resolved_auth_class_opt: Option<ResolvedAuthenticationClass>,
    ) -> Option<DruidAuthenticationSettings> {
        if let Some(resolved_auth_class) = resolved_auth_class_opt {
            return Some(DruidAuthenticationSettings {
                resolved_auth_class,
            });
        }
        None
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

        match self.resolved_auth_class.clone() {
            ResolvedAuthenticationClass::Ldap {
                auth_class_name: _,
                provider,
            } => ldap::generate_runtime_properties_config(provider, &mut config)?,
            ResolvedAuthenticationClass::Oidc {
                auth_class_name: _,
                provider,
                oidc,
            } => oidc::generate_runtime_properties_config(provider, oidc, role, &mut config)?,
            ResolvedAuthenticationClass::Tls {
                auth_class_name: _,
                provider: _,
            } => (),
        }
        Ok(config)
    }

    pub fn main_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let ResolvedAuthenticationClass::Oidc {
            auth_class_name,
            provider,
            oidc: _,
        } = self.resolved_auth_class.clone()
        {
            oidc::main_container_commands(auth_class_name, provider, &mut command)
        }
        command
    }

    pub fn prepare_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let ResolvedAuthenticationClass::Ldap {
            auth_class_name,
            provider,
        } = self.resolved_auth_class.clone()
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
            ENV_INTERNAL_SECRET,
        ));

        if let ResolvedAuthenticationClass::Oidc {
            auth_class_name: _,
            provider: _,
            oidc,
        } = self.resolved_auth_class.clone()
        {
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
        match self.resolved_auth_class.clone() {
            ResolvedAuthenticationClass::Ldap {
                auth_class_name: _,
                provider,
            } => ldap::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare),
            ResolvedAuthenticationClass::Oidc {
                auth_class_name: _,
                provider,
                oidc: _obj,
            } => oidc::add_volumes_and_mounts(provider, pb, cb_druid, cb_prepare),
            ResolvedAuthenticationClass::Tls {
                auth_class_name: _,
                provider: _,
            } => Ok(()),
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

    pub fn oidc_enabled(&self) -> bool {
        if let ResolvedAuthenticationClass::Oidc {
            auth_class_name: _,
            provider: _,
            oidc: _,
        } = self.resolved_auth_class.clone()
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use stackable_operator::commons::authentication::ldap::AuthenticationProvider as LdapAuthenticationProvider;

    use super::*;

    #[test]
    fn test_ldap_settings_are_added() {
        let auth_settings = DruidAuthenticationSettings {
            resolved_auth_class: ResolvedAuthenticationClass::Ldap {
                auth_class_name: "ldap".to_string(),
                provider: serde_yaml::from_str::<LdapAuthenticationProvider>(
                    "
                hostname: openldap
                searchBase: ou=users,dc=example,dc=org
                searchFilter: (uid=%s)
                ",
                )
                .unwrap(),
            },
        };

        let role = DruidRole::Coordinator;

        let got = auth_settings
            .generate_runtime_properties_config(&role)
            .unwrap();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
