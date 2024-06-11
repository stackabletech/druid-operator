use std::collections::BTreeMap;

use snafu::Snafu;
use stackable_druid_crd::authentication::ResolvedAuthenticationClass;

pub mod ldap;
pub mod oidc;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateOidcEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
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
    ) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        self.add_druid_system_authenticator_config(&mut config);
        self.add_escalator_config(&mut config);

        if let Err(err) = match self.resolved_auth_class.clone() {
            ResolvedAuthenticationClass::Ldap {
                auth_class_name: _,
                provider,
            } => ldap::generate_runtime_properties_config(provider, &mut config),
            ResolvedAuthenticationClass::Oidc {
                auth_class_name: _ ,
                provider,
                oidc: _,
            } => oidc::generate_runtime_properties_config(provider, &mut config),
            ResolvedAuthenticationClass::Tls {
                auth_class_name: _,
                provider: _,
            } => Ok(()),
        } {
            return Err(err)
        }
        Ok(config)
    }

    pub fn prepare_container_commands(
&self
    ) -> Vec<String> {
        let mut command = vec![];
        match self.resolved_auth_class.clone() {
            ResolvedAuthenticationClass::Ldap {
                auth_class_name,
                provider,
            } => ldap::prepare_container_commands(auth_class_name, provider, &mut command),
            _ => ()
        }
        command
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
            Some(r#"${env:{ENV_INTERNAL_SECRET}}"#.to_string()),
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
            Some(r#"${env:{ENV_INTERNAL_SECRET}}"#.to_string()),
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

        let got = auth_settings.generate_runtime_properties_config().unwrap();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
