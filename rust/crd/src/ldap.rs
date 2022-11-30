use std::collections::BTreeMap;

use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::commons::ldap::LdapAuthenticationProvider;

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    provider: LdapAuthenticationProvider,
}

impl DruidLdapSettings {
    pub fn new_from(
        resolved_authentication_config: &[AuthenticationClassProvider],
    ) -> Option<DruidLdapSettings> {
        resolved_authentication_config
            .iter()
            .find_map(|acc| match acc {
                AuthenticationClassProvider::Ldap(provider) => Some(DruidLdapSettings {
                    provider: provider.clone(),
                }),
                _ => None,
            })
    }

    // TODO: tests around this
    fn get_port(&self) -> u16 {
        if let Some(port) = self.provider.port {
            port
        } else {
            1337 // TODO: proper port, depends on whether TLS is defined etc...
        }
    }

    pub fn generate_runtime_properties_config_lines(&self) -> BTreeMap<String, Option<String>> {
        let mut lines: BTreeMap<String, Option<String>> = BTreeMap::new();

        // TODO: handle login credentials differently, don't hardcode them

        lines.insert(
            "druid.auth.authenticatorChain".to_string(),
            Some(r#"["ldap"]"#.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.type".to_string(),
            Some("basic".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.enableCacheNotifications".to_string(),
            Some("true".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.type".to_string(),
            Some("ldap".to_string()),
        );

        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.url".to_string(),
            Some(format!(
                "ldap://{}:{}",
                self.provider.hostname,
                self.get_port()
            )),
        );

        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.baseDn".to_string(),
            Some(self.provider.search_base.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.userSearch".to_string(),
            Some(self.provider.search_filter.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.userAttribute".to_string(),
            Some(self.provider.ldap_field_names.uid.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.authorizeQueryContextParams".to_string(),
            Some("true".to_string()),
        );

        //# Escalator
        lines.insert(
            "druid.escalator.type".to_string(),
            Some("basic".to_string()),
        );

        // TODO: set envs
        /*
            LDAP_ADMIN_USER = uid=admin,ou=Users,dc=example,dc=org
            LDAP_ADMIN_PASSWORD = admin
            LDAP_INTERNAL_PASSWORD = druidsystem
            LDAP_INTERNAL_USER = druid_system
        */
        /*
        lines.insert("druid.dynamic.config.provider".to_string(), Some(r#"{
            "type": "environment",
            "variables": {
              "druid.auth.authenticator.ldap.credentialsValidator.bindUser": "LDAP_ADMIN_USER",
              "druid.auth.authenticator.ldap.credentialsValidator.bindPassword": "LDAP_ADMIN_PASSWORD",
              "druid.auth.authenticator.ldap.initialAdminPassword": "LDAP_ADMIN_PASSWORD",
              "druid.auth.authenticator.ldap.initialInternalClientPassword": "LDAP_INTERNAL_PASSWORD",
              "druid.escalator.internalClientUsername": "LDAP_INTERNAL_USER",
              "druid.escalator.internalClientPassword": "LDAP_INTERNAL_PASSWORD"
            }
          }"#.replace('\n', "").replace(' ', "")));
        */
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindUser".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_ADMIN_USER" }"#.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindPassword".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_ADMIN_PASSWORD" }"#.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialAdminPassword".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_ADMIN_PASSWORD" }"#.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialInternalClientPassword".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_INTERNAL_PASSWORD" }"#.to_string()),
        );
        lines.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_INTERNAL_USER" }"#.to_string()),
        );
        lines.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some(r#"{ "type": "environment", "variable": "LDAP_INTERNAL_PASSWORD" }"#.to_string()),
        );

        lines
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use stackable_operator::commons::ldap::LdapFieldNames;

    #[test]
    fn test_ldap_settings_are_added() {
        let ldap_settings = DruidLdapSettings {
            provider: LdapAuthenticationProvider {
                hostname: "".to_string(),
                port: None,
                search_base: "".to_string(),
                search_filter: "".to_string(),
                ldap_field_names: LdapFieldNames::default(),
                bind_credentials: None,
                tls: None,
            },
        };

        //let expected: BTreeMap<String, Option<String>> = BTreeMap::new();

        let got = ldap_settings.generate_runtime_properties_config_lines();

        assert_ne!(got.len(), 0);
    }
}
