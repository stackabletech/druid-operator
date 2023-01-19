use std::collections::BTreeMap;

use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::commons::ldap::LdapAuthenticationProvider;

use crate::authentication::ResolvedAuthenticationClasses;

const DEFAULT_LDAP_PORT: u16 = 1389;
const DEFAULT_LDAP_TLS_PORT: u16 = 1636;

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    pub ldap: LdapAuthenticationProvider,
}

impl DruidLdapSettings {
    pub fn new_from(
        resolved_authentication_config: ResolvedAuthenticationClasses,
    ) -> Option<DruidLdapSettings> {
        let authentication_class = resolved_authentication_config.get_ldap_authentication_class();

        if let Some(authentication_class) = authentication_class {
            if let AuthenticationClassProvider::Ldap(ref provider) =
                authentication_class.spec.provider
            {
                return Some(DruidLdapSettings {
                    ldap: provider.clone(),
                });
            }
        }
        None
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
            Some("druid_system_pass".to_string()), // TODO: replace with sed placeholder
        );
        config.insert(
            format!("{PREFIX}.authorizerName"),
            Some("DruidSystemAuthorizer".to_string()),
        );
        config.insert(format!("{PREFIX}.skipOnFailure"), Some("true".to_string()));
    }

    fn add_ldap_authenticator_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        const PREFIX: &str = "druid.auth.authenticator.Ldap";

        config.insert(format!("{PREFIX}.type"), Some("basic".to_string()));
        config.insert(
            format!("{PREFIX}.enableCacheNotifications"),
            Some("true".to_string()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.type"),
            Some("ldap".to_string()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.url"),
            Some(self.credentials_validator_url()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.bindUser"),
            Some("xxx_ldap_bind_user_xxx".to_string()), // NOTE: this placeholder will be replaced from a mounted secret on container startup
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.bindPassword"),
            Some("xxx_ldap_bind_password_xxx".to_string()), // NOTE: this placeholder will be replaced from a mounted secret on container startup
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.baseDn"),
            Some(self.ldap.search_base.to_string()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.userAttribute"),
            Some(self.ldap.ldap_field_names.uid.to_string()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.userSearch"),
            Some(self.ldap.search_filter.to_string()),
        );
        config.insert(
            format!("{PREFIX}.authorizerName"),
            Some("LdapAuthorizer".to_string()),
        );
    }

    fn add_escalator_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            "druid.escalator.type".to_string(),
            Some("basic".to_string()),
        );
        config.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some("druid_system".to_string()), // TODO: replace with sed-placeholder xxx_druid_system_internal_user_xxx
        );
        config.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some("druid_system_pass".to_string()), // TODO: replace with sed-placeholder
        );
        config.insert(
            "druid.escalator.authorizerName".to_string(),
            Some("DruidSystemAuthorizer".to_string()),
        );
    }

    fn add_authorizer_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            "druid.auth.authorizers".to_string(),
            Some(r#"["LdapAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
        );
        config.insert(
            "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
        config.insert(
            "druid.auth.authorizer.LdapAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
    }

    pub fn generate_runtime_properties_config(&self) -> BTreeMap<String, Option<String>> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        config.insert(
            "druid.auth.authenticatorChain".to_string(),
            Some(r#"["DruidSystemAuthenticator", "Ldap"]"#.to_string()),
        );

        self.add_druid_system_authenticator_config(&mut config);
        self.add_ldap_authenticator_config(&mut config);
        self.add_escalator_config(&mut config);
        self.add_authorizer_config(&mut config);

        config
    }

    fn is_ssl_enabled(&self) -> bool {
        self.ldap.tls.is_some()
    }

    fn get_ldap_protocol_and_port(&self) -> (String, u16) {
        let protocol = if self.is_ssl_enabled() {
            "ldaps".to_string()
        } else {
            "ldap".to_string()
        };

        let port = if let Some(port) = self.ldap.port {
            port
        } else if self.is_ssl_enabled() {
            DEFAULT_LDAP_TLS_PORT
        } else {
            DEFAULT_LDAP_PORT
        };

        (protocol, port)
    }

    fn credentials_validator_url(&self) -> String {
        let (protocol, port) = self.get_ldap_protocol_and_port();
        format!("{}://{}:{}", protocol, self.ldap.hostname, port,)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use stackable_operator::commons::ldap::LdapFieldNames;

    #[test]
    fn test_ldap_settings_are_added() {
        let ldap_settings = DruidLdapSettings {
            ldap: LdapAuthenticationProvider {
                hostname: "openldap".to_string(),
                port: None,
                search_base: "ou=users,dc=example,dc=org".to_string(),
                search_filter: "(uid=%s)".to_string(),
                ldap_field_names: LdapFieldNames::default(),
                bind_credentials: None,
                tls: None,
            },
        };

        let got = ldap_settings.generate_runtime_properties_config();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
