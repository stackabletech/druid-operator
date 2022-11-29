use std::collections::BTreeMap;

use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::commons::ldap::LdapAuthenticationProvider;

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    provider: LdapAuthenticationProvider,
}

impl DruidLdapSettings {
    pub fn new_from(
        resolved_authentication_config: &Vec<AuthenticationClassProvider>,
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

    pub fn add_ldap_config_properties(&self) -> BTreeMap<String, Option<String>> {
        BTreeMap::new()
    }

fn not_used_add_ldap_config_properties(transformed_config: &mut BTreeMap<String, Option<String>>) {
    transformed_config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["ldap"]"#.to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.type".to_string(),
        Some("basic".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.enableCacheNotifications".to_string(),
        Some("true".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.type".to_string(),
        Some("ldap".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.url".to_string(),
        Some("ldap://openldap:1389".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.bindUser".to_string(),
        Some("uid=admin,ou=Users,dc=example,dc=org".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.bindPassword".to_string(),
        Some("admin".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.initialAdminPassword".to_string(),
        Some("admin".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.initialInternalClientPassword".to_string(),
        Some("druidsystem".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.baseDn".to_string(),
        Some("ou=Users,dc=example,dc=org".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.userSearch".to_string(),
        Some("(&(uid=%s)(objectClass=inetOrgPerson))".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.credentialsValidator.userAttribute".to_string(),
        Some("uid".to_string()),
    );
    transformed_config.insert(
        "druid.auth.authenticator.ldap.authorizeQueryContextParams".to_string(),
        Some("true".to_string()),
    );
    //# Escalator
    transformed_config.insert(
        "druid.escalator.type".to_string(),
        Some("basic".to_string()),
    );
    transformed_config.insert(
        "druid.escalator.internalClientUsername".to_string(),
        Some("druid_system".to_string()),
    );
    transformed_config.insert(
        "druid.escalator.internalClientPassword".to_string(),
        Some("druidsystem".to_string()),
    );
}
}

#[cfg(test)]
mod test {
    use super::*;
    use stackable_operator::commons::ldap::LdapFieldNames;

    #[test]
    fn test_no_ldap_settings_added() {
        let ldap_settings = DruidLdapSettings {
            provider: LdapAuthenticationProvider {
                hostname: "".to_string(),
                port: None,
                search_base: "".to_string(),
                search_filter: "".to_string(),
                ldap_field_names: LdapFieldNames::default(),
                bind_credentials: None,
                tls: None,
            }
        };

        let expected: BTreeMap<String, Option<String>> = BTreeMap::new();

        let got = ldap_settings.add_ldap_config_properties();

        assert_eq!(expected, got);
    }

}