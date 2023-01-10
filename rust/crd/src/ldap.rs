use std::collections::BTreeMap;
use std::string::FromUtf8Error;

use snafu::Snafu;
use stackable_operator::commons::authentication::{
    AuthenticationClass, AuthenticationClassProvider,
};
use stackable_operator::commons::ldap::LdapAuthenticationProvider;
use stackable_operator::k8s_openapi::api::core::v1::Secret;
use stackable_operator::kube::runtime::reflector::ObjectRef;
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::authentication::ResolvedAuthenticationClasses;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("invalid ldap settings"))]
    InvalidLdapSettings,
    #[snafu(display("missing ldap bind credentials"))]
    MissingBindCredentials,
    #[snafu(display("missing secret field"))]
    MissingSecretField,
    #[snafu(display("unable to parse key {} from {} as UTF8", key, secret))]
    NonUtf8Secret {
        source: FromUtf8Error,
        key: String,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display("failed to find referenced {}", secret))]
    MissingSecret {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display(
        "a required value was not found when parsing the authentication config: [{}]",
        value
    ))]
    MissingRequiredValue { value: String },
}

const DEFAULT_LDAP_PORT: u16 = 1389;
const DEFAULT_LDAP_TLS_PORT: u16 = 1636;

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    pub provider: LdapAuthenticationProvider,
}

impl DruidLdapSettings {
    pub fn new_from(
        resolved_authentication_config: ResolvedAuthenticationClasses,
    ) -> Option<DruidLdapSettings> {
        let maybe_authentication_class =
            resolved_authentication_config.get_ldap_authentication_class();

        if let Some(authentication_class) = maybe_authentication_class {
            if let AuthenticationClassProvider::Ldap(ref provider) =
                authentication_class.spec.provider
            {
                return Some(DruidLdapSettings {
                    provider: provider.clone(),
                });
            }
        }
        None
    }

    fn add_druid_system_authenticator_lines(&self, lines: &mut BTreeMap<String, Option<String>>) {
        lines.insert(
            "druid.auth.authenticator.DruidSystemAuthenticator.type".to_string(),
            Some("basic".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.DruidSystemAuthenticator.credentialsValidator.type"
                .to_string(),
            Some("metadata".to_string()),
        );

        // this line is left out, as we don't want to create an admin user
        // # druid.auth.authenticator.DruidSystemAuthenticator.initialAdminPassword: XXX

        lines.insert(
            "druid.auth.authenticator.DruidSystemAuthenticator.initialInternalClientPassword"
                .to_string(),
            Some("druid_system_pass".to_string()), // TODO: replace with sed placeholder
        );
        lines.insert(
            "druid.auth.authenticator.DruidSystemAuthenticator.authorizerName".to_string(),
            Some("DruidSystemAuthorizer".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.DruidSystemAuthenticator.skipOnFailure".to_string(),
            Some("true".to_string()), // TODO: is additional escaping necessary for "true"?
        );
    }

    fn add_ldap_authenticator_lines(&self, lines: &mut BTreeMap<String, Option<String>>) {
        lines.insert(
            "druid.auth.authenticator.Ldap.type".to_string(),
            Some("basic".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.enableCacheNotifications".to_string(),
            Some("true".to_string()), // TODO: is additional escaping necessary for "true"?
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.type".to_string(),
            Some("ldap".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.url".to_string(),
            Some(self.credentials_validator_url()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindUser".to_string(),
            Some("xxx_ldap_bind_user_xxx".to_string()), // NOTE: this placeholder will be replaced from a mounted secret on container startup
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindPassword".to_string(),
            Some("xxx_ldap_bind_password_xxx".to_string()), // NOTE: this placeholder will be replaced from a mounted secret on container startup
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.baseDn".to_string(),
            Some(self.provider.search_base.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.userAttribute".to_string(),
            Some(self.provider.ldap_field_names.uid.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.userSearch".to_string(),
            Some(self.provider.search_filter.to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.Ldap.authorizerName".to_string(),
            Some("LdapAuthorizer".to_string()),
        );
    }

    fn add_escalator_lines(&self, lines: &mut BTreeMap<String, Option<String>>) {
        lines.insert(
            "druid.escalator.type".to_string(),
            Some("basic".to_string()),
        );
        lines.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some("druid_system".to_string()), // TODO: replace with sed-placeholder xxx_druid_system_internal_user_xxx
        );
        lines.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some("druid_system_pass".to_string()), // TODO: replace with sed-placeholder
        );
        lines.insert(
            "druid.escalator.authorizerName".to_string(),
            Some("DruidSystemAuthorizer".to_string()),
        );
    }

    fn add_authorizer_lines(&self, lines: &mut BTreeMap<String, Option<String>>) {
        lines.insert(
            "druid.auth.authorizers".to_string(),
            Some(r#"["LdapAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
        );
        lines.insert(
            "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
        lines.insert(
            "druid.auth.authorizer.LdapAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
    }

    pub fn generate_runtime_properties_config_lines(&self) -> BTreeMap<String, Option<String>> {
        let mut lines: BTreeMap<String, Option<String>> = BTreeMap::new();

        lines.insert(
            "druid.auth.authenticatorChain".to_string(),
            Some(r#"["DruidSystemAuthenticator", "Ldap"]"#.to_string()),
        );

        self.add_druid_system_authenticator_lines(&mut lines);
        self.add_ldap_authenticator_lines(&mut lines);
        self.add_escalator_lines(&mut lines);
        self.add_authorizer_lines(&mut lines);

        lines
    }

    fn is_ssl_enabled(&self) -> bool {
        self.provider.tls.is_some()
    }

    fn get_ldap_protocol_and_port(&self) -> (String, u16) {
        let protocol = if self.is_ssl_enabled() {
            "ldaps".to_string()
        } else {
            "ldap".to_string()
        };

        let port = if let Some(port) = self.provider.port {
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
        format!("{}://{}:{}", protocol, self.provider.hostname, port,)
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
                hostname: "openldap".to_string(),
                port: None,
                search_base: "ou=users,dc=example,dc=org".to_string(),
                search_filter: "(uid=%s)".to_string(),
                ldap_field_names: LdapFieldNames::default(),
                bind_credentials: None,
                tls: None,
            },
        };

        let got = ldap_settings.generate_runtime_properties_config_lines();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
