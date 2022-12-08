use std::collections::BTreeMap;
use std::string::FromUtf8Error;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::commons::ldap::LdapAuthenticationProvider;
use stackable_operator::k8s_openapi::ByteString;
use stackable_operator::kube::runtime::reflector::ObjectRef;
use stackable_operator::{client::Client, k8s_openapi::api::core::v1::Secret};
use strum::{EnumDiscriminants, IntoStaticStr};

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
    #[snafu(display("Unable to parse key {} from {} as UTF8", key, secret))]
    NonUtf8Secret {
        source: FromUtf8Error,
        key: String,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display("Failed to find referenced {}", secret))]
    MissingSecret {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display(
        "A required value was not found when parsing the authentication config: [{}]",
        value
    ))]
    MissingRequiredValue { value: String },
}

const DEFAULT_LDAP_PORT: u16 = 1389;
const DEFAULT_LDAP_TLS_PORT: u16 = 1636;

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    provider: LdapAuthenticationProvider,
}

fn get_field_from_secret_data(
    data: &BTreeMap<String, ByteString>,
    var_name: String,
    secret_name: &str,
    secret_namespace: &str,
) -> Result<String, Error> {
    let password = data.get(&var_name).context(MissingSecretFieldSnafu)?;

    String::from_utf8(password.0.clone()).with_context(|_| NonUtf8SecretSnafu {
        key: var_name.clone(),
        secret: ObjectRef::new(secret_name).within(secret_namespace),
    })
}

impl DruidLdapSettings {
    pub async fn new_from(
        client: &Client,
        namespace: &str,
        resolved_authentication_config: &[AuthenticationClassProvider],
    ) -> Result<Option<DruidLdapSettings>, Error> {
        let maybe_provider = resolved_authentication_config
            .iter()
            .find_map(|acc| match acc {
                AuthenticationClassProvider::Ldap(provider) => Some(provider),
                _ => None,
            });

        if let Some(provider) = maybe_provider {
            // create DruidLdapSettings with everything in it
            Ok(Some(DruidLdapSettings {
                provider: provider.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn generate_runtime_properties_config_lines(&self) -> BTreeMap<String, Option<String>> {
        let mut lines: BTreeMap<String, Option<String>> = BTreeMap::new();

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
            Some(self.credentials_validator_url()),
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

        lines.insert(
            "druid.escalator.type".to_string(),
            Some("basic".to_string()),
        );

        // NOTE: these placeholders will be replaced from a mounted secret on container startup
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindUser".to_string(),
            Some("xxx_ldap_bind_user_xxx".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindPassword".to_string(),
            Some("xxx_ldap_bind_password_xxx".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialAdminPassword".to_string(),
            Some("xxx_ldap_bind_password_xxx".to_string()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialInternalClientPassword".to_string(),
            Some("xxx_ldap_internal_password_xxx".to_string()),
        );
        lines.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some("xxx_ldap_internal_user_xxx".to_string()),
        );
        lines.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some("xxx_ldap_internal_password_xxx".to_string()),
        );

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
                search_base: "ou=Users,dc=example,dc=org".to_string(),
                search_filter: "(&(uid=%s)(objectClass=inetOrgPerson))".to_string(),
                ldap_field_names: LdapFieldNames::default(),
                bind_credentials: None,
                tls: None,
            },
        };

        let expected: BTreeMap<String, Option<String>> = vec![
            (
                "druid.auth.authenticator.ldap.authorizeQueryContextParams".to_string(),
                Some("true".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.baseDn".to_string(),
                Some("ou=Users,dc=example,dc=org".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.bindPassword".to_string(),
                Some("xxx_ldap_bind_password_xxx".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.bindUser".to_string(),
                Some("xxx_ldap_bind_user_xxx".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.type".to_string(),
                Some("ldap".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.url".to_string(),
                Some("ldap://openldap:1389".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.userAttribute".to_string(),
                Some("uid".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.credentialsValidator.userSearch".to_string(),
                Some("(&(uid=%s)(objectClass=inetOrgPerson))".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.enableCacheNotifications".to_string(),
                Some("true".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.initialAdminPassword".to_string(),
                Some("xxx_ldap_bind_password_xxx".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.initialInternalClientPassword".to_string(),
                Some("xxx_ldap_internal_password_xxx".to_string()),
            ),
            (
                "druid.auth.authenticator.ldap.type".to_string(),
                Some("basic".to_string()),
            ),
            (
                "druid.auth.authenticatorChain".to_string(),
                Some("[\"ldap\"]".to_string()),
            ),
            (
                "druid.escalator.internalClientPassword".to_string(),
                Some("xxx_ldap_internal_password_xxx".to_string()),
            ),
            (
                "druid.escalator.internalClientUsername".to_string(),
                Some("xxx_ldap_internal_user_xxx".to_string()),
            ),
            (
                "druid.escalator.type".to_string(),
                Some("basic".to_string()),
            ),
        ]
        .into_iter()
        .collect();

        let got = ldap_settings.generate_runtime_properties_config_lines();

        assert_eq!(expected, got);
    }
}
