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

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    provider: LdapAuthenticationProvider,
    ldap_admin_user: String,
    ldap_admin_password: String,
    ldap_internal_user: String,
    ldap_internal_password: String,
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
            let bind_credentials = provider
                .bind_credentials
                .as_ref()
                .context(MissingBindCredentialsSnafu)?;

            // get secrets
            let secret_class_name = bind_credentials.secret_class.clone();
            // NOTE: the secret class name is assumed to be the same as the secret name
            // if not, we will fail and burn
            let secret_name = secret_class_name;
            let secret_namespace = namespace;
            let secret_content = client
                .get::<Secret>(&secret_name, secret_namespace)
                .await
                .with_context(|_| MissingSecretSnafu {
                    secret: ObjectRef::new(&secret_name).within(secret_namespace),
                })?;

            let data = secret_content
                .data
                .with_context(|| MissingRequiredValueSnafu {
                    value: "LDAP secret contains no data".to_string(),
                })?;

            let ldap_admin_user = get_field_from_secret_data(
                &data,
                "LDAP_ADMIN_USER".to_string(),
                &secret_name,
                secret_namespace,
            )?;
            let ldap_admin_password = get_field_from_secret_data(
                &data,
                "LDAP_ADMIN_PASSWORD".to_string(),
                &secret_name,
                secret_namespace,
            )?;
            let ldap_internal_user = get_field_from_secret_data(
                &data,
                "LDAP_INTERNAL_USER".to_string(),
                &secret_name,
                secret_namespace,
            )?;
            let ldap_internal_password = get_field_from_secret_data(
                &data,
                "LDAP_INTERNAL_PASSWORD".to_string(),
                &secret_name,
                secret_namespace,
            )?;

            // create DruidLdapSettings with everything in it
            Ok(Some(DruidLdapSettings {
                provider: provider.clone(),
                ldap_admin_user,
                ldap_admin_password,
                ldap_internal_user,
                ldap_internal_password,
            }))
        } else {
            Ok(None)
        }
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

        /*

        NOTE: it seems like there are two options to set credentials without mentioning them in the config directly.

        Both didn't work for us. The first one is the recommended way, the second one is deprecated.
        */

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
          }"#.replace('\mentioning "").replace(' ', "")));
        */

        /*
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
        */

        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindUser".to_string(),
            Some(self.ldap_admin_user.clone()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.credentialsValidator.bindPassword".to_string(),
            Some(self.ldap_admin_password.clone()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialAdminPassword".to_string(),
            Some(self.ldap_admin_password.clone()),
        );
        lines.insert(
            "druid.auth.authenticator.ldap.initialInternalClientPassword".to_string(),
            Some(self.ldap_internal_password.clone()),
        );
        lines.insert(
            "druid.escalator.internalClientUsername".to_string(),
            Some(self.ldap_internal_user.clone()),
        );
        lines.insert(
            "druid.escalator.internalClientPassword".to_string(),
            Some(self.ldap_internal_password.clone()),
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
            ldap_admin_user: "".to_string(),
            ldap_admin_password: "".to_string(),
            ldap_internal_user: "".to_string(),
            ldap_internal_password: "".to_string(),
        };

        //let expected: BTreeMap<String, Option<String>> = BTreeMap::new();

        let got = ldap_settings.generate_runtime_properties_config_lines();

        assert_ne!(got.len(), 0);
    }
}
