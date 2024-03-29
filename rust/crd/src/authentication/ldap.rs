use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::ldap::AuthenticationProvider;
use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::kube::ResourceExt;

use crate::authentication::ResolvedAuthenticationClasses;
use crate::{
    security::{add_cert_to_trust_store_cmd, STACKABLE_TLS_DIR, TLS_STORE_PASSWORD},
    ENV_INTERNAL_SECRET, RUNTIME_PROPS, RW_CONFIG_DIRECTORY,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
}

#[derive(Clone, Debug)]
pub struct DruidLdapSettings {
    pub ldap: AuthenticationProvider,
    pub authentication_class_name: String,
}

pub const PLACEHOLDER_INTERNAL_CLIENT_PASSWORD: &str =
    "xxx_druid_system_internal_client_password_xxx";
pub const PLACEHOLDER_LDAP_BIND_PASSWORD: &str = "xxx_ldap_bind_password_xxx";
pub const PLACEHOLDER_LDAP_BIND_USER: &str = "xxx_ldap_bind_user_xxx";

impl DruidLdapSettings {
    pub fn new_from(
        resolved_authentication_config: &ResolvedAuthenticationClasses,
    ) -> Option<DruidLdapSettings> {
        if let Some(authentication_class) =
            resolved_authentication_config.get_ldap_authentication_class()
        {
            if let AuthenticationClassProvider::Ldap(ref provider) =
                authentication_class.spec.provider
            {
                return Some(DruidLdapSettings {
                    ldap: provider.clone(),
                    authentication_class_name: authentication_class.name_unchecked(),
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
            Some(PLACEHOLDER_INTERNAL_CLIENT_PASSWORD.to_string()),
        );
        config.insert(
            format!("{PREFIX}.authorizerName"),
            Some("DruidSystemAuthorizer".to_string()),
        );
        config.insert(format!("{PREFIX}.skipOnFailure"), Some("true".to_string()));
    }

    fn add_ldap_authenticator_config(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
    ) -> Result<(), Error> {
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
            Some(
                self.ldap
                    .endpoint_url()
                    .context(FailedToCreateLdapEndpointUrlSnafu)?
                    .into(),
            ),
        );

        if self.ldap.bind_credentials_mount_paths().is_some() {
            config.insert(
                format!("{PREFIX}.credentialsValidator.bindUser"),
                Some(PLACEHOLDER_LDAP_BIND_USER.to_string()), // NOTE: this placeholder will be replaced from a mounted secret operator volume on container startup
            );
            config.insert(
                format!("{PREFIX}.credentialsValidator.bindPassword"),
                Some(PLACEHOLDER_LDAP_BIND_PASSWORD.to_string()), // NOTE: this placeholder will be replaced from a mounted secret operator volume on container startup
            );
        }

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

        Ok(())
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
            Some(PLACEHOLDER_INTERNAL_CLIENT_PASSWORD.to_string()),
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

    pub fn generate_runtime_properties_config(
        &self,
    ) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        config.insert(
            "druid.auth.authenticatorChain".to_string(),
            Some(r#"["DruidSystemAuthenticator", "Ldap"]"#.to_string()),
        );

        self.add_druid_system_authenticator_config(&mut config);
        self.add_ldap_authenticator_config(&mut config)?;
        self.add_escalator_config(&mut config);
        self.add_authorizer_config(&mut config);

        Ok(config)
    }

    pub fn main_container_commands(&self) -> Vec<String> {
        let mut commands = Vec::new();

        let runtime_properties_file: String = format!("{RW_CONFIG_DIRECTORY}/{RUNTIME_PROPS}");
        let internal_client_password = format!("$(echo ${ENV_INTERNAL_SECRET})");

        commands
                .push(format!("echo \"Replacing LDAP placeholders with their proper values in {runtime_properties_file}\""));
        commands.push(format!(
            r#"sed "s|{PLACEHOLDER_INTERNAL_CLIENT_PASSWORD}|{internal_client_password}|g" -i {runtime_properties_file}"# // using another delimiter (|) here because of base64 string
        ));

        if let Some((ldap_bind_user_path, ldap_bind_password_path)) =
            self.ldap.bind_credentials_mount_paths()
        {
            let ldap_bind_user = format!("$(cat {ldap_bind_user_path})");
            let ldap_bind_password = format!("$(cat {ldap_bind_password_path})");

            commands.push(format!(
                    r#"sed "s/{PLACEHOLDER_LDAP_BIND_USER}/{ldap_bind_user}/g" -i {runtime_properties_file}"#
                ));
            commands.push(format!(
                    r#"sed "s/{PLACEHOLDER_LDAP_BIND_PASSWORD}/{ldap_bind_password}/g" -i {runtime_properties_file}"#
                ));
        }

        commands
    }

    pub fn prepare_container_commands(&self) -> Vec<String> {
        let mut command = vec![];
        if let Some(tls_ca_cert_mount_path) = self.ldap.tls.tls_ca_cert_mount_path() {
            command.push(add_cert_to_trust_store_cmd(
                &tls_ca_cert_mount_path,
                STACKABLE_TLS_DIR,
                &format!("ldap-{}", self.authentication_class_name),
                TLS_STORE_PASSWORD,
            ))
        }
        command
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ldap_settings_are_added() {
        let ldap_settings = DruidLdapSettings {
            ldap: serde_yaml::from_str::<AuthenticationProvider>(
                "
                hostname: openldap
                searchBase: ou=users,dc=example,dc=org
                searchFilter: (uid=%s)
                ",
            )
            .unwrap(),
            authentication_class_name: "ldap".to_string(),
        };

        let got = ldap_settings.generate_runtime_properties_config().unwrap();

        assert!(got.contains_key("druid.auth.authenticator.Ldap.type"));
    }
}
