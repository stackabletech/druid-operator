use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::oidc::AuthenticationProvider;
use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::kube::ResourceExt;

use stackable_druid_crd::{
    security::{add_cert_to_trust_store_cmd, STACKABLE_TLS_DIR, TLS_STORE_PASSWORD},
};
use stackable_druid_crd::authentication::ResolvedAuthenticationClasses;
use crate::authentication::{add_druid_system_authenticator_config, add_escalator_config};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
}

#[derive(Clone, Debug)]
pub struct DruidOidcSettings {
    pub oidc: AuthenticationProvider,
    pub authentication_class_name: String,
}

impl DruidOidcSettings {
    pub fn new_from(
        resolved_authentication_config: &ResolvedAuthenticationClasses,
    ) -> Option<DruidOidcSettings> {
        if let Some(resolved_authentication_class) =
            resolved_authentication_config.get_oidc_authentication_class()
        {
            if let AuthenticationClassProvider::Oidc(ref provider) = resolved_authentication_class
                .authentication_class
                .spec
                .provider
            {
                return Some(DruidOidcSettings {
                    oidc: provider.clone(),
                    authentication_class_name: resolved_authentication_class
                        .authentication_class
                        .name_any(),
                    client_credentials_secret_ref: resolved_authentication_class.oidc
                });
            }
        }
        None
    }

    fn add_oidc_authenticator_config(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
    ) -> Result<(), Error> {
        if let Some(endpoint_url)  = self.oidc.endpoint_url() {

        const PREFIX: &str = "druid.auth.pac4j";

        config.insert(
            "druid.auth.authenticator.Oidc.type".to_string(),
            Some("pac4j".to_string()));
        config.insert(
            "druid.auth.authenticator.Oidc.authorizerName".to_string(),
            Some("LdapAuthorizer".to_string()),
        );
        config.insert(
            format!("{PREFIX}.cookiePassphrase"),
            Some(format!("${{env:{ENV_COOKIE_PASSPHRASE}}}").to_string()),
        );
        config.insert(
            format!("{PREFIX}.oidc.clientID"),
            Some(self.oidc..to_string()),
        );
        config.insert(
            format!("{PREFIX}.oidc.clientSecret"),
            Some(format!("${{env:{ENV_OIDC_CLIENT_SECRET}}}").to_string()),
        );



        config.insert(
            format!("{PREFIX}.oidc.discoveryURI"),
            Some(format!().to_string()),
        );
        config.insert(
            format!("{PREFIX}.oidc.oidcClaim"),
            Some(self.oidc.principal_claim.to_string()),
        );

        Ok(())
    }

    fn add_authorizer_config(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            "druid.auth.authorizers".to_string(),
            Some(r#"["OidcAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
        );
        config.insert(
            "druid.auth.authorizer.DruidSystemAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
        config.insert(
            "druid.auth.authorizer.OidcAuthorizer.type".to_string(),
            Some(r#"allowAll"#.to_string()),
        );
    }

    pub fn generate_runtime_properties_config(
        &self,
    ) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut config: BTreeMap<String, Option<String>> = BTreeMap::new();

        add_druid_system_authenticator_config(&mut config);
        add_escalator_config(&mut config);
        self.add_oidc_authenticator_config(&mut config)?;
        self.add_authorizer_config(&mut config);

        config.insert(
            "druid.auth.authenticatorChain".to_string(),
            Some(r#"["Oidc", "DruidSystemAuthenticator"]"#.to_string()),
        );

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
