use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::commons::authentication::ldap::AuthenticationProvider;

use stackable_druid_crd::security::{
    add_cert_to_trust_store_cmd, STACKABLE_TLS_DIR, TLS_STORE_PASSWORD,
};

use crate::authentication::{Error, FailedToCreateLdapEndpointUrlSnafu};

fn add_authenticator_config(
    provider: AuthenticationProvider,
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
            provider
                .endpoint_url()
                .context(FailedToCreateLdapEndpointUrlSnafu)?
                .into(),
        ),
    );

    if let Some((ldap_bind_user_path, ldap_bind_password_path)) =
        provider.bind_credentials_mount_paths()
    {
        config.insert(
            format!("{PREFIX}.credentialsValidator.bindUser"),
            Some(format!("${{file:UTF-8:{ldap_bind_user_path}}}").to_string()),
        );
        config.insert(
            format!("{PREFIX}.credentialsValidator.bindPassword"),
            Some(format!("${{file:UTF-8:{ldap_bind_password_path}}}").to_string()),
        );
    }

    config.insert(
        format!("{PREFIX}.credentialsValidator.baseDn"),
        Some(provider.search_base.to_string()),
    );
    config.insert(
        format!("{PREFIX}.credentialsValidator.userAttribute"),
        Some(provider.ldap_field_names.uid.to_string()),
    );
    config.insert(
        format!("{PREFIX}.credentialsValidator.userSearch"),
        Some(provider.search_filter.to_string()),
    );
    config.insert(
        format!("{PREFIX}.authorizerName"),
        Some("LdapAuthorizer".to_string()),
    );
    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["DruidSystemAuthenticator", "Ldap"]"#.to_string()),
    );

    Ok(())
}

fn add_authorizer_config(config: &mut BTreeMap<String, Option<String>>) {
    config.insert(
        "druid.auth.authorizers".to_string(),
        Some(r#"["LdapAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
    );
    config.insert(
        "druid.auth.authorizer.LdapAuthorizer.type".to_string(),
        Some(r#"allowAll"#.to_string()),
    );
}

pub fn generate_runtime_properties_config(
    provider: AuthenticationProvider,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    add_authenticator_config(provider, config)?;
    add_authorizer_config(config);

    Ok(())
}

pub fn prepare_container_commands(
    auth_class_name: String,
    provider: AuthenticationProvider,
    command: &mut Vec<String>,
) -> () {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.push(add_cert_to_trust_store_cmd(
            &tls_ca_cert_mount_path,
            STACKABLE_TLS_DIR,
            &format!("ldap-{}", auth_class_name),
            TLS_STORE_PASSWORD,
        ))
    }
}
