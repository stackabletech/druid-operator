use std::collections::BTreeMap;

pub mod oidc;
pub mod ldap;

pub fn add_druid_system_authenticator_config(config: &mut BTreeMap<String, Option<String>>) {
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
        Some(format!("${{env:{ENV_INTERNAL_SECRET}}}").to_string()),
    );
    config.insert(
        format!("{PREFIX}.authorizerName"),
        Some("DruidSystemAuthorizer".to_string()),
    );
    config.insert(format!("{PREFIX}.skipOnFailure"), Some("true".to_string()));
}

pub fn add_escalator_config(config: &mut BTreeMap<String, Option<String>>) {
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
        Some(format!("${{env:{ENV_INTERNAL_SECRET}}}").to_string()),
    );
    config.insert(
        "druid.escalator.authorizerName".to_string(),
        Some("DruidSystemAuthorizer".to_string()),
    );
}