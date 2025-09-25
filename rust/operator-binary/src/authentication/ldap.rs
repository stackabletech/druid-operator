use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::{
    builder::pod::{PodBuilder, container::ContainerBuilder},
    crd::authentication::ldap,
};

use super::{
    AddLdapVolumesSnafu, ConstructLdapEndpointUrlSnafu, Error, MissingLdapBindCredentialsSnafu,
};
use crate::crd::security::{STACKABLE_TLS_DIR, TLS_STORE_PASSWORD, add_cert_to_trust_store_cmd};

fn add_authenticator_config(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    config.insert(
        "druid.auth.authenticator.Ldap.type".to_string(),
        Some("basic".to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.enableCacheNotifications".to_string(),
        Some("true".to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.type".to_string(),
        Some("ldap".to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.url".to_string(),
        Some(
            provider
                .endpoint_url()
                .context(ConstructLdapEndpointUrlSnafu)?
                .into(),
        ),
    );

    if let Some((ldap_bind_user_path, ldap_bind_password_path)) =
        provider.bind_credentials_mount_paths()
    {
        config.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindUser".to_string(),
            Some(format!("${{file:UTF-8:{ldap_bind_user_path}}}").to_string()),
        );
        config.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindPassword".to_string(),
            Some(format!("${{file:UTF-8:{ldap_bind_password_path}}}").to_string()),
        );
    }

    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.baseDn".to_string(),
        Some(provider.search_base.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.userAttribute".to_string(),
        Some(provider.ldap_field_names.uid.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.userSearch".to_string(),
        Some(provider.search_filter.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.authorizerName".to_string(),
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
    provider: &ldap::v1alpha1::AuthenticationProvider,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    add_authenticator_config(provider, config)?;
    add_authorizer_config(config);

    Ok(())
}

pub fn prepare_container_commands(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    command: &mut Vec<String>,
) {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.push(add_cert_to_trust_store_cmd(
            &tls_ca_cert_mount_path,
            STACKABLE_TLS_DIR,
            TLS_STORE_PASSWORD,
        ))
    }
}

pub fn add_volumes_and_mounts(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    pb: &mut PodBuilder,
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
) -> Result<(), Error> {
    // TODO: Connecting to an LDAP server without bind credentials does not seem to be configurable in Druid at the moment
    // see https://github.com/stackabletech/druid-operator/issues/383 for future work.
    // Expect bind credentials to be provided for now, and throw return a useful error if there are none.
    if provider.bind_credentials_mount_paths().is_none() {
        return MissingLdapBindCredentialsSnafu.fail();
    }

    provider
        .add_volumes_and_mounts(pb, vec![cb_druid, cb_prepare])
        .context(AddLdapVolumesSnafu)
}
