use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::{
    crd::authentication::ldap,
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};

use super::{
    ConstructLdapEndpointUrlSnafu, Error, LdapVolumesSnafu, MissingLdapBindCredentialsSnafu,
};
use crate::crd::{
    STACKABLE_TRUST_STORE_PASSWORD, file_reference,
    security::{STACKABLE_TLS_DIR, add_cert_to_trust_store_cmd},
};

const LDAP_AUTHORIZER: &str = "LdapAuthorizer";

fn add_authenticator_config(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    config: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    config.insert(
        "druid.auth.authenticator.Ldap.type".to_string(),
        super::AUTHENTICATOR_TYPE_BASIC.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.enableCacheNotifications".to_string(),
        "true".to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.type".to_string(),
        "ldap".to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.url".to_string(),
        provider
            .endpoint_url()
            .context(ConstructLdapEndpointUrlSnafu)?
            .into(),
    );

    if let Some((ldap_bind_user_path, ldap_bind_password_path)) =
        provider.bind_credentials_mount_paths()
    {
        config.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindUser".to_string(),
            file_reference(ldap_bind_user_path),
        );
        config.insert(
            "druid.auth.authenticator.Ldap.credentialsValidator.bindPassword".to_string(),
            file_reference(ldap_bind_password_path),
        );
    }

    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.baseDn".to_string(),
        provider.search_base.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.userAttribute".to_string(),
        provider.ldap_field_names.uid.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.credentialsValidator.userSearch".to_string(),
        provider.search_filter.to_string(),
    );
    config.insert(
        "druid.auth.authenticator.Ldap.authorizerName".to_string(),
        LDAP_AUTHORIZER.to_string(),
    );
    super::set_authenticator_chain(config, &["Ldap"]);

    Ok(())
}

pub(super) fn generate_runtime_properties_config(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    config: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    add_authenticator_config(provider, config)?;
    super::add_authorizer_config(config, LDAP_AUTHORIZER);

    Ok(())
}

pub(super) fn prepare_container_commands(
    provider: &ldap::v1alpha1::AuthenticationProvider,
    command: &mut Vec<String>,
) {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.extend(add_cert_to_trust_store_cmd(
            &tls_ca_cert_mount_path,
            STACKABLE_TLS_DIR,
            STACKABLE_TRUST_STORE_PASSWORD,
        ))
    }
}

/// The volumes of the LDAP bind credentials and the provider's TLS CA certificate, and their
/// mounts.
pub(super) fn volumes_and_mounts(
    provider: &ldap::v1alpha1::AuthenticationProvider,
) -> Result<(Vec<Volume>, Vec<VolumeMount>), Error> {
    // TODO: Connecting to an LDAP server without bind credentials does not seem to be configurable in Druid at the moment
    // see https://github.com/stackabletech/druid-operator/issues/383 for future work.
    // Expect bind credentials to be provided for now, and throw return a useful error if there are none.
    if provider.bind_credentials_mount_paths().is_none() {
        return MissingLdapBindCredentialsSnafu.fail();
    }

    provider.volumes_and_mounts().context(LdapVolumesSnafu)
}
