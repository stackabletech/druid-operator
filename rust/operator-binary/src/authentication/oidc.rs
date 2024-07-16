use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_druid_crd::{
    security::add_cert_to_jvm_trust_store_cmd, DruidRole, COOKIE_PASSPHRASE_ENV,
};
use stackable_operator::{
    builder::pod::{container::ContainerBuilder, PodBuilder},
    commons::authentication::oidc::{
        AuthenticationProvider, ClientAuthenticationOptions, DEFAULT_OIDC_WELLKNOWN_PATH,
    },
    k8s_openapi::api::core::v1::EnvVar,
};

use crate::{
    authentication::{AddOidcVolumesSnafu, CreateOidcEndpointUrlSnafu, Error},
    internal_secret::env_var_from_secret,
};

fn add_authenticator_config(
    provider: &AuthenticationProvider,
    oidc: &ClientAuthenticationOptions,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    let endpoint_url = &provider
        .endpoint_url()
        .context(CreateOidcEndpointUrlSnafu)?;

    let (oidc_client_id_env, oidc_client_secret_env) =
        AuthenticationProvider::client_credentials_env_names(&oidc.client_credentials_secret_ref);

    config.insert(
        "druid.auth.authenticator.Oidc.type".to_string(),
        Some(r#"pac4j"#.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Oidc.authorizerName".to_string(),
        Some(r#"OidcAuthorizer"#.to_string()),
    );
    config.insert(
        format!("druid.auth.pac4j.cookiePassphrase"),
        Some(format!("${{env:{COOKIE_PASSPHRASE_ENV}}}").to_string()),
    );
    config.insert(
        format!("druid.auth.pac4j.oidc.clientID"),
        Some(format!("${{env:{oidc_client_id_env}}}").to_string()),
    );
    config.insert(
        format!("druid.auth.pac4j.oidc.clientSecret"),
        Some(format!("${{env:{oidc_client_secret_env}}}").to_string()),
    );

    config.insert(
        format!("druid.auth.pac4j.oidc.discoveryURI"),
        Some(format!("{endpoint_url}/{DEFAULT_OIDC_WELLKNOWN_PATH}").to_string()),
    );

    config.insert(
        format!("druid.auth.pac4j.oidc.oidcClaim"),
        Some(provider.principal_claim.to_string()),
    );
    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["DruidSystemAuthenticator", "Oidc"]"#.to_string()),
    );

    Ok(())
}

fn add_authorizer_config(config: &mut BTreeMap<String, Option<String>>) {
    config.insert(
        "druid.auth.authorizers".to_string(),
        Some(r#"["OidcAuthorizer", "DruidSystemAuthorizer"]"#.to_string()),
    );
    config.insert(
        "druid.auth.authorizer.OidcAuthorizer.type".to_string(),
        Some(r#"allowAll"#.to_string()),
    );
}

pub fn generate_runtime_properties_config(
    provider: &AuthenticationProvider,
    oidc: &ClientAuthenticationOptions,
    role: &DruidRole,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    match role {
        DruidRole::MiddleManager => {
            config.insert(
                "druid.auth.authenticatorChain".to_string(),
                Some(r#"["DruidSystemAuthenticator"]"#.to_string()),
            );
        }
        _ => {
            add_authenticator_config(provider, oidc, config)?;
            add_authorizer_config(config)
        }
    }
    Ok(())
}

pub fn main_container_commands(
    auth_class_name: &String,
    provider: &AuthenticationProvider,
    command: &mut Vec<String>,
) {
    if let Some(tls_ca_cert_mount_path) = provider.tls.tls_ca_cert_mount_path() {
        command.push(add_cert_to_jvm_trust_store_cmd(
            &tls_ca_cert_mount_path,
            &format!("oidc-{}", auth_class_name),
        ))
    }
}

pub fn get_env_var_mounts(
    role: &DruidRole,
    oidc: &ClientAuthenticationOptions,
    internal_secret_name: &str,
) -> Vec<EnvVar> {
    let mut envs = vec![];
    match role {
        DruidRole::MiddleManager => (),
        _ => {
            envs.extend(AuthenticationProvider::client_credentials_env_var_mounts(
                oidc.client_credentials_secret_ref.to_owned(),
            ));
            envs.push(env_var_from_secret(
                internal_secret_name,
                None,
                COOKIE_PASSPHRASE_ENV,
            ))
        }
    }
    envs
}

pub fn add_volumes_and_mounts(
    provider: &AuthenticationProvider,
    pb: &mut PodBuilder,
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
) -> Result<(), Error> {
    provider
        .tls
        .add_volumes_and_mounts(pb, vec![cb_druid, cb_prepare])
        .context(AddOidcVolumesSnafu)
}

#[cfg(test)]
mod test {}
