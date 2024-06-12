use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_druid_crd::{DruidRole, ENV_COOKIE_PASSPHRASE};
use stackable_operator::{
    commons::authentication::oidc::{
        AuthenticationProvider, ClientAuthenticationOptions, DEFAULT_OIDC_WELLKNOWN_PATH,
    },
    k8s_openapi::api::core::v1::EnvVar,
};

use crate::{authentication::{Error, FailedToCreateOidcEndpointUrlSnafu}, internal_secret::env_var_from_secret};

fn add_authenticator_config(
    provider: &AuthenticationProvider,
    oidc: ClientAuthenticationOptions,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    let endpoint_url = &provider
        .endpoint_url()
        .context(FailedToCreateOidcEndpointUrlSnafu)?;

    const PREFIX: &str = "druid.auth.pac4j";

    let (oidc_client_id_env, oidc_client_secret_env) = AuthenticationProvider::client_credentials_env_names(&oidc.client_credentials_secret_ref);

    config.insert(
        "druid.auth.authenticator.Oidc.type".to_string(),
        Some(r#"pac4j"#.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Oidc.authorizerName".to_string(),
        Some(r#"OidcAuthorizer"#.to_string()),
    );
    config.insert(
        format!("{PREFIX}.cookiePassphrase"),
        Some(r#"${env:OIDC_COOKIE_PASSPHRASE}"#.to_string()),
    );
    config.insert(
        format!("{PREFIX}.oidc.clientID"),
        Some(format!("${{env:{oidc_client_id_env}}}").to_string()),
    );
    config.insert(
        format!("{PREFIX}.oidc.clientSecret"),
        Some(format!("${{env:{oidc_client_secret_env}}}").to_string()),
    );

    config.insert(
        format!("{PREFIX}.oidc.discoveryURI"),
        Some(format!("{endpoint_url}/{DEFAULT_OIDC_WELLKNOWN_PATH}").to_string()),
    );

    config.insert(
        format!("{PREFIX}.oidc.oidcClaim"),
        Some(provider.principal_claim.to_string()),
    );

    Ok(())
}

fn add_authorizer_config(config: &mut BTreeMap<String, Option<String>>) {
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
    provider: AuthenticationProvider,
    oidc: ClientAuthenticationOptions,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    add_authenticator_config(&provider, oidc, config)?;
    add_authorizer_config(config);

    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["Oidc", "DruidSystemAuthenticator"]"#.to_string()),
    );

    Ok(())
}

pub fn get_env_var_mounts(role: &DruidRole, oidc: ClientAuthenticationOptions, internal_secret_name: &str ) -> Vec<EnvVar> {
    let mut envs = vec![];
    match role {
        DruidRole::MiddleManager => (),
        _ => { envs.extend(AuthenticationProvider::client_credentials_env_var_mounts(
            oidc.client_credentials_secret_ref,
        ));
        envs.push(env_var_from_secret(
            internal_secret_name,
            None,
            ENV_COOKIE_PASSPHRASE,
        ))}
    }
    envs
}

#[cfg(test)]
mod test {}
