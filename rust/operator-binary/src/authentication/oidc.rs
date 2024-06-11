use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::commons::authentication::oidc::AuthenticationProvider;

use crate::authentication::{Error, FailedToCreateOidcEndpointUrlSnafu};

fn add_oidc_authenticator_config(
    provider: &AuthenticationProvider,
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    let endpoint_url = &provider
        .endpoint_url()
        .context(FailedToCreateOidcEndpointUrlSnafu)?;

    const PREFIX: &str = "druid.auth.pac4j";

    config.insert(
        "druid.auth.authenticator.Oidc.type".to_string(),
        Some(r#"pac4j"#.to_string()),
    );
    config.insert(
        "druid.auth.authenticator.Oidc.authorizerName".to_string(),
        Some(r#"LdapAuthorizer"#.to_string()),
    );
    config.insert(
        format!("{PREFIX}.cookiePassphrase"),
        Some(r#"${env:{ENV_COOKIE_PASSPHRASE}}"#.to_string()),
    );
    config.insert(
        format!("{PREFIX}.oidc.clientID"),
        Some(r#"${env:{OIDC_CLIENT_ID}}"#.to_string()),
    );
    config.insert(
        format!("{PREFIX}.oidc.clientSecret"),
        Some(r#"${env:{OIDC_CLIENT_SECRET}}"#.to_string()),
    );

    config.insert(
        format!("{PREFIX}.oidc.discoveryURI"),
        Some(format!("{endpoint_url}").to_string()),
    );

    config.insert(
        format!("{PREFIX}.oidc.oidcClaim"),
        Some(provider.principal_claim.to_string()),
    );

    Ok(())
}

fn add_authorizer_config(
    config: &mut BTreeMap<String, Option<String>>,
) {
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
    config: &mut BTreeMap<String, Option<String>>,
) -> Result<(), Error> {
    add_oidc_authenticator_config(&provider, config)?;
    add_authorizer_config(config);

    config.insert(
        "druid.auth.authenticatorChain".to_string(),
        Some(r#"["Oidc", "DruidSystemAuthenticator"]"#.to_string()),
    );

    Ok(())
}

#[cfg(test)]
mod test {}
