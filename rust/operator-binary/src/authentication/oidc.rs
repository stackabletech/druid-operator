use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::oidc::AuthenticationProvider;
use stackable_operator::commons::authentication::oidc::ClientAuthenticationOptions;

use crate::authentication::{add_druid_system_authenticator_config, add_escalator_config};
use stackable_druid_crd::authentication::ResolvedAuthenticationClass;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateOidcEndpointUrl {
        source: stackable_operator::commons::authentication::oidc::Error,
    },
}

#[derive(Clone, Debug)]
pub struct DruidOidcSettings {
    provider: AuthenticationProvider,
    oidc: ClientAuthenticationOptions,
}

impl DruidOidcSettings {
    pub fn new_from(
        resolved_auth_class: &ResolvedAuthenticationClass,
    ) -> Option<DruidOidcSettings> {
        if let ResolvedAuthenticationClass::Oidc {
            auth_class_name,
            provider,
            oidc,
        } = resolved_auth_class
        {
            return Some(DruidOidcSettings {
                provider: provider.clone(),
                oidc: oidc.clone(),
            });
        }
        None
    }

    fn add_oidc_authenticator_config(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
    ) -> Result<(), Error> {
        let endpoint_url = self
            .provider
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
            Some(self.provider.principal_claim),
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
}

#[cfg(test)]
mod test {}
