use crate::DruidCluster;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::{
        authentication::{AuthenticationClass, AuthenticationClassProvider},
        tls::TlsAuthenticationProvider,
    },
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("The Trino Operator doesn't support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class} yet"))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthentication {
    /// TLS based client authentication (mutual TLS)
    pub tls: Option<DruidTlsAuthentication>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTlsAuthentication {
    pub authentication_class: String,
}

impl DruidAuthentication {
    pub async fn resolve(
        client: &Client,
        druid: &DruidCluster,
    ) -> Result<Vec<DruidAuthenticationConfig>, Error> {
        let mut druid_authentication_config: Vec<DruidAuthenticationConfig> = vec![];

        if let Some(DruidAuthentication {
            tls: Some(druid_tls),
        }) = &druid.spec.cluster_config.authentication
        {
            let authentication_class =
                AuthenticationClass::resolve(client, &druid_tls.authentication_class)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            &druid_tls.authentication_class,
                        ),
                    })?;

            match authentication_class.spec.provider {
                AuthenticationClassProvider::Tls(tls_provider) => {
                    druid_authentication_config.push(DruidAuthenticationConfig::Tls(tls_provider));
                }
                _ => {
                    return Err(Error::AuthenticationClassProviderNotSupported {
                        authentication_class_provider: authentication_class
                            .spec
                            .provider
                            .to_string(),
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            &druid_tls.authentication_class,
                        ),
                    })
                }
            }
        }

        Ok(druid_authentication_config)
    }
}

#[derive(Clone, Debug)]
pub enum DruidAuthenticationConfig {
    Tls(TlsAuthenticationProvider),
}

impl DruidAuthenticationConfig {
    pub fn is_tls_auth(&self) -> bool {
        matches!(self, DruidAuthenticationConfig::Tls(_))
    }
}
