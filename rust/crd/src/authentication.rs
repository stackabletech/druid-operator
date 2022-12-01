use crate::DruidCluster;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass [{authentication_class}]"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display(
        "Invalid {auth_method} authentication class provider [{authentication_class}]"
    ))]
    AuthenticationClassProviderNotSupported {
        auth_method: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthentication {
    /// TLS based client authentication (mutual TLS)
    pub tls: Option<DruidAuthenticationClass>,
    pub ldap: Option<DruidAuthenticationClass>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthenticationClass {
    pub authentication_class: String,
}

impl DruidAuthentication {
    pub async fn resolve(
        client: &Client,
        druid: &DruidCluster,
    ) -> Result<Vec<AuthenticationClassProvider>, Error> {
        let mut result = vec![];

        if let Some(DruidAuthentication {
            tls: Some(druid_tls),
            ..
        }) = &druid.spec.cluster_config.authentication
        {
            result.push(
                AuthenticationClass::resolve(client, &druid_tls.authentication_class)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            &druid_tls.authentication_class,
                        ),
                    })
                    .and_then(|auth_class| match auth_class.spec.provider {
                        AuthenticationClassProvider::Tls(_) => {
                            tracing::info!(
                                "Found TLS authentication provider [{}]",
                                druid_tls.authentication_class
                            );
                            Ok(auth_class.spec.provider)
                        }
                        _ => Err(Error::AuthenticationClassProviderNotSupported {
                            auth_method: "tls".to_string(),
                            authentication_class: ObjectRef::<AuthenticationClass>::new(
                                &druid_tls.authentication_class,
                            ),
                        }),
                    })?,
            );
        }

        if let Some(DruidAuthentication {
            ldap: Some(druid_ldap),
            ..
        }) = &druid.spec.cluster_config.authentication
        {
            result.push(
                AuthenticationClass::resolve(client, &druid_ldap.authentication_class)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            &druid_ldap.authentication_class,
                        ),
                    })
                    .and_then(|auth_class| match auth_class.spec.provider {
                        AuthenticationClassProvider::Ldap(_) => {
                            tracing::info!(
                                "Found LDAP authentication provider [{}]",
                                druid_ldap.authentication_class
                            );
                            Ok(auth_class.spec.provider)
                        }
                        _ => Err(Error::AuthenticationClassProviderNotSupported {
                            auth_method: "ldap".to_string(),
                            authentication_class: ObjectRef::<AuthenticationClass>::new(
                                &druid_ldap.authentication_class,
                            ),
                        }),
                    })?,
            );
        }
        Ok(result)
    }
}
