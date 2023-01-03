use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 1] = ["TLS"];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to retrieve AuthenticationClass [{authentication_class}]"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    // TODO: Adapt message if multiple authentication classes are supported
    #[snafu(display("only one authentication class is currently supported. Possible Authentication class providers are {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}"))]
    MultipleAuthenticationClassesProvided,
    #[snafu(display(
        "failed to use authentication provider [{provider}] for authentication class [{authentication_class}] - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        authentication_class: ObjectRef<AuthenticationClass>,
        provider: String,
    },
}

#[derive(Clone, Deserialize, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthentication {
    /// The AuthenticationClass <https://docs.stackable.tech/home/nightly/concepts/authenticationclass.html> to use.
    ///
    /// ## TLS provider
    ///
    /// Only affects client connections. This setting controls:
    /// - If clients need to authenticate themselves against Druid via TLS
    /// - Which ca.crt to use when validating the provided client certs
    ///
    /// Please note that the SecretClass used to authenticate users needs to be the same
    /// as the SecretClass used for internal communication.
    pub authentication_class: String,
}

#[derive(Clone, Debug)]
/// Helper struct that contains resolved AuthenticationClasses to reduce network API calls.
pub struct ResolvedAuthenticationClasses {
    resolved_authentication_classes: Vec<AuthenticationClass>,
}

impl ResolvedAuthenticationClasses {
    pub fn new(resolved_authentication_classes: Vec<AuthenticationClass>) -> Self {
        Self {
            resolved_authentication_classes,
        }
    }

    /// Resolve provided AuthenticationClasses via API calls and validate the contents.
    /// Currently errors out if:
    /// - AuthenticationClass could not be resolved
    /// - Validation failed
    pub async fn from_references(
        client: &Client,
        auth_classes: &Vec<DruidAuthentication>,
    ) -> Result<ResolvedAuthenticationClasses, Error> {
        let mut resolved_authentication_classes: Vec<AuthenticationClass> = vec![];

        for auth_class in auth_classes {
            resolved_authentication_classes.push(
                AuthenticationClass::resolve(client, &auth_class.authentication_class)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            &auth_class.authentication_class,
                        ),
                    })?,
            );
        }

        ResolvedAuthenticationClasses::new(resolved_authentication_classes).validate()
    }

    /// Return the (first) TLS `AuthenticationClass` if available
    pub fn get_tls_authentication_class(&self) -> Option<&AuthenticationClass> {
        self.resolved_authentication_classes
            .iter()
            .find(|auth| matches!(auth.spec.provider, AuthenticationClassProvider::Tls(_)))
    }

    /// Validates the resolved AuthenticationClasses.
    /// Currently errors out if:
    /// - More than one AuthenticationClass was provided
    /// - AuthenticationClass provider was not supported
    pub fn validate(&self) -> Result<Self, Error> {
        // TODO: Check usual stuff
        // TODO: Check that no tls AuthClass is used when Druid server_and_internal tls is not enabled.
        // TODO: Check that the tls AuthClass uses the same SecretClass as the Druid server itself.
        todo!()
    }
}

// impl DruidAuthentication {
//     pub async fn resolve(
//         client: &Client,
//         druid: &DruidCluster,
//     ) -> Result<Vec<DruidAuthenticationConfig>, Error> {
//         let mut druid_authentication_config: Vec<DruidAuthenticationConfig> = vec![];

//         if let Some(DruidAuthentication {
//             tls: Some(druid_tls),
//         }) = &druid.spec.cluster_config.authentication
//         {
//             let authentication_class =
//                 AuthenticationClass::resolve(client, &druid_tls.authentication_class)
//                     .await
//                     .context(AuthenticationClassRetrievalSnafu {
//                         authentication_class: ObjectRef::<AuthenticationClass>::new(
//                             &druid_tls.authentication_class,
//                         ),
//                     })?;

//             match authentication_class.spec.provider {
//                 AuthenticationClassProvider::Tls(tls_provider) => {
//                     druid_authentication_config.push(DruidAuthenticationConfig::Tls(tls_provider));
//                 }
//                 _ => {
//                     return Err(Error::AuthenticationClassProviderNotSupported {
//                         authentication_class_provider: authentication_class
//                             .spec
//                             .provider
//                             .to_string(),
//                         authentication_class: ObjectRef::<AuthenticationClass>::new(
//                             &druid_tls.authentication_class,
//                         ),
//                     })
//                 }
//             }
//         }

//         Ok(druid_authentication_config)
//     }
// }
