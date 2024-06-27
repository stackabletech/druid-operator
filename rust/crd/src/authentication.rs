use std::future::Future;

use snafu::{ensure, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{
        ldap,
        oidc::{self, IdentityProviderHint},
        tls, AuthenticationClass, AuthenticationClassProvider, ClientAuthenticationDetails,
    },
    kube::{runtime::reflector::ObjectRef, ResourceExt},
};
use tracing::info;

use crate::DruidClusterConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

// The assumed OIDC provider if no hint is given in the AuthClass
pub const DEFAULT_OIDC_PROVIDER: IdentityProviderHint = IdentityProviderHint::Keycloak;

const SUPPORTED_OIDC_PROVIDERS: &[IdentityProviderHint] = &[IdentityProviderHint::Keycloak];

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 3] = ["LDAP", "TLS", "OIDC"];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrievalFailed {
        source: stackable_operator::client::Error,
    },
    // TODO: Adapt message if multiple authentication classes are supported simultaneously
    #[snafu(display("only one authentication class is currently supported at a time."))]
    MultipleAuthenticationClassesNotSupported,
    #[snafu(display(
    "failed to use authentication provider [{authentication_class_provider}] for authentication class [{authentication_class}] - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("LDAP authentication without bind credentials is currently not supported. See https://github.com/stackabletech/druid-operator/issues/383 for details"))]
    LdapAuthenticationWithoutBindCredentialsNotSupported {},
    #[snafu(display("LDAP authentication requires server and internal tls to be enabled"))]
    LdapAuthenticationWithoutServerTlsNotSupported {},
    #[snafu(display(
    "client authentication using TLS (as requested by AuthenticationClass {auth_class_name}) can not be used when Druid server and internal TLS is disabled",
    ))]
    TlsAuthenticationClassWithoutDruidServerTls { auth_class_name: String },
    #[snafu(display(
    "client authentication using TLS (as requested by AuthenticationClass {auth_class_name}) can only use the same SecretClass as the Druid instance is using for server and internal communication (SecretClass {server_and_internal_secret_class} in this case)",
    ))]
    TlsAuthenticationClassSecretClassDiffersFromDruidServerTls {
        auth_class_name: String,
        server_and_internal_secret_class: String,
    },
    #[snafu(display("invalid OIDC configuration"))]
    OidcConfigurationInvalid {
        source: stackable_operator::commons::authentication::Error,
    },
    #[snafu(display("the OIDC provider {oidc_provider:?} is not yet supported (AuthenticationClass {auth_class_name:?})"))]
    OidcProviderNotSupported {
        auth_class_name: String,
        oidc_provider: String,
    },
}

#[derive(Clone, PartialEq, Debug)]
pub struct AuthenticationClassesResolved {
    pub auth_classes: Vec<AuthenticationClassResolved>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum AuthenticationClassResolved {
    /// An [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication) to use.
    Tls {
        provider: tls::AuthenticationProvider,
    },
    Ldap {
        auth_class_name: String,
        provider: ldap::AuthenticationProvider,
    },
    Oidc {
        auth_class_name: String,
        provider: oidc::AuthenticationProvider,
        oidc: oidc::ClientAuthenticationOptions<()>,
    },
}

impl AuthenticationClassesResolved {
    pub async fn from(
        cluster_config: &DruidClusterConfig,
        client: &Client,
    ) -> Result<AuthenticationClassesResolved> {
        let resolve_auth_class = |auth_details: ClientAuthenticationDetails| async move {
            auth_details.resolve_class(client).await
        };
        AuthenticationClassesResolved::resolve(cluster_config, resolve_auth_class).await
    }

    /// Retrieve all provided `AuthenticationClass` references.
    pub async fn resolve<R>(
        cluster_config: &DruidClusterConfig,
        resolve_auth_class: impl Fn(ClientAuthenticationDetails) -> R,
    ) -> Result<AuthenticationClassesResolved>
    where
        R: Future<Output = Result<AuthenticationClass, stackable_operator::client::Error>>,
    {
        let mut resolved_auth_classes = vec![];
        let auth_details = &cluster_config.authentication;

        match auth_details.len() {
            0 | 1 => {}
            _ => MultipleAuthenticationClassesNotSupportedSnafu.fail()?,
        }

        for entry in auth_details {
            let auth_class = resolve_auth_class(entry.clone())
                .await
                .context(AuthenticationClassRetrievalFailedSnafu)?;

            let auth_class_name = auth_class.name_any();
            let server_and_internal_secret_class = cluster_config
                .tls
                .as_ref()
                .and_then(|tls| tls.server_and_internal_secret_class.to_owned());

            match &auth_class.spec.provider {
                AuthenticationClassProvider::Tls(provider) => {
                    match &server_and_internal_secret_class {
                        Some(server_and_internal_secret_class) => {
                            if let Some(auth_class_secret_class) =
                                &provider.client_cert_secret_class
                            {
                                if auth_class_secret_class != server_and_internal_secret_class {
                                    return TlsAuthenticationClassSecretClassDiffersFromDruidServerTlsSnafu { auth_class_name: auth_class_name.to_string(), server_and_internal_secret_class: server_and_internal_secret_class.clone() }.fail()?;
                                }
                            }
                        }
                        None => {
                            // Check that a TLS AuthenticationClass is only used when Druid server_and_internal tls is enabled
                            return TlsAuthenticationClassWithoutDruidServerTlsSnafu {
                                auth_class_name: auth_class_name.to_string(),
                            }
                            .fail()?;
                        }
                    }
                    resolved_auth_classes.push(AuthenticationClassResolved::Tls {
                        provider: provider.clone(),
                    })
                }
                AuthenticationClassProvider::Ldap(provider) => {
                    if server_and_internal_secret_class.is_none() {
                        // We want the truststore to exist when using LDAP so that we can point to it
                        return LdapAuthenticationWithoutServerTlsNotSupportedSnafu.fail();
                    }
                    if provider.bind_credentials_mount_paths().is_none() {
                        // https://github.com/stackabletech/druid-operator/issues/383
                        return LdapAuthenticationWithoutBindCredentialsNotSupportedSnafu.fail();
                    }
                    resolved_auth_classes.push(AuthenticationClassResolved::Ldap {
                        auth_class_name: auth_class_name.to_owned(),
                        provider: provider.to_owned(),
                    })
                }
                AuthenticationClassProvider::Oidc(provider) => resolved_auth_classes.push(
                    AuthenticationClassesResolved::from_oidc(&auth_class_name, provider, entry)?,
                ),
                _ => AuthenticationClassProviderNotSupportedSnafu {
                    authentication_class_provider: auth_class.spec.provider.to_string(),
                    authentication_class: ObjectRef::<AuthenticationClass>::new(&auth_class_name),
                }
                .fail()?,
            };
        }

        Ok(AuthenticationClassesResolved {
            auth_classes: resolved_auth_classes,
        })
    }

    fn from_oidc(
        auth_class_name: &str,
        provider: &oidc::AuthenticationProvider,
        auth_details: &ClientAuthenticationDetails,
    ) -> Result<AuthenticationClassResolved> {
        let oidc_provider = match &provider.provider_hint {
            None => {
                info!("No OIDC provider hint given in AuthClass {auth_class_name}, assuming {default_oidc_provider_name}",
                    default_oidc_provider_name = serde_json::to_string(&DEFAULT_OIDC_PROVIDER).unwrap());
                DEFAULT_OIDC_PROVIDER
            }
            Some(oidc_provider) => oidc_provider.to_owned(),
        };

        ensure!(
            SUPPORTED_OIDC_PROVIDERS.contains(&oidc_provider),
            OidcProviderNotSupportedSnafu {
                auth_class_name,
                oidc_provider: serde_json::to_string(&oidc_provider).unwrap(),
            }
        );

        Ok(AuthenticationClassResolved::Oidc {
            auth_class_name: auth_class_name.to_string(),
            provider: provider.to_owned(),
            oidc: auth_details
                .oidc_or_error(auth_class_name)
                .context(OidcConfigurationInvalidSnafu)?
                .clone(),
        })
    }

    pub fn tls_authentication_enabled(&self) -> bool {
        if self.auth_classes.is_empty() {
            if let Some(AuthenticationClassResolved::Tls { .. }) = self.auth_classes.first() {
                return true;
            }
        }
        false
    }

    pub fn oidc_authentication_enabled(&self) -> bool {
        if self.auth_classes.is_empty() {
            if let Some(AuthenticationClassResolved::Oidc { .. }) = self.auth_classes.first() {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use indoc::formatdoc;
    use oidc::ClientAuthenticationOptions;

    use crate::DruidClusterConfig;

    use std::pin::Pin;

    use indoc::indoc;
    use stackable_operator::kube;

    use super::*;

    use crate::authentication::AuthenticationClassesResolved;

    const BASE_CLUSTER_CONFIG: &str = r#"
deepStorage:
  hdfs:
    configMapName: druid-hdfs
    directory: /druid
metadataStorageDatabase:
  dbType: derby
  connString: jdbc:derby://localhost:1527/var/druid/metadata.db;create=true
  host: localhost
  port: 1527
zookeeperConfigMapName: zk-config-map
    "#;

    #[tokio::test]
    async fn resolve_ldap() {
        let auth_classes_resolved = test_resolve_and_expect_success(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: ldap
                "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
                      port: 389
                      searchBase: ou=users,dc=example,dc=org
                      bindCredentials:
                        secretClass: ldap-bind-credentials
            "},
        )
        .await;

        assert_eq!(
            AuthenticationClassesResolved {
                auth_classes: vec![AuthenticationClassResolved::Ldap {
                    auth_class_name: "ldap".to_string(),
                    provider: serde_yaml::from_str::<ldap::AuthenticationProvider>(
                        "
                        hostname: my.ldap.server
                        port: 389
                        searchBase: ou=users,dc=example,dc=org
                        bindCredentials:
                          secretClass: ldap-bind-credentials
                        "
                    )
                    .unwrap()
                }]
            },
            auth_classes_resolved
        );
    }

    #[tokio::test]
    async fn resolve_oidc() {
        let auth_classes_resolved = test_resolve_and_expect_success(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: oidc-client-credentials
                "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            AuthenticationClassesResolved {
                auth_classes: vec![AuthenticationClassResolved::Oidc {
                    auth_class_name: "oidc".to_string(),
                    provider: serde_yaml::from_str::<oidc::AuthenticationProvider>(
                        "
                        hostname: my.oidc.server
                        principalClaim: preferred_username
                        scopes: []
                        "
                    )
                    .unwrap(),
                    oidc: serde_yaml::from_str::<ClientAuthenticationOptions>(
                        "
                        clientCredentialsSecret: oidc-client-credentials
                        "
                    )
                    .unwrap()
                }]
            },
            auth_classes_resolved
        );
    }

    #[tokio::test]
    async fn resolve_tls() {
        let auth_classes_resolved = test_resolve_and_expect_success(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: tls
                "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: tls
                spec:
                  provider:
                    tls: {}
            "},
        )
        .await;

        assert_eq!(
            AuthenticationClassesResolved {
                auth_classes: vec![AuthenticationClassResolved::Tls {
                    provider: serde_yaml::from_str::<tls::AuthenticationProvider>("").unwrap(),
                }]
            },
            auth_classes_resolved
        );
    }

    #[tokio::test]
    async fn reject_multiple_authentication_methods() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: druid-oidc-client
                - authenticationClass: ldap
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                ---
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
                      port: 389
                      searchBase: ou=users,dc=example,dc=org
                      bindCredentials:
                          secretClass: ldap-bind-credentials
            "},
        )
        .await;

        assert_eq!(
            "only one authentication class is currently supported at a time.",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_oidc_details_are_missing() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: oidc
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                invalid OIDC configuration

                Caused by this error:
                  1: authentication details for OIDC were not specified. The AuthenticationClass "oidc" uses an OIDC provider, you need to specify OIDC authentication details (such as client credentials) as well"#
            },
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_ldap_bind_credentials_missing() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: ldap
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
                      port: 389
                      searchBase: ou=users,dc=example,dc=org
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                LDAP authentication without bind credentials is currently not supported. See https://github.com/stackabletech/druid-operator/issues/383 for details"#
            },
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_tls_without_tls_secret_class() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: tls
                tls:
                  serverAndInternalSecretClass: null
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: tls
                spec:
                  provider:
                    tls:
                      clientCertSecretClass: tls
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                client authentication using TLS (as requested by AuthenticationClass tls) can not be used when Druid server and internal TLS is disabled"#
            },
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_ldap_without_tls_secret_class() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: ldap
                tls:
                  serverAndInternalSecretClass: null
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
                      port: 389
                      searchBase: ou=users,dc=example,dc=org
                      bindCredentials:
                          secretClass: ldap-bind-credentials
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                LDAP authentication requires server and internal tls to be enabled"#
            },
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_tls_with_wrong_tls_secret_class() {
        let error_message = test_resolve_and_expect_error(
            formatdoc! {"\
                {BASE_CLUSTER_CONFIG}
                authentication:
                - authenticationClass: tls
                tls:
                  serverAndInternalSecretClass: other-tls
            "}
            .as_str(),
            indoc! {"
                ---
                metadata:
                  name: tls
                spec:
                  provider:
                    tls:
                      clientCertSecretClass: tls
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                client authentication using TLS (as requested by AuthenticationClass tls) can only use the same SecretClass as the Druid instance is using for server and internal communication (SecretClass other-tls in this case)"#
            },
            error_message
        );
    }

    /// Call `AuthenticationClassesResolved::resolve` with
    /// the given lists of `AuthenticationDetails` and
    /// `AuthenticationClass`es and return the
    /// `AuthenticationClassesResolved`.
    ///
    /// The parameters are meant to be valid and resolvable. Just fail
    /// if there is an error.
    async fn test_resolve_and_expect_success(
        cluster_config_yaml: &str,
        auth_classes_yaml: &str,
    ) -> AuthenticationClassesResolved {
        test_resolve(cluster_config_yaml, auth_classes_yaml)
            .await
            .expect("The AuthenticationClassesResolved should be resolvable.")
    }

    /// Call `AuthenticationClassesResolved::resolve` with
    /// the given lists of `ClientAuthenticationDetails` and
    /// `AuthenticationClass`es and return the error message.
    ///
    /// The parameters are meant to be invalid or not resolvable. Just
    /// fail if there is no error.
    async fn test_resolve_and_expect_error(
        cluster_config_yaml: &str,
        auth_classes_yaml: &str,
    ) -> String {
        dbg!(&cluster_config_yaml);
        let error = test_resolve(cluster_config_yaml, auth_classes_yaml)
            .await
            .expect_err(
                "The AuthenticationClassesResolved are invalid and should not be resolvable.",
            );
        snafu::Report::from_error(error)
            .to_string()
            .trim_end()
            .to_owned()
    }

    /// Call `AuthenticationClassesResolved::resolve` with
    /// the given lists of `AuthenticationDetails` and
    /// `AuthenticationClass`es and return the result.
    async fn test_resolve(
        cluster_config_yaml: &str,
        auth_classes_yaml: &str,
    ) -> Result<AuthenticationClassesResolved> {
        let cluster_config = deserialize_cluster_config(cluster_config_yaml);

        let auth_classes = deserialize_auth_classes(auth_classes_yaml);

        let resolve_auth_class = create_auth_class_resolver(auth_classes);

        AuthenticationClassesResolved::resolve(&cluster_config, resolve_auth_class).await
    }

    /// Deserialize the given list of
    /// `SupersetClientAuthenticationDetails`.
    ///
    /// Fail if the given string cannot be deserialized.
    fn deserialize_cluster_config(input: &str) -> DruidClusterConfig {
        let deserializer = serde_yaml::Deserializer::from_str(input);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .expect("The definition of the DruidClusterConfig should be valid.")
    }

    /// Deserialize the given `AuthenticationClass` YAML documents.
    ///
    /// Fail if the given string cannot be deserialized.
    fn deserialize_auth_classes(input: &str) -> Vec<AuthenticationClass> {
        if input.is_empty() {
            Vec::new()
        } else {
            let deserializer = serde_yaml::Deserializer::from_str(input);
            deserializer
                .map(|d| {
                    serde_yaml::with::singleton_map_recursive::deserialize(d)
                        .expect("The definition of the AuthenticationClass should be valid.")
                })
                .collect()
        }
    }

    /// Returns a function which resolves `AuthenticationClass` names to
    /// the given list of `AuthenticationClass`es.
    ///
    /// Use this function in the tests to replace
    /// `stackable_operator::commons::authentication::ClientAuthenticationDetails`
    /// which requires a Kubernetes client.
    fn create_auth_class_resolver(
        auth_classes: Vec<AuthenticationClass>,
    ) -> impl Fn(
        ClientAuthenticationDetails,
    ) -> Pin<
        Box<dyn Future<Output = Result<AuthenticationClass, stackable_operator::client::Error>>>,
    > {
        move |auth_details: ClientAuthenticationDetails| {
            let auth_classes = auth_classes.clone();
            Box::pin(async move {
                auth_classes
                    .iter()
                    .find(|auth_class| {
                        auth_class.metadata.name.as_ref()
                            == Some(auth_details.authentication_class_name())
                    })
                    .cloned()
                    .ok_or_else(|| stackable_operator::client::Error::ListResources {
                        source: kube::Error::Api(kube::error::ErrorResponse {
                            code: 404,
                            message: "AuthenticationClass not found".into(),
                            reason: "NotFound".into(),
                            status: "Failure".into(),
                        }),
                    })
            })
        }
    }
}
