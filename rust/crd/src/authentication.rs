use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{
        ldap, oidc, tls, AuthenticationClass, AuthenticationClassProvider,
        ClientAuthenticationDetails,
    },
    kube::ResourceExt,
};

use crate::DruidCluster;

type Result<T, E = Error> = std::result::Result<T, E>;

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 3] = ["LDAP", "TLS", "OIDC"];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::client::Error,
    },
    // TODO: Adapt message if multiple authentication classes are supported simultaneously
    #[snafu(display("only one authentication class is currently supported at a time. Possible Authentication class providers are {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}"))]
    MultipleAuthenticationClassesProvided,
    #[snafu(display(
    "failed to use authentication provider [{provider}] for authentication class [{auth_class_name}] - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        auth_class_name: String,
        provider: String,
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
    #[snafu(display("Invalid OIDC configuration"))]
    InvalidOidcConfiguration {
        source: stackable_operator::commons::authentication::Error,
    },
}

#[derive(Clone, PartialEq, Debug)]
pub enum ResolvedAuthenticationClass {
    /// An [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication) to use.
    Tls {
        auth_class_name: String,
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

/// Resolve provided AuthenticationClasses via API calls and validate the contents.
/// Currently errors out if:
/// - AuthenticationClass could not be resolved
/// - Validation failed
pub async fn get_resolved_authentication_class(
    druid: &DruidCluster,
    client: &Client,
) -> Result<Option<ResolvedAuthenticationClass>, Error> {
    let mut resolved_auth_classes = vec![];
    let client_auth_details_list = druid.spec.cluster_config.authentication.clone();

    for client_auth_details in client_auth_details_list {
        let auth_class = client_auth_details
            .resolve_class(client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;

        match resolve_authentication_class(auth_class, client_auth_details) {
            Ok(resolved_auth_class) => resolved_auth_classes.push(resolved_auth_class),
            Err(err) => return Err(err),
        }
    }

    validate(
        resolved_auth_classes,
        druid
            .spec
            .cluster_config
            .tls
            .as_ref()
            .and_then(|tls| tls.server_and_internal_secret_class.clone()),
    )
}

fn resolve_authentication_class(
    auth_class: AuthenticationClass,
    client_auth_details: ClientAuthenticationDetails,
) -> Result<ResolvedAuthenticationClass, Error> {
    match &auth_class.spec.provider {
        AuthenticationClassProvider::Oidc(auth_provider) => Ok(ResolvedAuthenticationClass::Oidc {
            auth_class_name: auth_class.name_any(),
            provider: auth_provider.clone(),
            oidc: client_auth_details
                .oidc_or_error(&auth_class.name_any())
                .context(InvalidOidcConfigurationSnafu)?
                .clone(),
        }),
        AuthenticationClassProvider::Ldap(auth_provider) => Ok(ResolvedAuthenticationClass::Ldap {
            auth_class_name: auth_class.name_any(),
            provider: auth_provider.clone(),
        }),
        AuthenticationClassProvider::Tls(auth_provider) => Ok(ResolvedAuthenticationClass::Tls {
            auth_class_name: auth_class.name_any(),
            provider: auth_provider.clone(),
        }),
        _ => Err(Error::AuthenticationProviderNotSupported {
            auth_class_name: auth_class.name_any(),
            provider: auth_class.spec.provider.to_string(),
        }),
    }
}

/// Validates the resolved AuthenticationClasses.
/// Currently errors out if:
/// - More than one AuthenticationClass was provided
/// - TLS secret class misconfiguration while using a TLS or LDAP authentication class
fn validate(
    resolved_auth_classes: Vec<ResolvedAuthenticationClass>,
    server_and_internal_secret_class: Option<String>,
) -> Result<Option<ResolvedAuthenticationClass>, Error> {
    if resolved_auth_classes.len() > 1 {
        return Err(Error::MultipleAuthenticationClassesProvided);
    }

    if let Some(resolved_auth_class) = resolved_auth_classes.first() {
        match resolved_auth_class {
            ResolvedAuthenticationClass::Tls {
                auth_class_name,
                provider,
            } => {
                match &server_and_internal_secret_class {
                    Some(server_and_internal_secret_class) => {
                        if let Some(auth_class_secret_class) = &provider.client_cert_secret_class {
                            if auth_class_secret_class != server_and_internal_secret_class {
                                return Err(Error::TlsAuthenticationClassSecretClassDiffersFromDruidServerTls { auth_class_name: auth_class_name.to_string(), server_and_internal_secret_class: server_and_internal_secret_class.clone() });
                            }
                        }
                    }
                    None => {
                        // Check that a TLS AuthenticationClass is only used when Druid server_and_internal tls is enabled
                        return Err(Error::TlsAuthenticationClassWithoutDruidServerTls {
                            auth_class_name: auth_class_name.to_string(),
                        });
                    }
                }
            }

            ResolvedAuthenticationClass::Ldap {
                auth_class_name: _,
                provider,
            } => {
                if server_and_internal_secret_class.is_none() {
                    // We want the truststore to exist when using LDAP so that we can point to it
                    return LdapAuthenticationWithoutServerTlsNotSupportedSnafu.fail();
                }
                if provider.bind_credentials_mount_paths().is_none() {
                    // https://github.com/stackabletech/druid-operator/issues/383
                    return LdapAuthenticationWithoutBindCredentialsNotSupportedSnafu.fail();
                }
            }
            ResolvedAuthenticationClass::Oidc {
                auth_class_name: _,
                provider: _,
                oidc: _,
            } => {}
        }
        Ok(Some(resolved_auth_class.clone()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use indoc::formatdoc;
    use stackable_operator::commons::authentication::Error as AuthError;

    use crate::DruidClusterConfig;
    //use stackable_operator::commons::authentication::tls::Tls;
    use crate::{authentication::Error, tests::deserialize_yaml_str};
    //use stackable_operator::kube::ResourceExt;
    use crate::authentication::{
        resolve_authentication_class, validate, ResolvedAuthenticationClass,
    };

    const BASE_DRUID_CONFIGURATION: &str = r#"
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

    #[test]
    fn test_authentication_classes_validation() {
        let classes = vec![];
        assert!(
            validate(classes, None).is_ok(),
            "Supported: No server tls, no AuthenticationClasses"
        );

        let classes = vec![get_tls_authentication_class_without_secret_class()];
        assert!(
            matches!(
                validate(classes, None),
                Err(Error::TlsAuthenticationClassWithoutDruidServerTls { auth_class_name }) if auth_class_name == "tls"
            ),
            "Not supported: No server tls, TLS authentication class"
        );

        let classes = vec![get_ldap_authentication_class()];
        assert!(
            matches!(
                validate(classes, None),
                Err(Error::LdapAuthenticationWithoutServerTlsNotSupported {})
            ),
            "Not supported: No server tls, LDAP authentication class"
        );

        let classes = vec![];
        assert!(
            validate(classes, Some("tls".to_string())).is_ok(),
            "Supported: Server tls, no AuthenticationClasses"
        );

        let classes = vec![get_ldap_authentication_class()];
        assert!(
            validate(classes, Some("tls".to_string())).is_ok(),
            "Supported: Server tls, LDAP authentication class"
        );

        let classes = vec![get_tls_authentication_class_without_secret_class()];
        assert!(
            validate(classes, Some("tls".to_string())).is_ok(),
            "Supported: Server tls, TLS authentication class without SecretClass"
        );

        let classes = vec![get_tls_authentication_class_with_secret_class_tls()];
        assert!(
            validate(classes, Some("tls".to_string())).is_ok(),
            "Supported: Server tls, TLS authentication class with same SecretClass as Druid cluster"
        );

        let classes = vec![get_tls_authentication_class_with_secret_class_druid_clients()];
        assert!(
            matches!(
                validate(classes, Some("tls-druid".to_string())),
                Err(Error::TlsAuthenticationClassSecretClassDiffersFromDruidServerTls{ auth_class_name, server_and_internal_secret_class }) if auth_class_name == "tls-druid-clients" && server_and_internal_secret_class == "tls-druid"
            ),
            "Not supported: Server tls, TLS authentication class with *different* SecretClass as Druid cluster"
        );

        let classes = vec![get_ldap_authentication_class_without_bind_credentials()];
        assert!(
            matches!(
                validate(classes, Some("tls".to_string())),
                Err(Error::LdapAuthenticationWithoutBindCredentialsNotSupported {})
            ),
            "Not supported: Server tls, LDAP authentication class without bind credentials"
        );

        let classes = vec![
            get_tls_authentication_class_without_secret_class(),
            get_tls_authentication_class_without_secret_class(),
        ];
        assert!(
            matches!(
                validate(classes, Some("tls-druid".to_string())),
                Err(Error::MultipleAuthenticationClassesProvided {})
            ),
            "Not supported: Server tls, multiple authentication classes"
        );

        let classes = vec![
            get_tls_authentication_class_without_secret_class(),
            get_ldap_authentication_class(),
        ];
        assert!(
            matches!(
                validate(classes, Some("tls-druid".to_string())),
                Err(Error::MultipleAuthenticationClassesProvided {})
            ),
            "Not supported: Server tls, multiple authentication classes"
        );
        assert!(
            matches!(
                get_oidc_authentication_class_without_oidc_secret_ref_(),
                Err(Error::InvalidOidcConfiguration {source: AuthError::OidcAuthenticationDetailsNotSpecified {
                    auth_class_name,
                }}) if auth_class_name == "oidc"
            ),
            "Not supported: OIDC authentication class with no OIDC authentication details"
        )
    }

    fn get_tls_authentication_class_without_secret_class() -> ResolvedAuthenticationClass {
        let auth_class_input = r#"
metadata:
  name: tls
spec:
  provider:
    tls: {}
"#;
        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: tls-druid-clients
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
        .unwrap()
    }

    fn get_tls_authentication_class_with_secret_class_tls() -> ResolvedAuthenticationClass {
        let auth_class_input = r#"
metadata:
  name: tls-tls
spec:
  provider:
    tls:
      clientCertSecretClass: tls
"#;

        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: tls-tls
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
        .unwrap()
    }

    fn get_tls_authentication_class_with_secret_class_druid_clients() -> ResolvedAuthenticationClass
    {
        let auth_class_input = r#"
metadata:
  name: tls-druid-clients
spec:
  provider:
    tls:
      clientCertSecretClass: druid-clients
"#;

        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: tls-druid-clients
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
        .unwrap()
    }

    fn get_ldap_authentication_class() -> ResolvedAuthenticationClass {
        let auth_class_input = r#"
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
"#;

        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: ldap
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
        .unwrap()
    }

    fn get_ldap_authentication_class_without_bind_credentials() -> ResolvedAuthenticationClass {
        let auth_class_input = r#"
apiVersion: authentication.stackable.tech/v1alpha1
kind: AuthenticationClass
metadata:
  name: ldap
spec:
  provider:
    ldap:
      hostname: my.ldap.server
      port: 389
      searchBase: ou=users,dc=example,dc=org
"#;

        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: ldap
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
        .unwrap()
    }

    fn get_oidc_authentication_class_without_oidc_secret_ref_(
    ) -> Result<ResolvedAuthenticationClass, Error> {
        let auth_class_input = r#"
apiVersion: authentication.stackable.tech/v1alpha1
kind: AuthenticationClass
metadata:
  name: oidc
spec:
  provider:
    oidc:
      hostname: keycloak.default.svc.cluster.local
      rootPath: /realms/test
      principalClaim: preferred_username
      scopes:
        - openid
        - email
        - profile
      providerHint: Keycloak
"#;

        let cluster_config_input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        authentication:
          - authenticationClass: oidc
        "};

        let auth_class = deserialize_yaml_str(auth_class_input);
        let cluster_config: DruidClusterConfig = deserialize_yaml_str(&cluster_config_input);
        resolve_authentication_class(
            auth_class,
            cluster_config.authentication.first().unwrap().to_owned(),
        )
    }
}
