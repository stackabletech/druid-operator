pub mod ldap;
pub mod oidc;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{oidc as stackable_operator_oidc, AuthenticationClass, AuthenticationClassProvider, ClientAuthenticationDetails},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
};

type Result<T, E = Error> = std::result::Result<T, E>;

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 2] = ["LDAP", "TLS"];

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
        "failed to use authentication provider [{provider}] for authentication class [{authentication_class}] - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        authentication_class: ObjectRef<AuthenticationClass>,
        provider: String,
    },
    #[snafu(display("LDAP authentication without bind credentials is currently not supported. See https://github.com/stackabletech/druid-operator/issues/383 for details"))]
    LdapAuthenticationWithoutBindCredentialsNotSupported {},
    #[snafu(display("LDAP authentication requires server and internal tls to be enabled"))]
    LdapAuthenticationWithoutServerTlsNotSupported {},
    #[snafu(display(
        "client authentication using TLS (as requested by AuthenticationClass {authentication_class}) can not be used when Druid server and internal TLS is disabled",
    ))]
    TlsAuthenticationClassWithoutDruidServerTls {
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display(
        "client authentication using TLS (as requested by AuthenticationClass {authentication_class}) can only use the same SecretClass as the Druid instance is using for server and internal communication (SecretClass {server_and_internal_secret_class} in this case)",
    ))]
    TlsAuthenticationClassSecretClassDiffersFromDruidServerTls {
        authentication_class: ObjectRef<AuthenticationClass>,
        server_and_internal_secret_class: String,
    },
    #[snafu(display("Invalid OIDC configuration"))]
    InvalidOidcConfiguration {
        source: stackable_operator::commons::authentication::Error,
    },
}

pub struct ResolvedAuthenticationClass {
    /// An [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication) to use.
    pub authentication_class: AuthenticationClass,
    pub oidc: Option<stackable_operator_oidc::ClientAuthenticationOptions>,
}

pub struct ResolvedAuthenticationClasses {
    resolved_authentication_classes: Vec<ResolvedAuthenticationClass>
}

impl ResolvedAuthenticationClasses {
    pub fn new(resolved_authentication_classes: Vec<ResolvedAuthenticationClass>) -> Self {
        Self {
            resolved_authentication_classes,
        }
    }

    /// Resolve provided AuthenticationClasses via API calls and validate the contents.
    /// Currently errors out if:
    /// - AuthenticationClass could not be resolved
    /// - Validation failed
    pub async fn resolve_authentication_classes(
        client: &Client,
        client_auth_details: &Vec<ClientAuthenticationDetails>,
    ) -> Result<ResolvedAuthenticationClasses, Error> {
        let mut resolved_auth_classes = vec![];

    for client_authentication_detail in client_auth_details {
        let resolved_auth_class = client_authentication_detail
            .resolve_class(client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;
        let auth_class_name = resolved_auth_class.name_any();

        resolved_auth_classes.push(ResolvedAuthenticationClass {
            oidc: match &resolved_auth_class.spec.provider {
                AuthenticationClassProvider::Oidc(_) => Some(
                    client_authentication_detail
                        .oidc_or_error(&auth_class_name)
                        .context(InvalidOidcConfigurationSnafu)?
                        .clone(),
                ),
                _ => None,
            },
            authentication_class: resolved_auth_class,
        });
    }

    Ok(ResolvedAuthenticationClasses::new(resolved_auth_classes))

    /* 
        ResolvedAuthenticationClasses::new(resolved_authentication_classes).validate(
            druid
                .spec
                .cluster_config
                .tls
                .as_ref()
                .and_then(|tls| tls.server_and_internal_secret_class.clone()),
        )
        */
    }


    /// Return the (first) TLS `AuthenticationClass` if available
    pub fn get_tls_authentication_class(&self) -> Option<&ResolvedAuthenticationClass> {
        self.resolved_authentication_classes
            .iter()
            .find(|auth| matches!(auth.authentication_class.spec.provider, AuthenticationClassProvider::Tls(_)))
    }

    pub fn get_ldap_authentication_class(&self) -> Option<&ResolvedAuthenticationClass> {
        self.resolved_authentication_classes
            .iter()
            .find(|auth| matches!(auth.authentication_class.spec.provider, AuthenticationClassProvider::Ldap(_)))
    }

    pub fn get_oidc_authentication_class(&self) -> Option<&ResolvedAuthenticationClass> {
        self.resolved_authentication_classes
            .iter()
            .find(|auth| matches!(auth.authentication_class.spec.provider, AuthenticationClassProvider::Oidc(_)))
    }

    /// Validates the resolved AuthenticationClasses.
    /// Currently errors out if:
    /// - More than one AuthenticationClass was provided
    /// - AuthenticationClass provider was not supported
    pub fn validate(self, server_and_internal_secret_class: Option<String>) -> Result<Self, Error> {
        if self.resolved_authentication_classes.len() > 1 {
            return Err(Error::MultipleAuthenticationClassesProvided);
        }

        for resolved_auth_class in &self.resolved_authentication_classes {
            match &resolved_auth_class.authentication_class.spec.provider {
                AuthenticationClassProvider::Tls(_) => {}
                AuthenticationClassProvider::Ldap(ldap) => {
                    if server_and_internal_secret_class.is_none() {
                        // We want the truststore to exist when using LDAP so that we can point to it
                        return LdapAuthenticationWithoutServerTlsNotSupportedSnafu.fail();
                    }
                    if ldap.bind_credentials_mount_paths().is_none() {
                        // https://github.com/stackabletech/druid-operator/issues/383
                        return LdapAuthenticationWithoutBindCredentialsNotSupportedSnafu.fail();
                    }
                }
                AuthenticationClassProvider::Oidc(_) => {
                }
                _ => {
                    return Err(Error::AuthenticationProviderNotSupported {
                        authentication_class: ObjectRef::from_obj(&resolved_auth_class.authentication_class),
                        provider: resolved_auth_class.authentication_class.spec.provider.to_string(),
                    })
                }
            }
        }

        if let Some(resolved_tls_auth_class) = self.get_tls_authentication_class() {
            match &server_and_internal_secret_class {
                Some(server_and_internal_secret_class) => {
                    // Check that the tls AuthenticationClass uses the same SecretClass as the Druid server itself
                    match &resolved_tls_auth_class.authentication_class.spec.provider {
                        AuthenticationClassProvider::Tls(tls) => {
                            if let Some(auth_class_secret_class) = &tls.client_cert_secret_class {
                                if auth_class_secret_class != server_and_internal_secret_class {
                                    return Err(Error::TlsAuthenticationClassSecretClassDiffersFromDruidServerTls { authentication_class:  ObjectRef::from_obj(&resolved_tls_auth_class.authentication_class), server_and_internal_secret_class: server_and_internal_secret_class.clone() });
                                }
                            }
                        }
                        _ => unreachable!(
                            "We know for sure we can only have tls AuthenticationClasses here"
                        ),
                    }
                }
                None => {
                    // Check that no tls AuthenticationClass is used when Druid server_and_internal tls is disabled
                    return Err(Error::TlsAuthenticationClassWithoutDruidServerTls {
                        authentication_class: ObjectRef::from_obj(&resolved_tls_auth_class.authentication_class),
                    });
                }
            }
        }

        Ok(self)
    }
}


#[cfg(test)]
mod tests {
    use crate::{
        authentication::{Error, ResolvedAuthenticationClass, ResolvedAuthenticationClasses},
        tests::deserialize_yaml_str,
    };
    use stackable_operator::kube::ResourceExt;

    #[test]
    fn test_authentication_classes_validation() {
        let classes = ResolvedAuthenticationClasses::new(vec![]);
        assert!(
            classes.validate(None).is_ok(),
            "Supported: No server tls, no AuthenticationClasses"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_without_secret_class(),
        ]);
        assert!(
            matches!(
                classes.validate(None),
                Err(Error::TlsAuthenticationClassWithoutDruidServerTls { authentication_class }) if authentication_class.name == "tls",
            ),
            "Not supported: No server tls, TLS authentication class"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![get_ldap_authentication_class()]);
        assert!(
            matches!(
                classes.validate(None),
                Err(Error::LdapAuthenticationWithoutServerTlsNotSupported {})
            ),
            "Not supported: No server tls, LDAP authentication class"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![]);
        assert!(
            classes.validate(Some("tls".to_string())).is_ok(),
            "Supported: Server tls, no AuthenticationClasses"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![get_ldap_authentication_class()]);
        assert!(
            classes.validate(Some("tls".to_string())).is_ok(),
            "Supported: Server tls, LDAP authentication class"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_without_secret_class(),
        ]);
        assert!(
            classes.validate(Some("tls".to_string())).is_ok(),
            "Supported: Server tls, TLS authentication class without SecretClass"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_with_secret_class_tls(),
        ]);
        assert!(
            classes.validate(Some("tls".to_string())).is_ok(),
            "Supported: Server tls, TLS authentication class with same SecretClass as Druid cluster"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_with_secret_class_druid_clients(),
        ]);
        assert!(
            matches!(
                classes.validate(Some("tls-druid".to_string())),
                Err(Error::TlsAuthenticationClassSecretClassDiffersFromDruidServerTls{ authentication_class, server_and_internal_secret_class }) if authentication_class.name == "tls-druid-clients" && server_and_internal_secret_class == "tls-druid"
            ),
            "Not supported: Server tls, TLS authentication class with *different* SecretClass as Druid cluster"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_ldap_authentication_class_without_bind_credentials(),
        ]);
        assert!(
            matches!(
                classes.validate(Some("tls".to_string())),
                Err(Error::LdapAuthenticationWithoutBindCredentialsNotSupported {})
            ),
            "Not supported: Server tls, LDAP authentication class without bind credentials"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_without_secret_class(),
            get_tls_authentication_class_without_secret_class(),
        ]);
        assert!(
            matches!(
                classes.validate(Some("tls-druid".to_string())),
                Err(Error::MultipleAuthenticationClassesProvided {})
            ),
            "Not supported: Server tls, multiple authentication classes"
        );

        let classes = ResolvedAuthenticationClasses::new(vec![
            get_tls_authentication_class_without_secret_class(),
            get_ldap_authentication_class(),
        ]);
        assert!(
            matches!(
                classes.validate(Some("tls-druid".to_string())),
                Err(Error::MultipleAuthenticationClassesProvided {})
            ),
            "Not supported: Server tls, multiple authentication classes"
        );
    }

    #[test]
    fn test_get_tls_authentication_class() {
        let classes = ResolvedAuthenticationClasses::new(vec![
            get_ldap_authentication_class(),
            get_tls_authentication_class_without_secret_class(),
            get_tls_authentication_class_with_secret_class_druid_clients(),
        ]);

        let tls_authentication_class = classes.get_tls_authentication_class();

        // TODO Check deriving PartialEq for AuthenticationClass so that we can compare them directly instead of comparing the names
        assert_eq!(
            tls_authentication_class.map(|class| class.authentication_class.name_any()),
            Some("tls".to_string())
        );
    }

    #[test]
    fn test_get_ldap_authentication_class() {
        let classes = ResolvedAuthenticationClasses::new(vec![
            get_ldap_authentication_class(),
            get_tls_authentication_class_without_secret_class(),
            get_tls_authentication_class_with_secret_class_druid_clients(),
        ]);

        let ldap_authentication_class = classes.get_ldap_authentication_class();

        // TODO Check deriving PartialEq for AuthenticationClass so that we can compare them directly instead of comparing the names
        assert_eq!(
            ldap_authentication_class.map(|class| class.authentication_class.name_any()),
            Some("ldap".to_string())
        );
    }

    fn get_tls_authentication_class_without_secret_class() -> ResolvedAuthenticationClass {
        let input = r#"
apiVersion: authentication.stackable.tech/v1alpha1
kind: AuthenticationClass
metadata:
  name: tls
spec:
  provider:
    tls: {}
"#;
ResolvedAuthenticationClass {
    authentication_class: deserialize_yaml_str(input),
    oidc: None
}
    }

    fn get_tls_authentication_class_with_secret_class_tls() -> ResolvedAuthenticationClass {
        let input = r#"
apiVersion: authentication.stackable.tech/v1alpha1
kind: AuthenticationClass
metadata:
  name: tls-tls
spec:
  provider:
    tls:
      clientCertSecretClass: tls
"#;
ResolvedAuthenticationClass {
    authentication_class: deserialize_yaml_str(input),
    oidc: None
    }
}

    fn get_tls_authentication_class_with_secret_class_druid_clients() -> ResolvedAuthenticationClass {
        let input = r#"
apiVersion: authentication.stackable.tech/v1alpha1
kind: AuthenticationClass
metadata:
  name: tls-druid-clients
spec:
  provider:
    tls:
      clientCertSecretClass: druid-clients
"#;
        ResolvedAuthenticationClass {
            authentication_class: deserialize_yaml_str(input),
            oidc: None
        }
    }

    fn get_ldap_authentication_class() -> ResolvedAuthenticationClass {
        let input = r#"
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
      bindCredentials:
        secretClass: ldap-bind-credentials
"#;
ResolvedAuthenticationClass {
    authentication_class: deserialize_yaml_str(input),
    oidc: None
}
    }

    fn get_ldap_authentication_class_without_bind_credentials() -> ResolvedAuthenticationClass {
        let input = r#"
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
ResolvedAuthenticationClass {
    authentication_class: deserialize_yaml_str(input),
    oidc: None
}
    }
}
