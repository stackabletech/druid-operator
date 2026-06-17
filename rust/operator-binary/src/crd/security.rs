use stackable_operator::v2::types::kubernetes::SecretClassName;

use crate::crd::{
    STACKABLE_TRUST_STORE_PASSWORD, authentication::AuthenticationClassesResolved, v1alpha1,
};

/// The validated TLS security decision for a Druid cluster: which server/internal TLS `SecretClass`
/// is configured (if any) and whether a client `AuthenticationClass` using TLS is in use.
pub struct DruidTlsSecurity {
    /// Whether a client `AuthenticationClass` using TLS is configured.
    tls_authentication_enabled: bool,
    /// The TLS `SecretClass` used for external client -> server and server <-> server
    /// communication, if any.
    server_and_internal_secret_class: Option<SecretClassName>,
}

// Port names (shared with the build-side renderer and other build modules)
pub const PLAINTEXT_PORT_NAME: &str = "http";
pub const TLS_PORT_NAME: &str = "https";

// Misc TLS (shared with the build-side renderer and the LDAP authentication module)
pub const TLS_STORE_PASSWORD: &str = "changeit";
pub const STACKABLE_TLS_DIR: &str = "/stackable/tls";

pub const INTERNAL_INITIAL_CLIENT_PASSWORD_ENV: &str = "INTERNAL_INITIAL_CLIENT_PASSWORD";

impl DruidTlsSecurity {
    #[cfg(test)]
    pub(crate) fn new(
        tls_authentication_enabled: bool,
        server_and_internal_secret_class: Option<SecretClassName>,
    ) -> Self {
        Self {
            tls_authentication_enabled,
            server_and_internal_secret_class,
        }
    }

    /// Create a `DruidTlsSecurity` struct from the Druid custom resource and the resolved
    /// `AuthenticationClass` references.
    pub fn new_from_druid_cluster(
        druid: &v1alpha1::DruidCluster,
        auth_classes: &AuthenticationClassesResolved,
    ) -> Self {
        DruidTlsSecurity {
            tls_authentication_enabled: auth_classes.tls_authentication_enabled(),
            server_and_internal_secret_class: druid
                .spec
                .cluster_config
                .tls
                .as_ref()
                .and_then(|tls| tls.server_and_internal_secret_class.clone()),
        }
    }

    /// Check if TLS encryption is enabled. This could be due to:
    ///
    /// - A provided server `SecretClass`
    /// - A provided client `AuthenticationClass` using tls
    ///
    /// This affects init container commands, Druid configuration, volume mounts
    /// and the Druid client port.
    pub fn tls_enabled(&self) -> bool {
        // TODO: This must be adapted if other authentication methods are supported and require TLS
        self.tls_authentication_enabled || self.server_and_internal_secret_class.is_some()
    }

    /// Whether a client `AuthenticationClass` using TLS is configured.
    pub(crate) fn tls_authentication_enabled(&self) -> bool {
        self.tls_authentication_enabled
    }

    /// The optional TLS `SecretClass` for external client -> server and server <-> server
    /// communication.
    pub(crate) fn server_and_internal_secret_class(&self) -> Option<&SecretClassName> {
        self.server_and_internal_secret_class.as_ref()
    }
}

/// Generate a bash command to add a CA to a truststore
pub fn add_cert_to_trust_store_cmd(
    cert_file: &str,
    destination_directory: &str,
    store_password: &str,
) -> Vec<String> {
    let truststore = format!("{destination_directory}/truststore.p12");
    vec![format!(
        "if [ -f {truststore} ]; then cert-tools generate-pkcs12-truststore --pkcs12 {truststore}:{store_password} --pem {cert_file} --out {truststore} --out-password {store_password}; else cert-tools generate-pkcs12-truststore --pem {cert_file} --out {truststore} --out-password {store_password}; fi"
    )]
}

/// Generate a bash command to add a CA to the truststore that is passed to the JVM
pub fn add_cert_to_jvm_trust_store_cmd(cert_file: &str) -> Vec<String> {
    add_cert_to_trust_store_cmd(cert_file, "/stackable", STACKABLE_TRUST_STORE_PASSWORD)
}
