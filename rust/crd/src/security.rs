use crate::{
    authentication::{self, ResolvedAuthenticationClasses},
    tls, DruidCluster, DruidRole, METRICS_PORT,
};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
    client::Client,
    commons::authentication::AuthenticationClass,
    k8s_openapi::{
        api::core::v1::{ContainerPort, Probe, ServicePort, TCPSocketAction},
        apimachinery::pkg::util::intstr::IntOrString,
    },
};
use std::collections::BTreeMap;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to process authentication class"))]
    InvalidAuthenticationClassConfiguration { source: authentication::Error },
}

/// Helper struct combining TLS settings for server and internal tls with the resolved AuthenticationClasses
pub struct DruidTlsSecurity {
    resolved_authentication_classes: ResolvedAuthenticationClasses,
    server_and_internal_secret_class: Option<String>,
}

impl DruidTlsSecurity {
    // Ports
    pub const ENABLE_PLAINTEXT_PORT: &str = "druid.enablePlaintextPort";
    pub const PLAINTEXT_PORT: &str = "druid.plaintextPort";
    pub const ENABLE_TLS_PORT: &str = "druid.enableTlsPort";
    pub const TLS_PORT: &str = "druid.tlsPort";
    // Port names
    const PLAINTEXT_PORT_NAME: &str = "http";
    const TLS_PORT_NAME: &str = "https";
    const METRICS_PORT_NAME: &str = "metrics";
    // Client side (Druid) TLS
    pub const CLIENT_HTTPS_KEY_STORE_PATH: &str = "druid.client.https.keyStorePath";
    pub const CLIENT_HTTPS_KEY_STORE_TYPE: &str = "druid.client.https.keyStoreType";
    pub const CLIENT_HTTPS_KEY_STORE_PASSWORD: &str = "druid.client.https.keyStorePassword";
    pub const CLIENT_HTTPS_TRUST_STORE_PATH: &str = "druid.client.https.trustStorePath";
    pub const CLIENT_HTTPS_TRUST_STORE_TYPE: &str = "druid.client.https.trustStoreType";
    pub const CLIENT_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.client.https.trustStorePassword";
    pub const CLIENT_HTTPS_CERT_ALIAS: &str = "druid.client.https.certAlias";
    pub const CLIENT_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.client.https.validateHostnames";
    pub const CLIENT_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.client.https.keyManagerPassword";
    // Server side TLS
    pub const SERVER_HTTPS_KEY_STORE_PATH: &str = "druid.server.https.keyStorePath";
    pub const SERVER_HTTPS_KEY_STORE_TYPE: &str = "druid.server.https.keyStoreType";
    pub const SERVER_HTTPS_KEY_STORE_PASSWORD: &str = "druid.server.https.keyStorePassword";
    pub const SERVER_HTTPS_TRUST_STORE_PATH: &str = "druid.server.https.trustStorePath";
    pub const SERVER_HTTPS_TRUST_STORE_TYPE: &str = "druid.server.https.trustStoreType";
    pub const SERVER_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.server.https.trustStorePassword";
    pub const SERVER_HTTPS_CERT_ALIAS: &str = "druid.server.https.certAlias";
    pub const SERVER_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.server.https.validateHostnames";
    pub const SERVER_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.server.https.keyManagerPassword";
    pub const SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE: &str =
        "druid.server.https.requireClientCertificate";
    pub const TLS_ALIAS_NAME: &str = "tls";
    // Misc TLS
    pub const TLS_STORE_PASSWORD: &str = "changeit";
    pub const TLS_STORE_TYPE: &str = "pkcs12";

    // directories
    pub const STACKABLE_MOUNT_TLS_DIR: &str = "/stackable/mount_tls";
    pub const STACKABLE_TLS_DIR: &str = "/stackable/tls";

    pub const TLS_DEFAULT_SECRET_CLASS: &str = "tls";

    pub fn new(
        resolved_authentication_classes: ResolvedAuthenticationClasses,
        server_and_internal_secret_class: Option<String>,
    ) -> Self {
        Self {
            resolved_authentication_classes,
            server_and_internal_secret_class,
        }
    }

    /// Create a `DruidTlsSecurity` struct from the Druid custom resource and resolve
    /// all provided `AuthenticationClass` references.
    pub async fn new_from_druid_cluster(
        client: &Client,
        druid: &DruidCluster,
    ) -> Result<Self, Error> {
        Ok(DruidTlsSecurity {
            resolved_authentication_classes:
                authentication::ResolvedAuthenticationClasses::from_references(
                    client,
                    &druid.spec.cluster_config.authentication,
                )
                .await
                .context(InvalidAuthenticationClassConfigurationSnafu)?,
            server_and_internal_secret_class: druid
                .spec
                .cluster_config
                .tls
                .as_ref()
                .map(|tls| tls.server_and_internal_secret_class.clone())
                .unwrap_or_else(tls::tls_default),
        })
    }

    /// Check if TLS encryption is enabled. This could be due to:
    /// - A provided server `SecretClass`
    /// - A provided client `AuthenticationClass` using tls
    /// This affects init container commands, Druid configuration, volume mounts and
    /// the Druid client port
    pub fn tls_enabled(&self) -> bool {
        // TODO: This must be adapted if other authentication methods are supported and require TLS
        self.tls_client_authentication_class().is_some()
            || self.tls_server_and_internal_secret_class().is_some()
    }

    /// Retrieve an optional TLS secret class for external client -> server and server <-> server communications.
    pub fn tls_server_and_internal_secret_class(&self) -> Option<&str> {
        self.server_and_internal_secret_class.as_deref()
    }

    /// Retrieve an optional TLS `AuthenticationClass`.
    pub fn tls_client_authentication_class(&self) -> Option<&AuthenticationClass> {
        self.resolved_authentication_classes
            .get_tls_authentication_class()
    }

    pub fn container_ports(&self, role: &DruidRole) -> Vec<ContainerPort> {
        self.exposed_ports(role)
            .into_iter()
            .map(|(name, val)| ContainerPort {
                name: Some(name),
                container_port: val.into(),
                protocol: Some("TCP".to_string()),
                ..ContainerPort::default()
            })
            .collect()
    }

    pub fn service_ports(&self, role: &DruidRole) -> Vec<ServicePort> {
        self.exposed_ports(role)
            .into_iter()
            .map(|(name, val)| ServicePort {
                name: Some(name),
                port: val.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            })
            .collect()
    }

    fn exposed_ports(&self, role: &DruidRole) -> Vec<(String, u16)> {
        let mut ports = vec![(Self::METRICS_PORT_NAME.to_string(), METRICS_PORT)];

        if self.tls_enabled() {
            ports.push((Self::TLS_PORT_NAME.to_string(), role.get_https_port()));
        } else {
            ports.push((Self::PLAINTEXT_PORT_NAME.to_string(), role.get_http_port()));
        }

        ports
    }

    /// Adds required tls volume mounts to image and product container builders
    /// Adds required tls volumes to pod builder
    pub fn add_tls_volume_and_volume_mounts(
        &self,
        prepare: &mut ContainerBuilder,
        druid: &mut ContainerBuilder,
        pod: &mut PodBuilder,
    ) -> Result<(), Error> {
        // `ResolvedAuthenticationClasses::validate` already checked that the tls AuthenticationClass
        // uses the same SecretClass as the Druid server itself.
        if let Some(secret_class) = &self.server_and_internal_secret_class {
            pod.add_volume(
                VolumeBuilder::new("tls-mount")
                    .ephemeral(
                        SecretOperatorVolumeSourceBuilder::new(secret_class)
                            .with_pod_scope()
                            .with_node_scope()
                            .build(),
                    )
                    .build(),
            );
            prepare.add_volume_mount("tls-mount", Self::STACKABLE_MOUNT_TLS_DIR);
            druid.add_volume_mount("tls-mount", Self::STACKABLE_MOUNT_TLS_DIR);

            pod.add_volume(
                VolumeBuilder::new("tls")
                    .with_empty_dir(Option::<&str>::None, None)
                    .build(),
            );
            prepare.add_volume_mount("tls", Self::STACKABLE_TLS_DIR);
            druid.add_volume_mount("tls", Self::STACKABLE_TLS_DIR);
        }
        Ok(())
    }

    fn add_tls_port_config_properties(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
        role: &DruidRole,
    ) {
        // no secure communication
        if !self.tls_enabled() {
            config.insert(
                Self::ENABLE_PLAINTEXT_PORT.to_string(),
                Some("true".to_string()),
            );
            config.insert(Self::ENABLE_TLS_PORT.to_string(), Some("false".to_string()));
            config.insert(
                Self::PLAINTEXT_PORT.to_string(),
                Some(role.get_http_port().to_string()),
            );
        }
        // only allow secure communication
        else {
            config.insert(
                Self::ENABLE_PLAINTEXT_PORT.to_string(),
                Some("false".to_string()),
            );
            config.insert(Self::ENABLE_TLS_PORT.to_string(), Some("true".to_string()));
            config.insert(
                Self::TLS_PORT.to_string(),
                Some(role.get_https_port().to_string()),
            );
        }
    }

    /// Add required TLS ports, trust/key store properties
    pub fn add_tls_config_properties(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
        role: &DruidRole,
    ) {
        self.add_tls_port_config_properties(config, role);

        if self.tls_enabled() {
            Self::add_tls_encryption_config_properties(
                config,
                Self::STACKABLE_TLS_DIR,
                Self::TLS_ALIAS_NAME,
            );
        }

        if self
            .resolved_authentication_classes
            .get_tls_authentication_class()
            .is_some()
        {
            Self::add_tls_auth_config_properties(
                config,
                Self::STACKABLE_TLS_DIR,
                Self::TLS_ALIAS_NAME,
            );
        }
    }

    fn add_tls_encryption_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
        // We need a truststore in addition to a keystore here, because server and internal tls
        // can only be enabled/disabled together

        // TODO: Check why we don't check the certificates of other servers
        config.insert(
            Self::CLIENT_HTTPS_TRUST_STORE_PATH.to_string(),
            Some(format!("{}/truststore.p12", store_directory)),
        );
        config.insert(
            Self::CLIENT_HTTPS_TRUST_STORE_TYPE.to_string(),
            Some(Self::TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            Self::CLIENT_HTTPS_TRUST_STORE_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );

        config.insert(
            Self::SERVER_HTTPS_KEY_STORE_PATH.to_string(),
            Some(format!("{}/keystore.p12", store_directory)),
        );
        config.insert(
            Self::SERVER_HTTPS_KEY_STORE_TYPE.to_string(),
            Some(Self::TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            Self::SERVER_HTTPS_KEY_STORE_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );
        config.insert(
            Self::SERVER_HTTPS_CERT_ALIAS.to_string(),
            Some(store_alias.to_string()),
        );
    }

    fn add_tls_auth_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
        config.insert(
            Self::CLIENT_HTTPS_KEY_STORE_PATH.to_string(),
            Some(format!("{store_directory}/keystore.p12")),
        );
        config.insert(
            Self::CLIENT_HTTPS_KEY_STORE_TYPE.to_string(),
            Some(Self::TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            Self::CLIENT_HTTPS_KEY_STORE_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );
        // This is required because PKCS12 does not use any key passwords but it will
        // be checked and would lead to an exception:
        // java.security.UnrecoverableKeyException: Get Key failed: null
        // Must be set to the store password or we get a bad padding exception:
        // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
        config.insert(
            Self::CLIENT_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );
        config.insert(
            Self::CLIENT_HTTPS_CERT_ALIAS.to_string(),
            Some(store_alias.to_string()),
        );
        // This is required because the server will send its pod ip which is not in the SANs of the certificates
        // TODO TEST TEST TEST!
        // Awful!
        config.insert(
            Self::CLIENT_HTTPS_VALIDATE_HOST_NAMES.to_string(),
            Some("false".to_string()),
        );

        // This will enforce the client to authenticate itself
        config.insert(
            Self::SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE.to_string(),
            Some("true".to_string()),
        );

        config.insert(
            Self::SERVER_HTTPS_TRUST_STORE_PATH.to_string(),
            Some(format!("{store_directory}/truststore.p12")),
        );
        config.insert(
            Self::SERVER_HTTPS_TRUST_STORE_TYPE.to_string(),
            Some(Self::TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            Self::SERVER_HTTPS_TRUST_STORE_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );
        // This is required because PKCS12 does not use any key passwords but it will
        // be checked and would lead to an exception:
        // java.security.UnrecoverableKeyException: Get Key failed: null
        // Must be set to the store password or we get a bad padding exception:
        // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
        config.insert(
            Self::SERVER_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
            Some(Self::TLS_STORE_PASSWORD.to_string()),
        );
        // This is required because the client will send its pod ip which is not in the SANs of the certificates
        // TODO TEST TEST TEST!
        // Awful!
        config.insert(
            Self::SERVER_HTTPS_VALIDATE_HOST_NAMES.to_string(),
            Some("false".to_string()),
        );
    }

    pub fn build_tls_key_stores_cmd(&self) -> Vec<String> {
        let mut command = vec![];
        if self.tls_enabled() {
            command.extend(add_cert_to_trust_store_cmd(
                Self::STACKABLE_MOUNT_TLS_DIR,
                Self::STACKABLE_TLS_DIR,
                Self::TLS_ALIAS_NAME,
                Self::TLS_STORE_PASSWORD,
            ));
            command.extend(add_key_pair_to_key_store_cmd(
                Self::STACKABLE_MOUNT_TLS_DIR,
                Self::STACKABLE_TLS_DIR,
                Self::TLS_ALIAS_NAME,
                Self::TLS_STORE_PASSWORD,
            ));
        }
        command
    }

    pub fn get_tcp_socket_probe(
        &self,
        initial_delay_seconds: i32,
        period_seconds: i32,
        failure_threshold: i32,
        timeout_seconds: i32,
    ) -> Probe {
        let port = if self.tls_enabled() {
            IntOrString::String(Self::TLS_PORT_NAME.to_string())
        } else {
            IntOrString::String(Self::PLAINTEXT_PORT_NAME.to_string())
        };

        Probe {
            tcp_socket: Some(TCPSocketAction {
                port,
                ..Default::default()
            }),
            initial_delay_seconds: Some(initial_delay_seconds),
            period_seconds: Some(period_seconds),
            failure_threshold: Some(failure_threshold),
            timeout_seconds: Some(timeout_seconds),
            ..Default::default()
        }
    }
}

/// Generate a script to add a CA to a truststore
pub fn add_cert_to_trust_store_cmd(
    cert_directory: &str,
    trust_store_directory: &str,
    alias_name: &str,
    store_password: &str,
) -> Vec<String> {
    let mut command = vec![];
    command.push(format!(
        "echo Cleaning up truststore [{trust_store_directory}/truststore.p12] - just in case"
    ));
    command.push(format!("rm -f {trust_store_directory}/truststore.p12"));
    command.push(format!(
        "echo Creating truststore [{trust_store_directory}/truststore.p12]"
    ));
    command.push(format!("keytool -importcert -file {cert_directory}/ca.crt -keystore {trust_store_directory}/truststore.p12 -storetype pkcs12 -alias {alias_name} -storepass {store_password} -noprompt"));

    command
}

/// Generate a script to create a certificate chain and add a key-cert pair to the keystore
pub fn add_key_pair_to_key_store_cmd(
    cert_directory: &str,
    key_store_directory: &str,
    alias_name: &str,
    store_password: &str,
) -> Vec<String> {
    vec![
        format!("echo Creating certificate chain [{key_store_directory}/chain.crt]"),
        format!("cat {cert_directory}/ca.crt {cert_directory}/tls.crt > {key_store_directory}/chain.crt"),
        format!("echo Creating keystore [{key_store_directory}/keystore.p12]"),
        format!("openssl pkcs12 -export -in {key_store_directory}/chain.crt -inkey {cert_directory}/tls.key -out {key_store_directory}/keystore.p12 --passout pass:{store_password} -name {alias_name}"),
    ]
}
