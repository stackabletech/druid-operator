use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        pod::{
            container::ContainerBuilder,
            volume::{
                SecretFormat, SecretOperatorVolumeSourceBuilder,
                SecretOperatorVolumeSourceBuilderError, VolumeBuilder,
            },
            PodBuilder,
        },
    },
    k8s_openapi::{
        api::core::v1::{ContainerPort, Probe, ServicePort, TCPSocketAction},
        apimachinery::pkg::util::intstr::IntOrString,
    },
    time::Duration,
};

use crate::{
    authentication::{self, AuthenticationClassesResolved},
    DruidCluster, DruidRole, METRICS_PORT, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to process authentication class"))]
    InvalidAuthenticationClassConfiguration { source: authentication::Error },

    #[snafu(display("failed to build the Secret operator Volume"))]
    SecretVolumeBuild {
        source: SecretOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },
}

/// Helper struct combining TLS settings for server and internal tls with the resolved AuthenticationClasses
pub struct DruidTlsSecurity {
    auth_classes: AuthenticationClassesResolved,
    server_and_internal_secret_class: Option<String>,
}

// Ports
const ENABLE_PLAINTEXT_PORT: &str = "druid.enablePlaintextPort";
const PLAINTEXT_PORT: &str = "druid.plaintextPort";
const ENABLE_TLS_PORT: &str = "druid.enableTlsPort";
const TLS_PORT: &str = "druid.tlsPort";
// Port names
const PLAINTEXT_PORT_NAME: &str = "http";
const TLS_PORT_NAME: &str = "https";
const METRICS_PORT_NAME: &str = "metrics";
// Client side (Druid) TLS
const CLIENT_HTTPS_KEY_STORE_PATH: &str = "druid.client.https.keyStorePath";
const CLIENT_HTTPS_KEY_STORE_TYPE: &str = "druid.client.https.keyStoreType";
const CLIENT_HTTPS_KEY_STORE_PASSWORD: &str = "druid.client.https.keyStorePassword";
const CLIENT_HTTPS_TRUST_STORE_PATH: &str = "druid.client.https.trustStorePath";
const CLIENT_HTTPS_TRUST_STORE_TYPE: &str = "druid.client.https.trustStoreType";
const CLIENT_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.client.https.trustStorePassword";
const CLIENT_HTTPS_CERT_ALIAS: &str = "druid.client.https.certAlias";
const CLIENT_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.client.https.validateHostnames";
const CLIENT_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.client.https.keyManagerPassword";
// Server side TLS
const SERVER_HTTPS_KEY_STORE_PATH: &str = "druid.server.https.keyStorePath";
const SERVER_HTTPS_KEY_STORE_TYPE: &str = "druid.server.https.keyStoreType";
const SERVER_HTTPS_KEY_STORE_PASSWORD: &str = "druid.server.https.keyStorePassword";
const SERVER_HTTPS_TRUST_STORE_PATH: &str = "druid.server.https.trustStorePath";
const SERVER_HTTPS_TRUST_STORE_TYPE: &str = "druid.server.https.trustStoreType";
const SERVER_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.server.https.trustStorePassword";
const SERVER_HTTPS_CERT_ALIAS: &str = "druid.server.https.certAlias";
const SERVER_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.server.https.validateHostnames";
const SERVER_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.server.https.keyManagerPassword";
const SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE: &str = "druid.server.https.requireClientCertificate";
const TLS_ALIAS_NAME: &str = "tls";
pub const AUTH_TRUST_STORE_PATH: &str = "druid.auth.basic.ssl.trustStorePath";
pub const AUTH_TRUST_STORE_TYPE: &str = "druid.auth.basic.ssl.trustStoreType";
pub const AUTH_TRUST_STORE_PASSWORD: &str = "druid.auth.basic.ssl.trustStorePassword";
// Misc TLS
pub const TLS_STORE_PASSWORD: &str = "changeit";
pub const TLS_STORE_TYPE: &str = "pkcs12";
const SYSTEM_TRUST_STORE: &str = "/etc/pki/java/cacerts";
const SYSTEM_TRUST_STORE_PASSWORD: &str = "changeit";

// directories
const STACKABLE_MOUNT_TLS_DIR: &str = "/stackable/mount_tls";
pub const STACKABLE_TLS_DIR: &str = "/stackable/tls";

// volume names
const TLS_VOLUME_NAME: &str = "tls";
const TLS_MOUNT_VOLUME_NAME: &str = "tls-mount";

pub const INTERNAL_INITIAL_CLIENT_PASSWORD_ENV: &str = "INTERNAL_INITIAL_CLIENT_PASSWORD";
// It seems this needs to be the same password for Druid to work, so we re-use the existing env variable from above.
pub const ESCALATOR_INTERNAL_CLIENT_PASSWORD_ENV: &str = INTERNAL_INITIAL_CLIENT_PASSWORD_ENV;

impl DruidTlsSecurity {
    pub fn new(
        auth_classes: &AuthenticationClassesResolved,
        server_and_internal_secret_class: Option<String>,
    ) -> Self {
        Self {
            auth_classes: auth_classes.clone(),
            server_and_internal_secret_class,
        }
    }

    /// Create a `DruidTlsSecurity` struct from the Druid custom resource and resolve
    /// all provided `AuthenticationClass` references.
    pub fn new_from_druid_cluster(
        druid: &DruidCluster,
        auth_classes: &AuthenticationClassesResolved,
    ) -> Self {
        DruidTlsSecurity {
            auth_classes: auth_classes.clone(),
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
    /// and the Druid client port
    pub fn tls_enabled(&self) -> bool {
        // TODO: This must be adapted if other authentication methods are supported and require TLS
        self.auth_classes.tls_authentication_enabled()
            || self.tls_server_and_internal_secret_class().is_some()
    }

    /// Retrieve an optional TLS secret class for external client -> server and server <-> server communications.
    pub fn tls_server_and_internal_secret_class(&self) -> Option<&str> {
        self.server_and_internal_secret_class.as_deref()
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
        let mut ports = vec![(METRICS_PORT_NAME.to_string(), METRICS_PORT)];

        if self.tls_enabled() {
            ports.push((TLS_PORT_NAME.to_string(), role.get_https_port()));
        } else {
            ports.push((PLAINTEXT_PORT_NAME.to_string(), role.get_http_port()));
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
        requested_secret_lifetime: &Duration,
    ) -> Result<(), Error> {
        // `ResolvedAuthenticationClasses::validate` already checked that the tls AuthenticationClass
        // uses the same SecretClass as the Druid server itself.
        if let Some(secret_class) = &self.server_and_internal_secret_class {
            pod.add_volume(
                VolumeBuilder::new(TLS_MOUNT_VOLUME_NAME)
                    .ephemeral(
                        SecretOperatorVolumeSourceBuilder::new(secret_class)
                            .with_pod_scope()
                            .with_node_scope()
                            .with_format(SecretFormat::TlsPkcs12)
                            .with_tls_pkcs12_password(TLS_STORE_PASSWORD)
                            .with_auto_tls_cert_lifetime(*requested_secret_lifetime)
                            .build()
                            .context(SecretVolumeBuildSnafu)?,
                    )
                    .build(),
            )
            .context(AddVolumeSnafu)?;
            prepare
                .add_volume_mount(TLS_MOUNT_VOLUME_NAME, STACKABLE_MOUNT_TLS_DIR)
                .context(AddVolumeMountSnafu)?;
            druid
                .add_volume_mount(TLS_MOUNT_VOLUME_NAME, STACKABLE_MOUNT_TLS_DIR)
                .context(AddVolumeMountSnafu)?;

            pod.add_volume(
                VolumeBuilder::new(TLS_VOLUME_NAME)
                    .with_empty_dir(Option::<&str>::None, None)
                    .build(),
            )
            .context(AddVolumeSnafu)?;

            prepare
                .add_volume_mount(TLS_VOLUME_NAME, STACKABLE_TLS_DIR)
                .context(AddVolumeMountSnafu)?;
            druid
                .add_volume_mount(TLS_VOLUME_NAME, STACKABLE_TLS_DIR)
                .context(AddVolumeMountSnafu)?;
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
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("true".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("false".to_string()));
            config.insert(
                PLAINTEXT_PORT.to_string(),
                Some(role.get_http_port().to_string()),
            );
        }
        // only allow secure communication
        else {
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("false".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("true".to_string()));
            config.insert(
                TLS_PORT.to_string(),
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
            Self::add_tls_encryption_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
        }

        if self.auth_classes.tls_authentication_enabled() {
            Self::add_tls_auth_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
        }
    }

    fn add_tls_encryption_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
        // We need a truststore in addition to a keystore here, because server and internal tls
        // can only be enabled/disabled together
        config.insert(
            CLIENT_HTTPS_TRUST_STORE_PATH.to_string(),
            Some(format!("{}/truststore.p12", store_directory)),
        );
        config.insert(
            CLIENT_HTTPS_TRUST_STORE_TYPE.to_string(),
            Some(TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            CLIENT_HTTPS_TRUST_STORE_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );

        config.insert(
            SERVER_HTTPS_KEY_STORE_PATH.to_string(),
            Some(format!("{}/keystore.p12", store_directory)),
        );
        config.insert(
            SERVER_HTTPS_KEY_STORE_TYPE.to_string(),
            Some(TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            SERVER_HTTPS_KEY_STORE_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
        config.insert(
            SERVER_HTTPS_CERT_ALIAS.to_string(),
            Some(store_alias.to_string()),
        );

        // We also need to configure the truststore for authentication related stuff,
        // such as verifying the LDAP server
        config.insert(
            AUTH_TRUST_STORE_PATH.to_string(),
            Some(format!("{}/truststore.p12", store_directory)),
        );
        config.insert(
            AUTH_TRUST_STORE_TYPE.to_string(),
            Some(TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            AUTH_TRUST_STORE_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
    }

    fn add_tls_auth_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
        config.insert(
            CLIENT_HTTPS_KEY_STORE_PATH.to_string(),
            Some(format!("{store_directory}/keystore.p12")),
        );
        config.insert(
            CLIENT_HTTPS_KEY_STORE_TYPE.to_string(),
            Some(TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            CLIENT_HTTPS_KEY_STORE_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
        // This is required because PKCS12 does not use any key passwords but it will
        // be checked and would lead to an exception:
        // java.security.UnrecoverableKeyException: Get Key failed: null
        // Must be set to the store password or we get a bad padding exception:
        // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
        config.insert(
            CLIENT_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
        config.insert(
            CLIENT_HTTPS_CERT_ALIAS.to_string(),
            Some(store_alias.to_string()),
        );
        // FIXME: https://github.com/stackabletech/druid-operator/issues/372
        // This is required because the server will send its pod ip which is not in the SANs of the certificates
        config.insert(
            CLIENT_HTTPS_VALIDATE_HOST_NAMES.to_string(),
            Some("false".to_string()),
        );

        // This will enforce the client to authenticate itself
        config.insert(
            SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE.to_string(),
            Some("true".to_string()),
        );

        config.insert(
            SERVER_HTTPS_TRUST_STORE_PATH.to_string(),
            Some(format!("{store_directory}/truststore.p12")),
        );
        config.insert(
            SERVER_HTTPS_TRUST_STORE_TYPE.to_string(),
            Some(TLS_STORE_TYPE.to_string()),
        );
        config.insert(
            SERVER_HTTPS_TRUST_STORE_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
        // This is required because PKCS12 does not use any key passwords but it will
        // be checked and would lead to an exception:
        // java.security.UnrecoverableKeyException: Get Key failed: null
        // Must be set to the store password or we get a bad padding exception:
        // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
        config.insert(
            SERVER_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
            Some(TLS_STORE_PASSWORD.to_string()),
        );
        // FIXME: https://github.com/stackabletech/druid-operator/issues/372
        // This is required because the client will send its pod ip which is not in the SANs of the certificates
        config.insert(
            SERVER_HTTPS_VALIDATE_HOST_NAMES.to_string(),
            Some("false".to_string()),
        );
    }

    pub fn build_tls_key_stores_cmd(&self) -> Vec<String> {
        if !self.tls_enabled() {
            return vec![];
        }

        vec![
            // Copy system truststore to empty dir and convert to PKCS12
            import_system_truststore(STACKABLE_TLS_DIR),
            // Import secret-op truststore to copied system trust store
            import_truststore(STACKABLE_MOUNT_TLS_DIR, STACKABLE_TLS_DIR),
            // Import / Copy secret-op keystore to empty dir and set required alias
            import_keystore(STACKABLE_MOUNT_TLS_DIR, STACKABLE_TLS_DIR),
        ]
    }

    pub fn get_tcp_socket_probe(
        &self,
        initial_delay_seconds: i32,
        period_seconds: i32,
        failure_threshold: i32,
        timeout_seconds: i32,
    ) -> Probe {
        let port = if self.tls_enabled() {
            IntOrString::String(TLS_PORT_NAME.to_string())
        } else {
            IntOrString::String(PLAINTEXT_PORT_NAME.to_string())
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
    cert: &str,
    trust_store_directory: &str,
    alias_name: &str,
    store_password: &str,
) -> String {
    format!("keytool -importcert -file {cert} -keystore {trust_store_directory}/truststore.p12 -storetype pkcs12 -alias {alias_name} -storepass {store_password} -noprompt")
}

pub fn add_cert_to_jvm_trust_store_cmd(cert: &str, alias_name: &str) -> String {
    format!("keytool -importcert -file {cert} -keystore {STACKABLE_TRUST_STORE} -storetype pkcs12 -alias {alias_name} -storepass {STACKABLE_TRUST_STORE_PASSWORD} -noprompt")
}

/// Import the system truststore to a truststore named `truststore.p12` in `destination_directory`.
fn import_system_truststore(destination_directory: &str) -> String {
    let dest_truststore_path = format!("{destination_directory}/truststore.p12");
    format!("keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {dest_truststore_path} -deststoretype pkcs12 -deststorepass {TLS_STORE_PASSWORD} -noprompt")
}

/// Generates the shell script to import a secret operator provided truststore without password
/// into a new truststore with password in a writeable empty dir
///
/// # Arguments
/// - `source_directory`      - The directory of the source truststore.
///                             Should usually be a secret operator volume mount.
/// - `destination_directory` - The directory of the destination truststore.
///                             Should usually be an empty dir.
fn import_truststore(source_directory: &str, destination_directory: &str) -> String {
    let source_truststore_path = format!("{source_directory}/truststore.p12");
    let dest_truststore_path = format!("{destination_directory}/truststore.p12");
    // The source directory is a secret-op mount and we do not want to write / add anything in there
    // Therefore we import all the contents to a truststore in "writeable" empty dirs.
    // Keytool is only barking if a password is not set for the destination truststore (which we set)
    // and do provide an empty password for the source truststore coming from the secret-operator.
    // Using no password will result in a warning.
    // All secret-op generated truststores have one entry with alias "1". We generate a UUID for
    // the destination truststore to avoid conflicts when importing multiple secret-op generated
    // truststores. We do not use the UUID rust crate since this will continuously change the STS... and
    // leads to never-ending reconciles.
    format!("keytool -importkeystore -srckeystore {source_truststore_path} -srcstoretype PKCS12 -srcstorepass {TLS_STORE_PASSWORD} -srcalias 1 -destkeystore {dest_truststore_path} -deststoretype PKCS12 -deststorepass {TLS_STORE_PASSWORD} -destalias $(cat /proc/sys/kernel/random/uuid) -noprompt")
}

/// Generate a script to import a mounted keystore to an empty dir and set an alias
fn import_keystore(source_directory: &str, destination_directory: &str) -> String {
    let source_keystore_path = format!("{source_directory}/keystore.p12");
    let dest_keystore_path = format!("{destination_directory}/keystore.p12");
    // The source directory is a secret-op mount and we do not want to write / add anything in there
    // Therefore we import all the contents to a keystore in "writeable" empty dirs.
    // Using no password will result in a warning.
    // All secret-op generated keystores have one entry with alias "1".
    format!("keytool -importkeystore -srckeystore {source_keystore_path} -srcstoretype PKCS12 -srcstorepass {TLS_STORE_PASSWORD} -srcalias 1 -destkeystore {dest_keystore_path} -deststoretype PKCS12 -deststorepass {TLS_STORE_PASSWORD} -destalias {TLS_ALIAS_NAME} -noprompt")
}
