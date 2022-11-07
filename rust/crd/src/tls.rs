use crate::authentication::DruidAuthenticationConfig;
use crate::{DruidRole, METRICS_PORT};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
    k8s_openapi::{
        api::core::v1::{ContainerPort, Probe, ServicePort, TCPSocketAction, Volume},
        apimachinery::pkg::util::intstr::IntOrString,
    },
    schemars::{self, JsonSchema},
};
use std::collections::BTreeMap;
use strum::{EnumDiscriminants, IntoStaticStr};

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

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("The provided TLS configuration is invalid: {reason}"))]
    InvalidTlsConfiguration { reason: String },
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTls {
    /// Only affects client connections.
    /// This setting controls:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the client
    /// Important: This will activate encrypted internal druid communication as well!
    // TODO: Separating internal and server TLS is currently not possible. Internal communication
    //   happens via the HTTPS port. Even if both HTTPS and HTTP port are enabled, Druid clients
    //   will default to using TLS.
    pub secret_class: String,
}

/// This is a struct to bundle TLS encryption and TLS authentication. Helper methods contain:
/// - Which config properties must be set
/// - Which extension should be loaded
/// - Which volume and volume mounts to be set
/// - Which container and service ports to be set
/// - Which init container commands to be set
/// - Which probes to be set
pub struct DruidTlsSettings {
    pub encryption: Option<DruidTls>,
    pub authentication: Option<DruidAuthenticationConfig>,
}

impl DruidTlsSettings {
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

        if self.encryption.is_none() && self.authentication.is_none() {
            ports.push((PLAINTEXT_PORT_NAME.to_string(), role.get_http_port()));
        } else {
            ports.push((TLS_PORT_NAME.to_string(), role.get_https_port()));
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
        let secret_class = if let Some(DruidAuthenticationConfig::Tls(provider)) =
            &self.authentication
        {
            // If client_cert_secret_class authentication is set use it for our tls volume mounts
            if provider.client_cert_secret_class.is_some() {
                provider.client_cert_secret_class.as_ref()
            }
            // If the client_cert_secret_class is not set, we require to have a TLS encryption secret class set
            else if let Some(tls) = &self.encryption {
                Some(&tls.secret_class)
            }
            // This is a bad configuration (TLS auth required, but certificates are neither provided in the AuthenticationClass nor in the TLS encryption SecretClass
            else {
                return Err(Error::InvalidTlsConfiguration {
                    reason: "TLS client authentication is required but no certificates are provided in the \
                             `spec.cluster_config.authentication.tls.authenticationClass` \
                             or in the `spec.cluster_config.tls.secretClass` encryption settings".to_string()
                });
            }
        } else {
            self.encryption.as_ref().map(|tls| &tls.secret_class)
        };

        if let Some(secret_class) = secret_class {
            prepare.add_volume_mount("tls-mount", STACKABLE_MOUNT_TLS_DIR);
            druid.add_volume_mount("tls-mount", STACKABLE_MOUNT_TLS_DIR);
            pod.add_volume(create_tls_volume("tls-mount", secret_class));

            prepare.add_volume_mount("tls", STACKABLE_TLS_DIR);
            druid.add_volume_mount("tls", STACKABLE_TLS_DIR);
            pod.add_volume(
                VolumeBuilder::new("tls")
                    .with_empty_dir(Some(""), None)
                    .build(),
            );
        }

        Ok(())
    }

    fn add_tls_port_config_properties(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
        role: &DruidRole,
    ) {
        // no secure communication
        if self.encryption.is_none() && self.authentication.is_none() {
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("true".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("false".to_string()));
            config.insert(
                PLAINTEXT_PORT.to_string(),
                Some(role.get_http_port().to_string()),
            );
        }
        // only secure communication
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
        if self.encryption.is_some() || self.authentication.is_some() {
            self.add_tls_port_config_properties(config, role);
            Self::add_tls_encryption_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
        }

        if self.authentication.is_some() {
            Self::add_tls_auth_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
        }
    }

    fn add_tls_encryption_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
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
    }

    fn add_tls_auth_config_properties(
        config: &mut BTreeMap<String, Option<String>>,
        store_directory: &str,
        store_alias: &str,
    ) {
        config.insert(
            CLIENT_HTTPS_KEY_STORE_PATH.to_string(),
            Some(format!("{}/keystore.p12", store_directory)),
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
            Some(format!("{}/truststore.p12", store_directory)),
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
        // This is required because the client will send its pod ip which is not in the SANs of the certificates
        config.insert(
            SERVER_HTTPS_VALIDATE_HOST_NAMES.to_string(),
            Some("false".to_string()),
        );
    }

    pub fn build_tls_key_stores_cmd(&self) -> Vec<String> {
        let mut command = vec![];
        if self.encryption.is_some() || self.authentication.is_some() {
            command.extend(add_cert_to_trust_store_cmd(
                STACKABLE_MOUNT_TLS_DIR,
                STACKABLE_TLS_DIR,
                TLS_ALIAS_NAME,
                TLS_STORE_PASSWORD,
            ));
            command.extend(add_key_pair_to_key_store_cmd(
                STACKABLE_MOUNT_TLS_DIR,
                STACKABLE_TLS_DIR,
                TLS_ALIAS_NAME,
                TLS_STORE_PASSWORD,
            ));
            command.extend(chown_and_chmod(STACKABLE_TLS_DIR));
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
        let port = if self.encryption.is_some() || self.authentication.is_some() {
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

/// Generates a shell script to chown and chmod the provided directory.
pub fn chown_and_chmod(directory: &str) -> Vec<String> {
    vec![
        format!("echo chown and chmod {dir}", dir = directory),
        format!("chown -R stackable:stackable {dir}", dir = directory),
        format!("chmod -R a=,u=rwX {dir}", dir = directory),
    ]
}

/// Create an ephemeral TLS volume
pub fn create_tls_volume(volume_name: &str, tls_secret_class: &str) -> Volume {
    VolumeBuilder::new(volume_name)
        .ephemeral(
            SecretOperatorVolumeSourceBuilder::new(tls_secret_class)
                .with_pod_scope()
                .with_node_scope()
                .build(),
        )
        .build()
}
