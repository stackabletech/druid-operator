use crate::{DruidRole, METRICS_PORT};

use serde::{Deserialize, Serialize};
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
    k8s_openapi::{
        api::core::v1::{ContainerPort, Probe, ServicePort, TCPSocketAction, Volume},
        apimachinery::pkg::util::intstr::IntOrString,
    },
    schemars::{self, JsonSchema},
};
use std::collections::BTreeMap;

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
// Server side TLS
pub const SERVER_HTTPS_KEY_STORE_PATH: &str = "druid.server.https.keyStorePath";
pub const SERVER_HTTPS_KEY_STORE_TYPE: &str = "druid.server.https.keyStoreType";
pub const SERVER_HTTPS_KEY_STORE_PASSWORD: &str = "druid.server.https.keyStorePassword";
pub const SERVER_HTTPS_TRUST_STORE_PATH: &str = "druid.server.https.trustStorePath";
pub const SERVER_HTTPS_TRUST_STORE_TYPE: &str = "druid.server.https.trustStoreType";
pub const SERVER_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.server.https.trustStorePassword";
pub const SERVER_HTTPS_CERT_ALIAS: &str = "druid.server.https.certAlias";
// directories
pub const STACKABLE_SERVER_TLS_DIR: &str = "/stackable/server_tls";
pub const STACKABLE_INTERNAL_TLS_DIR: &str = "/stackable/internal_tls";
pub const STACKABLE_MOUNT_SERVER_TLS_DIR: &str = "/stackable/mount_server_tls";
pub const STACKABLE_MOUNT_INTERNAL_TLS_DIR: &str = "/stackable/mount_internal_tls";

const DEFAULT_TLS_SECRET_CLASS: &str = "tls";
const SIMPLE_CLIENT_SSL_CONTEXT: &str = "simple-client-sslcontext";
const TLS_STORE_ALIAS_NAME: &str = "druid";
const TLS_STORE_PASSWORD: &str = "changeit";

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTls {
    /// Only affects client connections.
    /// This setting controls:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the client
    #[serde(
        default = "DruidTlsSecretClass::default_secret_class",
        skip_serializing_if = "Option::is_none"
    )]
    pub server: Option<DruidTlsSecretClass>,
    /// Only affects internal communication. Use mutual verification between Druid nodes
    /// This setting controls:
    /// - Which cert the servers should use to authenticate themselves against other servers
    /// - Which ca.crt to use when validating the other server
    #[serde(
        default = "DruidTlsSecretClass::default_secret_class",
        skip_serializing_if = "Option::is_none"
    )]
    pub internal: Option<DruidTlsSecretClass>,
}

impl DruidTls {
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

        match (self.server.is_some(), self.server.is_some()) {
            // only plaintext
            (false, false) => ports.push((PLAINTEXT_PORT_NAME.to_string(), role.get_http_port())),
            // plaintext and tls
            (true, false) | (false, true) => {
                ports.push((PLAINTEXT_PORT_NAME.to_string(), role.get_http_port()));
                ports.push((TLS_PORT_NAME.to_string(), role.get_https_port()));
            }
            // only tls
            (true, true) => ports.push((TLS_PORT_NAME.to_string(), role.get_https_port())),
        }

        ports
    }

    pub fn get_probe(&self) -> Probe {
        let port = if self.server.is_some() || self.internal.is_some() {
            IntOrString::String(TLS_PORT_NAME.to_string())
        } else {
            IntOrString::String(PLAINTEXT_PORT_NAME.to_string())
        };

        Probe {
            tcp_socket: Some(TCPSocketAction {
                port,
                ..Default::default()
            }),
            initial_delay_seconds: Some(30),
            period_seconds: Some(5),
            ..Default::default()
        }
    }

    /// Adds required tls volume mounts to image and product container builders
    /// Adds required tls volumes to pod builder
    pub fn add_tls_volume_and_volume_mounts(
        &self,
        prepare: &mut ContainerBuilder,
        druid: &mut ContainerBuilder,
        pod: &mut PodBuilder,
    ) {
        if let Some(server_tls) = &self.server {
            prepare.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
            druid.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
            pod.add_volume(Self::create_tls_volume("server-tls-mount", server_tls));

            prepare.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
            druid.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
            pod.add_volume(
                VolumeBuilder::new("server-tls")
                    .with_empty_dir(Some(""), None)
                    .build(),
            );
        }

        if let Some(internal_tls) = &self.internal {
            prepare.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
            druid.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
            pod.add_volume(Self::create_tls_volume("internal-tls-mount", internal_tls));

            prepare.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
            druid.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
            pod.add_volume(
                VolumeBuilder::new("internal-tls")
                    .with_empty_dir(Some(""), None)
                    .build(),
            );
        }
    }

    /// Add required TLS extensions
    pub fn add_tls_extensions(&self, extensions: &mut Vec<String>) {
        if self.server.is_some() || self.internal.is_some() {
            extensions.push(SIMPLE_CLIENT_SSL_CONTEXT.to_string());
        }
    }

    /// Add required TLS ports, trust/key store properties
    pub fn add_common_config_properties(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
        role: &DruidRole,
    ) {
        // no secure communication
        if self.server.is_none() && self.internal.is_none() {
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("true".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("false".to_string()));
            config.insert(
                PLAINTEXT_PORT.to_string(),
                Some(role.get_http_port().to_string()),
            );
        }
        // only secure communication
        else if self.server.is_some() && self.internal.is_some() {
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("false".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("true".to_string()));
            config.insert(
                TLS_PORT.to_string(),
                Some(role.get_https_port().to_string()),
            );
        }
        // secure and insecure communications
        else {
            config.insert(ENABLE_PLAINTEXT_PORT.to_string(), Some("true".to_string()));
            config.insert(ENABLE_TLS_PORT.to_string(), Some("true".to_string()));
            config.insert(
                PLAINTEXT_PORT.to_string(),
                Some(role.get_http_port().to_string()),
            );
            config.insert(
                TLS_PORT.to_string(),
                Some(role.get_https_port().to_string()),
            );
        }

        if self.server.is_some() {
            config.insert(
                SERVER_HTTPS_TRUST_STORE_PATH.to_string(),
                Some(format!("{}/truststore.p12", STACKABLE_SERVER_TLS_DIR)),
            );
            config.insert(
                SERVER_HTTPS_TRUST_STORE_TYPE.to_string(),
                Some("pkcs12".to_string()),
            );
            config.insert(
                SERVER_HTTPS_TRUST_STORE_PASSWORD.to_string(),
                Some(TLS_STORE_PASSWORD.to_string()),
            );
            config.insert(
                SERVER_HTTPS_CERT_ALIAS.to_string(),
                Some(TLS_STORE_ALIAS_NAME.to_string()),
            );
            // not working
            // config.insert(
            //     CLIENT_HTTPS_KEY_STORE_PATH.to_string(),
            //     Some(format!("{}/keystore.p12", STACKABLE_SERVER_TLS_DIR)),
            // );
            // config.insert(
            //     CLIENT_HTTPS_KEY_STORE_TYPE.to_string(),
            //     Some("pkcs12".to_string()),
            // );
            // config.insert(
            //     CLIENT_HTTPS_KEY_STORE_PASSWORD.to_string(),
            //     Some(TLS_STORE_PASSWORD.to_string()),
            // );
        }

        if self.internal.is_some() {
            // client truststore for internal communication
            config.insert(
                CLIENT_HTTPS_TRUST_STORE_PATH.to_string(),
                Some(format!("{}/truststore.p12", STACKABLE_INTERNAL_TLS_DIR)),
            );
            config.insert(
                CLIENT_HTTPS_TRUST_STORE_TYPE.to_string(),
                Some("pkcs12".to_string()),
            );
            config.insert(
                CLIENT_HTTPS_TRUST_STORE_PASSWORD.to_string(),
                Some(TLS_STORE_PASSWORD.to_string()),
            );
            config.insert(
                CLIENT_HTTPS_CERT_ALIAS.to_string(),
                Some(TLS_STORE_ALIAS_NAME.to_string()),
            );
            // server keystore for internal communication
            config.insert(
                SERVER_HTTPS_KEY_STORE_PATH.to_string(),
                Some(format!("{}/keystore.p12", STACKABLE_INTERNAL_TLS_DIR)),
            );
            config.insert(
                SERVER_HTTPS_KEY_STORE_TYPE.to_string(),
                Some("pkcs12".to_string()),
            );
            config.insert(
                SERVER_HTTPS_KEY_STORE_PASSWORD.to_string(),
                Some(TLS_STORE_PASSWORD.to_string()),
            );
        }
    }

    pub fn build_tls_stores_cmd(&self) -> Vec<String> {
        let mut command = vec![];
        if self.server.is_some() {
            command.extend(Self::create_key_and_trust_store(
                STACKABLE_MOUNT_SERVER_TLS_DIR,
                STACKABLE_SERVER_TLS_DIR,
                TLS_STORE_ALIAS_NAME,
                TLS_STORE_PASSWORD,
            ));
            command.extend(Self::chown_and_chmod(STACKABLE_SERVER_TLS_DIR));
        }

        if self.internal.is_some() {
            command.extend(Self::create_key_and_trust_store(
                STACKABLE_MOUNT_INTERNAL_TLS_DIR,
                STACKABLE_INTERNAL_TLS_DIR,
                TLS_STORE_ALIAS_NAME,
                TLS_STORE_PASSWORD,
            ));
            command.extend(Self::chown_and_chmod(STACKABLE_INTERNAL_TLS_DIR));
        }

        command
    }

    /// Generates the shell script to create key and trust stores from the certificates provided
    /// by the secret operator.
    fn create_key_and_trust_store(
        cert_directory: &str,
        stackable_cert_directory: &str,
        alias_name: &str,
        store_password: &str,
    ) -> Vec<String> {
        vec![
            format!("echo [{stackable_cert_directory}] Cleaning up truststore - just in case"),
            format!("rm -f {stackable_cert_directory}/truststore.p12"),
            format!("echo [{stackable_cert_directory}] Creating truststore"),
            format!("keytool -importcert -file {cert_directory}/ca.crt -keystore {stackable_cert_directory}/truststore.p12 -storetype pkcs12 -noprompt -alias {alias_name} -storepass {store_password}"),
            format!("echo [{stackable_cert_directory}] Creating certificate chain"),
            format!("cat {cert_directory}/ca.crt {cert_directory}/tls.crt > {stackable_cert_directory}/chain.crt"),
            format!("echo [{stackable_cert_directory}] Creating keystore"),
            format!("openssl pkcs12 -export -in {stackable_cert_directory}/chain.crt -inkey {cert_directory}/tls.key -out {stackable_cert_directory}/keystore.p12 --passout pass:{store_password}")
        ]
    }

    /// Generates a shell script to chown and chmod the provided directory.
    fn chown_and_chmod(directory: &str) -> Vec<String> {
        vec![
            format!("echo chown and chmod {dir}", dir = directory),
            format!("chown -R stackable:stackable {dir}", dir = directory),
            format!("chmod -R a=,u=rwX {dir}", dir = directory),
        ]
    }

    fn create_tls_volume(volume_name: &str, tls_secret_class: &DruidTlsSecretClass) -> Volume {
        VolumeBuilder::new(volume_name)
            .ephemeral(
                SecretOperatorVolumeSourceBuilder::new(&tls_secret_class.secret_class)
                    .with_pod_scope()
                    .with_node_scope()
                    .build(),
            )
            .build()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTlsSecretClass {
    pub secret_class: String,
}

impl DruidTlsSecretClass {
    fn default_secret_class() -> Option<DruidTlsSecretClass> {
        Some(DruidTlsSecretClass {
            secret_class: DEFAULT_TLS_SECRET_CLASS.to_string(),
        })
    }
}
