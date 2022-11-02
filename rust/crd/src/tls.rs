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
pub const CLIENT_HTTPS_CERT_ALIAS_NAME: &str = "client";
// Server side TLS
pub const SERVER_HTTPS_KEY_STORE_PATH: &str = "druid.server.https.keyStorePath";
pub const SERVER_HTTPS_KEY_STORE_TYPE: &str = "druid.server.https.keyStoreType";
pub const SERVER_HTTPS_KEY_STORE_PASSWORD: &str = "druid.server.https.keyStorePassword";
pub const SERVER_HTTPS_TRUST_STORE_PATH: &str = "druid.server.https.trustStorePath";
pub const SERVER_HTTPS_TRUST_STORE_TYPE: &str = "druid.server.https.trustStoreType";
pub const SERVER_HTTPS_TRUST_STORE_PASSWORD: &str = "druid.server.https.trustStorePassword";
pub const SERVER_HTTPS_CERT_ALIAS: &str = "druid.server.https.certAlias";
pub const SERVER_HTTPS_CERT_ALIAS_NAME: &str = "server";
// Misc TLS
const DEFAULT_TLS_SECRET_CLASS: &str = "tls";
const SIMPLE_CLIENT_SSL_CONTEXT: &str = "simple-client-sslcontext";
pub const TLS_STORE_PASSWORD: &str = "changeit";
// directories
pub const STACKABLE_SERVER_TLS_DIR: &str = "/stackable/server_tls";
pub const STACKABLE_CLIENT_TLS_DIR: &str = "/stackable/client_tls";
pub const STACKABLE_SHARED_TLS_DIR: &str = "/stackable/tls";
pub const STACKABLE_MOUNT_SERVER_TLS_DIR: &str = "/stackable/mount_server_tls";
pub const STACKABLE_MOUNT_CLIENT_TLS_DIR: &str = "/stackable/mount_client_tls";

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
    //   will default to using TLS. That is why we need shared key and trust stores to allow
    //   druid internal communication and external client communication.
    #[serde(
        default = "DruidTlsSecretClass::default_secret_class",
        skip_serializing_if = "Option::is_none"
    )]
    pub server: Option<DruidTlsSecretClass>,
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

        if self.server.is_none() {
            ports.push((PLAINTEXT_PORT_NAME.to_string(), role.get_http_port()))
        } else {
            ports.push((TLS_PORT_NAME.to_string(), role.get_https_port()))
        }

        ports
    }

    pub fn get_probe(&self) -> Probe {
        let port = if self.server.is_some() {
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
            pod.add_volume(create_tls_volume(
                "server-tls-mount",
                &server_tls.secret_class,
            ));

            prepare.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
            druid.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
            pod.add_volume(
                VolumeBuilder::new("server-tls")
                    .with_empty_dir(Some(""), None)
                    .build(),
            );
        }
    }

    /// Add required TLS extensions
    pub fn add_tls_extensions(&self, extensions: &mut Vec<String>) {
        if self.server.is_some() {
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
        if self.server.is_none() {
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

        if self.server.is_some() {
            config.insert(
                CLIENT_HTTPS_TRUST_STORE_PATH.to_string(),
                Some(format!("{}/truststore.p12", STACKABLE_SERVER_TLS_DIR)),
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
                Some(CLIENT_HTTPS_CERT_ALIAS_NAME.to_string()),
            );

            config.insert(
                SERVER_HTTPS_KEY_STORE_PATH.to_string(),
                Some(format!("{}/keystore.p12", STACKABLE_SERVER_TLS_DIR)),
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

    /// Create init container command to create key and trust stores
    pub fn build_tls_stores_cmd(&self) -> Vec<String> {
        let mut command = vec![];
        if self.server.is_some() {
            command.extend(add_cert_to_trust_store_cmd(
                STACKABLE_MOUNT_SERVER_TLS_DIR,
                STACKABLE_SERVER_TLS_DIR,
                SERVER_HTTPS_CERT_ALIAS_NAME,
                TLS_STORE_PASSWORD,
                true,
            ));
            command.extend(add_key_pair_to_key_store_cmd(
                STACKABLE_MOUNT_SERVER_TLS_DIR,
                STACKABLE_SERVER_TLS_DIR,
                SERVER_HTTPS_CERT_ALIAS_NAME,
                TLS_STORE_PASSWORD,
            ));
            command.extend(chown_and_chmod(STACKABLE_SERVER_TLS_DIR));
        }

        command
    }
}

/// Generate a script to add a CA to a truststore
pub fn add_cert_to_trust_store_cmd(
    cert_directory: &str,
    trust_store_directory: &str,
    alias_name: &str,
    store_password: &str,
    delete_before: bool,
) -> Vec<String> {
    let mut command = vec![];

    if delete_before {
        command.push(format!(
            "echo [{trust_store_directory}] Cleaning up truststore - just in case"
        ));
        command.push(format!("rm -f {trust_store_directory}/truststore.p12"));
    }

    command.push(format!(
        "echo [{trust_store_directory}] Creating truststore"
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
        format!("echo [{cert_directory}] Creating certificate chain"),
        format!("cat {cert_directory}/ca.crt {cert_directory}/tls.crt > {cert_directory}/chain.crt"),
        // We have add the key cert pair via openssl to a temporary (keystore_<alias>.p12) PKCS12 keystore first, to add multiple key pairs (e.g. for TLS and client authentication)
        // Using this command twice will simply override any existing entries
        format!("echo [{key_store_directory}] Creating temporary [{key_store_directory}/keystore_{alias_name}.p12]"),
        format!("openssl pkcs12 -export -in {cert_directory}/chain.crt -inkey {cert_directory}/tls.key -out {key_store_directory}/keystore_{alias_name}.p12 --passout pass:{store_password} -name {alias_name}"),
        // We have to add the temporary keystore to our final keystore using keytool
        format!("echo [{key_store_directory}] Adding temporary [{key_store_directory}/keystore_{alias_name}].p12 to [{key_store_directory}/keystore.p12]"),
        format!("keytool -importkeystore -srckeystore {key_store_directory}/keystore_{alias_name}.p12 -srcstoretype pkcs12 -srcstorepass {store_password} -destkeystore {key_store_directory}/keystore.p12 -deststoretype pkcs12 -deststorepass {store_password}"),
        // Delete the temporary keystore
        format!("echo [{key_store_directory}] Removing temporary [{key_store_directory}/keystore_{alias_name}.p12"),
        format!("rm {key_store_directory}/keystore_{alias_name}.p12")
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
