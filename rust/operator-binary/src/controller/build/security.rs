//! Build-side rendering of the validated TLS security decision ([`DruidTlsSecurity`]).
//!
//! These functions turn the validated TLS decision into Kubernetes/config artifacts (ports, config
//! properties, volumes and mounts, keystore commands, probes). They live in the build step so the
//! validated [`DruidTlsSecurity`] type carries no rendering logic.

use std::{collections::BTreeMap, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        pod::{
            PodBuilder,
            container::ContainerBuilder,
            volume::{
                SecretFormat, SecretOperatorVolumeSourceBuilder,
                SecretOperatorVolumeSourceBuilderError, VolumeBuilder,
            },
        },
    },
    commons::secret_class::SecretClassVolumeProvisionParts,
    crd::listener,
    k8s_openapi::{
        api::core::v1::{ContainerPort, Probe, ServicePort, TCPSocketAction},
        apimachinery::pkg::util::intstr::IntOrString,
    },
    shared::time::Duration,
    v2::types::{common::Port, kubernetes::VolumeName},
};

use crate::crd::{
    DruidRole, KEY_STORE_FILE, STACKABLE_TRUST_STORE_PASSWORD, STACKABLE_TRUST_STORE_TYPE,
    TRUST_STORE_FILE,
    security::{DruidTlsSecurity, PLAINTEXT_PORT_NAME, STACKABLE_TLS_DIR, TLS_PORT_NAME},
};

#[derive(Snafu, Debug)]
pub enum Error {
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

// Ports
const ENABLE_PLAINTEXT_PORT: &str = "druid.enablePlaintextPort";
const PLAINTEXT_PORT: &str = "druid.plaintextPort";
const ENABLE_TLS_PORT: &str = "druid.enableTlsPort";
const TLS_PORT: &str = "druid.tlsPort";
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
/// The alias of the certificate in the keystore used for TLS stuff.
/// All secret-op generated keystores have one entry with the alias "1".
/// (side node: I think technically they don't have an alias and the JVm counts them, but not sure)
const TLS_ALIAS_NAME: &str = "1";
const AUTH_TRUST_STORE_PATH: &str = "druid.auth.basic.ssl.trustStorePath";
const AUTH_TRUST_STORE_TYPE: &str = "druid.auth.basic.ssl.trustStoreType";
const AUTH_TRUST_STORE_PASSWORD: &str = "druid.auth.basic.ssl.trustStorePassword";
// The layer-4 protocol used by all of Druid's exposed ports.
const TCP_PROTOCOL: &str = "TCP";

// directories
const STACKABLE_MOUNT_TLS_DIR: &str = "/stackable/mount_tls";

// volume names
stackable_operator::constant!(TLS_VOLUME_NAME: VolumeName = "tls");
stackable_operator::constant!(TLS_MOUNT_VOLUME_NAME: VolumeName = "tls-mount");

pub fn container_ports(tls: &DruidTlsSecurity, role: &DruidRole) -> Vec<ContainerPort> {
    let (name, port) = exposed_port(tls, role);
    vec![ContainerPort {
        name: Some(name.to_string()),
        container_port: port.into(),
        protocol: Some(TCP_PROTOCOL.to_string()),
        ..ContainerPort::default()
    }]
}

pub fn service_ports(tls: &DruidTlsSecurity, role: &DruidRole) -> Vec<ServicePort> {
    let (name, port) = exposed_port(tls, role);
    vec![ServicePort {
        name: Some(name.to_string()),
        port: port.into(),
        protocol: Some(TCP_PROTOCOL.to_string()),
        ..ServicePort::default()
    }]
}

pub fn listener_ports(
    tls: &DruidTlsSecurity,
    role: &DruidRole,
) -> Vec<listener::v1alpha1::ListenerPort> {
    let (name, port) = exposed_port(tls, role);
    vec![listener::v1alpha1::ListenerPort {
        name: name.to_string(),
        port: port.into(),
        protocol: Some(TCP_PROTOCOL.to_string()),
    }]
}

/// The single port (TLS or plaintext, depending on the TLS decision) Druid exposes for the role.
fn exposed_port(tls: &DruidTlsSecurity, role: &DruidRole) -> (&'static str, Port) {
    if tls.tls_enabled() {
        (TLS_PORT_NAME, role.get_https_port())
    } else {
        (PLAINTEXT_PORT_NAME, role.get_http_port())
    }
}

/// Adds required tls volume mounts to image and product container builders
/// Adds required tls volumes to pod builder
pub fn add_tls_volume_and_volume_mounts(
    tls: &DruidTlsSecurity,
    prepare: &mut ContainerBuilder,
    druid: &mut ContainerBuilder,
    pod: &mut PodBuilder,
    requested_secret_lifetime: &Duration,
    listener_scope: Option<String>,
) -> Result<(), Error> {
    // `ResolvedAuthenticationClasses::validate` already checked that the tls AuthenticationClass
    // uses the same SecretClass as the Druid server itself.
    if let Some(secret_class) = tls.server_and_internal_secret_class() {
        let mut secret_volume_source_builder = SecretOperatorVolumeSourceBuilder::new(
            secret_class,
            SecretClassVolumeProvisionParts::PublicPrivate,
        );

        secret_volume_source_builder
            .with_pod_scope()
            .with_format(SecretFormat::TlsPkcs12)
            .with_tls_pkcs12_password(STACKABLE_TRUST_STORE_PASSWORD)
            .with_auto_tls_cert_lifetime(*requested_secret_lifetime);

        if let Some(listener_scope) = &listener_scope {
            secret_volume_source_builder.with_listener_volume_scope(listener_scope);
        }

        pod.add_volume(
            VolumeBuilder::new(&*TLS_MOUNT_VOLUME_NAME)
                .ephemeral(
                    secret_volume_source_builder
                        .build()
                        .context(SecretVolumeBuildSnafu)?,
                )
                .build(),
        )
        .context(AddVolumeSnafu)?;
        prepare
            .add_volume_mount(&*TLS_MOUNT_VOLUME_NAME, STACKABLE_MOUNT_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        druid
            .add_volume_mount(&*TLS_MOUNT_VOLUME_NAME, STACKABLE_MOUNT_TLS_DIR)
            .context(AddVolumeMountSnafu)?;

        pod.add_volume(
            VolumeBuilder::new(&*TLS_VOLUME_NAME)
                .with_empty_dir(Option::<&str>::None, None)
                .build(),
        )
        .context(AddVolumeSnafu)?;

        prepare
            .add_volume_mount(&*TLS_VOLUME_NAME, STACKABLE_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        druid
            .add_volume_mount(&*TLS_VOLUME_NAME, STACKABLE_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
    }
    Ok(())
}

fn add_tls_port_config_properties(
    tls: &DruidTlsSecurity,
    config: &mut BTreeMap<String, String>,
    role: &DruidRole,
) {
    // no secure communication
    if !tls.tls_enabled() {
        config.insert(ENABLE_PLAINTEXT_PORT.to_string(), "true".to_string());
        config.insert(ENABLE_TLS_PORT.to_string(), "false".to_string());
        config.insert(PLAINTEXT_PORT.to_string(), role.get_http_port().to_string());
    }
    // only allow secure communication
    else {
        config.insert(ENABLE_PLAINTEXT_PORT.to_string(), "false".to_string());
        config.insert(ENABLE_TLS_PORT.to_string(), "true".to_string());
        config.insert(TLS_PORT.to_string(), role.get_https_port().to_string());
    }
}

/// Add required TLS ports, trust/key store properties
pub fn add_tls_config_properties(
    tls: &DruidTlsSecurity,
    config: &mut BTreeMap<String, String>,
    role: &DruidRole,
) {
    add_tls_port_config_properties(tls, config, role);

    if tls.tls_enabled() {
        add_tls_encryption_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
    }

    if tls.tls_authentication_enabled() {
        add_tls_auth_config_properties(config, STACKABLE_TLS_DIR, TLS_ALIAS_NAME);
    }
}

/// Inserts the path/type/password triple describing a single PKCS12 keystore or truststore
/// (`<store_directory>/<store_file>`), keeping the store type and password consistent across
/// all of Druid's HTTPS store settings.
fn add_pkcs12_store_properties(
    config: &mut BTreeMap<String, String>,
    store_directory: &str,
    store_file: &str,
    path_property: &str,
    type_property: &str,
    password_property: &str,
) {
    config.insert(
        path_property.to_string(),
        format!("{store_directory}/{store_file}"),
    );
    config.insert(
        type_property.to_string(),
        STACKABLE_TRUST_STORE_TYPE.to_string(),
    );
    config.insert(
        password_property.to_string(),
        STACKABLE_TRUST_STORE_PASSWORD.to_string(),
    );
}

fn add_tls_encryption_config_properties(
    config: &mut BTreeMap<String, String>,
    store_directory: &str,
    store_alias: &str,
) {
    // We need a truststore in addition to a keystore here, because server and internal tls
    // can only be enabled/disabled together
    add_pkcs12_store_properties(
        config,
        store_directory,
        TRUST_STORE_FILE,
        CLIENT_HTTPS_TRUST_STORE_PATH,
        CLIENT_HTTPS_TRUST_STORE_TYPE,
        CLIENT_HTTPS_TRUST_STORE_PASSWORD,
    );

    add_pkcs12_store_properties(
        config,
        store_directory,
        KEY_STORE_FILE,
        SERVER_HTTPS_KEY_STORE_PATH,
        SERVER_HTTPS_KEY_STORE_TYPE,
        SERVER_HTTPS_KEY_STORE_PASSWORD,
    );
    config.insert(SERVER_HTTPS_CERT_ALIAS.to_string(), store_alias.to_string());

    // We also need to configure the truststore for authentication related stuff,
    // such as verifying the LDAP server
    add_pkcs12_store_properties(
        config,
        store_directory,
        TRUST_STORE_FILE,
        AUTH_TRUST_STORE_PATH,
        AUTH_TRUST_STORE_TYPE,
        AUTH_TRUST_STORE_PASSWORD,
    );
}

fn add_tls_auth_config_properties(
    config: &mut BTreeMap<String, String>,
    store_directory: &str,
    store_alias: &str,
) {
    add_pkcs12_store_properties(
        config,
        store_directory,
        KEY_STORE_FILE,
        CLIENT_HTTPS_KEY_STORE_PATH,
        CLIENT_HTTPS_KEY_STORE_TYPE,
        CLIENT_HTTPS_KEY_STORE_PASSWORD,
    );
    // This is required because PKCS12 does not use any key passwords but it will
    // be checked and would lead to an exception:
    // java.security.UnrecoverableKeyException: Get Key failed: null
    // Must be set to the store password or we get a bad padding exception:
    // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
    config.insert(
        CLIENT_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
        STACKABLE_TRUST_STORE_PASSWORD.to_string(),
    );
    config.insert(CLIENT_HTTPS_CERT_ALIAS.to_string(), store_alias.to_string());
    // FIXME: https://github.com/stackabletech/druid-operator/issues/372
    // This is required because the server will send its pod ip which is not in the SANs of the certificates
    config.insert(
        CLIENT_HTTPS_VALIDATE_HOST_NAMES.to_string(),
        "false".to_string(),
    );

    // This will enforce the client to authenticate itself
    config.insert(
        SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE.to_string(),
        "true".to_string(),
    );

    add_pkcs12_store_properties(
        config,
        store_directory,
        TRUST_STORE_FILE,
        SERVER_HTTPS_TRUST_STORE_PATH,
        SERVER_HTTPS_TRUST_STORE_TYPE,
        SERVER_HTTPS_TRUST_STORE_PASSWORD,
    );
    // This is required because PKCS12 does not use any key passwords but it will
    // be checked and would lead to an exception:
    // java.security.UnrecoverableKeyException: Get Key failed: null
    // Must be set to the store password or we get a bad padding exception:
    // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
    config.insert(
        SERVER_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
        STACKABLE_TRUST_STORE_PASSWORD.to_string(),
    );
    // FIXME: https://github.com/stackabletech/druid-operator/issues/372
    // This is required because the client will send its pod ip which is not in the SANs of the certificates
    config.insert(
        SERVER_HTTPS_VALIDATE_HOST_NAMES.to_string(),
        "false".to_string(),
    );
}

pub fn build_tls_key_stores_cmd(tls: &DruidTlsSecurity) -> Vec<String> {
    if !tls.tls_enabled() {
        return vec![];
    }

    vec![
        // FIXME: *Technically* we should only add the system truststore in case any webPki usage is detected,
        // wether that's in S3, LDAP, OIDC, FTE or whatnot.
        format!(
            "cert-tools generate-pkcs12-truststore --pkcs12 '{STACKABLE_MOUNT_TLS_DIR}/{TRUST_STORE_FILE}:{STACKABLE_TRUST_STORE_PASSWORD}' --pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem --out {STACKABLE_TLS_DIR}/{TRUST_STORE_FILE} --out-password '{STACKABLE_TRUST_STORE_PASSWORD}'"
        ),
        // We can copy the keystore as is.
        format!(
            "cp {STACKABLE_MOUNT_TLS_DIR}/{KEY_STORE_FILE} {STACKABLE_TLS_DIR}/{KEY_STORE_FILE}"
        ),
    ]
}

pub fn get_tcp_socket_probe(
    tls: &DruidTlsSecurity,
    initial_delay_seconds: i32,
    period_seconds: i32,
    failure_threshold: i32,
    timeout_seconds: i32,
) -> Probe {
    let port = if tls.tls_enabled() {
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
