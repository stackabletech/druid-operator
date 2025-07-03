use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::volume::{ListenerOperatorVolumeSourceBuilder, ListenerReference},
    },
    crd::listener::{self, v1alpha1::Listener},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kube::ResourceExt,
    kvp::{Labels, ObjectLabels},
};

use crate::crd::{
    DruidRole,
    security::{DruidTlsSecurity, PLAINTEXT_PORT_NAME, TLS_PORT_NAME},
    v1alpha1,
};

pub const LISTENER_VOLUME_NAME: &str = "listener";
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("listener object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build listener object meta data"))]
    BuildObjectMeta {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build listener volume"))]
    BuildListenerPersistentVolume {
        source: stackable_operator::builder::pod::volume::ListenerOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("{role_name} listener has no adress"))]
    RoleListenerHasNoAddress { role_name: String },

    #[snafu(display("could not find port [{port_name}] for rolegroup listener {role_name}"))]
    NoServicePort {
        port_name: String,
        role_name: String,
    },
}

pub fn build_group_listener(
    druid: &v1alpha1::DruidCluster,
    object_labels: ObjectLabels<v1alpha1::DruidCluster>,
    listener_class: String,
    listener_group_name: String,
    druid_role: &DruidRole,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Listener, Error> {
    Ok(Listener {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(listener_group_name)
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(BuildObjectMetaSnafu)?
            .build(),
        spec: listener::v1alpha1::ListenerSpec {
            class_name: Some(listener_class),
            ports: druid_tls_security.listener_ports(druid_role),
            ..listener::v1alpha1::ListenerSpec::default()
        },
        status: None,
    })
}

pub fn build_group_listener_pvc(
    group_listener_name: &String,
    unversioned_recommended_labels: &Labels,
) -> Result<PersistentVolumeClaim, Error> {
    ListenerOperatorVolumeSourceBuilder::new(
        &ListenerReference::ListenerName(group_listener_name.to_string()),
        unversioned_recommended_labels,
    )
    .context(BuildListenerPersistentVolumeSnafu)?
    .build_pvc(LISTENER_VOLUME_NAME.to_string())
    .context(BuildListenerPersistentVolumeSnafu)
}

pub fn group_listener_name(
    druid: &v1alpha1::DruidCluster,
    druid_role: &DruidRole,
) -> Option<String> {
    match druid_role {
        DruidRole::Coordinator | DruidRole::Broker | DruidRole::Router => Some(format!(
            "{cluster_name}-{druid_role}",
            cluster_name = druid.name_any(),
        )),
        DruidRole::Historical | DruidRole::MiddleManager => None,
    }
}

// Builds the connection string with respect to the listener provided objects
pub fn build_listener_connection_string(
    listener: Listener,
    druid_tls_security: &DruidTlsSecurity,
    role_name: &String,
) -> Result<String, Error> {
    // We only need the first address corresponding to the role
    let listener_address = listener
        .status
        .and_then(|s| s.ingress_addresses?.into_iter().next())
        .context(RoleListenerHasNoAddressSnafu { role_name })?;
    let port_name = match druid_tls_security.tls_enabled() {
        true => TLS_PORT_NAME,
        false => PLAINTEXT_PORT_NAME,
    };
    Ok(format!(
        "{address}:{port}",
        address = listener_address.address,
        port = listener_address
            .ports
            .get(port_name)
            .copied()
            .context(NoServicePortSnafu {
                port_name,
                role_name
            })?
    ))
}

/// The listener volume name depending on the role
pub fn secret_volume_listener_scope(role: &DruidRole) -> Option<String> {
    match role {
        DruidRole::Broker | DruidRole::Coordinator | DruidRole::Router => {
            Some(LISTENER_VOLUME_NAME.to_string())
        }
        DruidRole::Historical | DruidRole::MiddleManager => None,
    }
}
