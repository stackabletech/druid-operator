use snafu::{ResultExt, Snafu};
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

use crate::crd::{DruidRole, security::DruidTlsSecurity, v1alpha1};

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
