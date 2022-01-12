//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router process
//! inside a config map.  We only provide a connection string to the router process, since it serves as
//! a gateway to the cluster for client queries.

use std::num::TryFromIntError;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{DruidCluster, DruidRole, APP_NAME};
use stackable_operator::{
    builder::{ConfigMapBuilder, ObjectMetaBuilder},
    k8s_openapi::api::core::v1::{ConfigMap, Service},
    kube::{runtime::reflector::ObjectRef, Resource, ResourceExt},
};

use crate::druid_controller::druid_version;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object {} is missing metadata to build owner reference", druid))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
        druid: ObjectRef<DruidCluster>,
    },
    #[snafu(display("chroot path {} was relative (must be absolute)", chroot))]
    RelativeChroot { chroot: String },
    #[snafu(display("object has no name associated"))]
    NoName,
    #[snafu(display("object has no namespace associated"))]
    NoNamespace,
    #[snafu(display("failed to get service FQDN"))]
    NoServiceFqdn,
    #[snafu(display("could not find service port with name {}", port_name))]
    NoServicePort { port_name: String },
    #[snafu(display("service port with name {} does not have a nodePort", port_name))]
    NoNodePort { port_name: String },
    #[snafu(display("could not find Endpoints for {}", svc))]
    FindEndpoints {
        source: stackable_operator::error::Error,
        svc: ObjectRef<Service>,
    },
    #[snafu(display("nodePort was out of range"))]
    InvalidNodePort { source: TryFromIntError },
    #[snafu(display("failed to build ConfigMap"))]
    BuildConfigMap {
        source: stackable_operator::error::Error,
    },
}

/// Builds discovery [`ConfigMap`]s for connecting to a [`DruidCluster`] for all expected scenarios
pub async fn build_discovery_configmaps(
    owner: &impl Resource<DynamicType = ()>,
    druid: &DruidCluster,
) -> Result<Vec<ConfigMap>, Error> {
    let name = owner.name();
    Ok(vec![build_discovery_configmap(&name, owner, druid)?])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain [`DruidCluster`]
///
/// `hosts` will usually come from either [`pod_hosts`] or [`nodeport_hosts`].
fn build_discovery_configmap(
    name: &str,
    owner: &impl Resource<DynamicType = ()>,
    druid: &DruidCluster,
) -> Result<ConfigMap, Error> {
    let conn_str = format!(
        "druid://{}:{}/druid/v2/sql",
        druid
            .role_service_fqdn(&DruidRole::Router)
            .with_context(|| NoServiceFqdn)?,
        DruidRole::Router.get_http_port()
    );

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(druid)
                .name(name)
                .ownerreference_from_resource(owner, None, Some(true))
                .with_context(|| ObjectMissingMetadataForOwnerRef {
                    druid: ObjectRef::from_obj(druid),
                })?
                .with_recommended_labels(
                    druid,
                    APP_NAME,
                    druid_version(druid).unwrap_or("unknown"),
                    &DruidRole::Router.to_string(),
                    "discovery",
                )
                .build(),
        )
        .add_data("DRUID", conn_str)
        .build()
        .context(BuildConfigMap)
}
