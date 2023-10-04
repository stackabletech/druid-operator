//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use crate::DRUID_CONTROLLER_NAME;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    build_recommended_labels, security::DruidTlsSecurity, DruidCluster, DruidRole,
};
use stackable_operator::{
    builder::{ConfigMapBuilder, ObjectMetaBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::ConfigMap,
    kube::{runtime::reflector::ObjectRef, Resource, ResourceExt},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object {} is missing metadata to build owner reference", druid))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
        druid: ObjectRef<DruidCluster>,
    },
    #[snafu(display("failed to get service FQDN"))]
    NoServiceFqdn,
    #[snafu(display("failed to build ConfigMap"))]
    BuildConfigMap {
        source: stackable_operator::error::Error,
    },
}

/// Builds discovery [`ConfigMap`]s for connecting to a [`DruidCluster`]
pub async fn build_discovery_configmaps(
    druid: &DruidCluster,
    owner: &impl Resource<DynamicType = ()>,
    resolved_product_image: &ResolvedProductImage,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Vec<ConfigMap>, Error> {
    let name = owner.name_unchecked();
    Ok(vec![build_discovery_configmap(
        druid,
        owner,
        resolved_product_image,
        druid_tls_security,
        &name,
    )?])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain [`DruidCluster`]
fn build_discovery_configmap(
    druid: &DruidCluster,
    owner: &impl Resource<DynamicType = ()>,
    resolved_product_image: &ResolvedProductImage,
    druid_tls_security: &DruidTlsSecurity,
    name: &str,
) -> Result<ConfigMap, Error> {
    let router_host = format!(
        "{}:{}",
        druid
            .role_service_fqdn(&DruidRole::Router)
            .with_context(|| NoServiceFqdnSnafu)?,
        if druid_tls_security.tls_enabled() {
            DruidRole::Router.get_https_port()
        } else {
            DruidRole::Router.get_http_port()
        }
    );
    let sqlalchemy_conn_str = format!("druid://{}/druid/v2/sql", router_host);
    let avatica_conn_str = format!(
        "jdbc:avatica:remote:url=http://{}/druid/v2/sql/avatica/",
        router_host
    );

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(druid)
                .name(name)
                .ownerreference_from_resource(owner, None, Some(true))
                .with_context(|_| ObjectMissingMetadataForOwnerRefSnafu {
                    druid: ObjectRef::from_obj(druid),
                })?
                .with_recommended_labels(build_recommended_labels(
                    druid,
                    DRUID_CONTROLLER_NAME,
                    &resolved_product_image.app_version_label,
                    &DruidRole::Router.to_string(),
                    "discovery",
                ))
                .build(),
        )
        .add_data("DRUID_ROUTER", router_host)
        .add_data("DRUID_SQLALCHEMY", sqlalchemy_conn_str)
        .add_data("DRUID_AVATICA_JDBC", avatica_conn_str)
        .build()
        .context(BuildConfigMapSnafu)
}
