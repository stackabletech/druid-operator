//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::ConfigMap,
    kube::{Resource, ResourceExt, runtime::reflector::ObjectRef},
    utils::cluster_info::KubernetesClusterInfo,
};

use crate::{
    DRUID_CONTROLLER_NAME,
    crd::{DruidRole, build_recommended_labels, security::DruidTlsSecurity, v1alpha1},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object {} is missing metadata to build owner reference", druid))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
        druid: ObjectRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("failed to get service FQDN"))]
    NoServiceFqdn,

    #[snafu(display("failed to build ConfigMap"))]
    BuildConfigMap {
        source: stackable_operator::builder::configmap::Error,
    },

    #[snafu(display("failed to add recommended labels"))]
    AddRecommendedLabels {
        source: stackable_operator::builder::meta::Error,
    },
}

/// Builds discovery [`ConfigMap`]s for connecting to a [`v1alpha1::DruidCluster`].
pub async fn build_discovery_configmaps(
    druid: &v1alpha1::DruidCluster,
    owner: &impl Resource<DynamicType = ()>,
    cluster_info: &KubernetesClusterInfo,
    resolved_product_image: &ResolvedProductImage,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Vec<ConfigMap>, Error> {
    let name = owner.name_unchecked();
    Ok(vec![build_discovery_configmap(
        druid,
        owner,
        cluster_info,
        resolved_product_image,
        druid_tls_security,
        &name,
    )?])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain [`v1alpha1::DruidCluster`].
fn build_discovery_configmap(
    druid: &v1alpha1::DruidCluster,
    owner: &impl Resource<DynamicType = ()>,
    cluster_info: &KubernetesClusterInfo,
    resolved_product_image: &ResolvedProductImage,
    druid_tls_security: &DruidTlsSecurity,
    name: &str,
) -> Result<ConfigMap, Error> {
    let router_host = format!(
        "{}:{}",
        druid
            .role_service_fqdn(&DruidRole::Router, cluster_info)
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
                .context(AddRecommendedLabelsSnafu)?
                .build(),
        )
        .add_data("DRUID_ROUTER", router_host)
        .add_data("DRUID_SQLALCHEMY", sqlalchemy_conn_str)
        .add_data("DRUID_AVATICA_JDBC", avatica_conn_str)
        .build()
        .context(BuildConfigMapSnafu)
}
