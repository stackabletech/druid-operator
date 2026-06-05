//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    crd::listener::v1alpha1::Listener,
    k8s_openapi::api::core::v1::ConfigMap,
    kube::{Resource, ResourceExt},
};

use crate::{
    DRUID_CONTROLLER_NAME,
    controller::validate::ValidatedCluster,
    crd::{DruidRole, build_recommended_labels},
    listener::build_listener_connection_string,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
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

    #[snafu(display("failed to configure listener discovery configmap"))]
    ListenerConfiguration { source: crate::listener::Error },
}

/// Builds discovery [`ConfigMap`]s for connecting to a Druid cluster.
pub async fn build_discovery_configmaps(
    cluster: &ValidatedCluster,
    owner: &impl Resource<DynamicType = ()>,
    listener: Listener,
) -> Result<Vec<ConfigMap>, Error> {
    let name = owner.name_unchecked();
    Ok(vec![build_discovery_configmap(
        cluster, owner, &name, listener,
    )?])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain Druid cluster.
fn build_discovery_configmap(
    cluster: &ValidatedCluster,
    owner: &impl Resource<DynamicType = ()>,
    name: &str,
    listener: Listener,
) -> Result<ConfigMap, Error> {
    let router_host = build_listener_connection_string(
        listener,
        &cluster.cluster_config.druid_tls_security,
        &DruidRole::Router.to_string(),
    )
    .context(ListenerConfigurationSnafu)?;
    let sqlalchemy_conn_str = format!("druid://{}/druid/v2/sql", router_host);
    let avatica_conn_str = format!(
        "jdbc:avatica:remote:url=http://{}/druid/v2/sql/avatica/",
        router_host
    );

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(owner)
                .name(name)
                .ownerreference_from_resource(owner, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(&build_recommended_labels(
                    owner,
                    DRUID_CONTROLLER_NAME,
                    &cluster.image.app_version_label_value,
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
