//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    crd::listener::v1alpha1::Listener,
    k8s_openapi::api::core::v1::ConfigMap,
    v2::{
        builder::meta::ownerreference_from_resource,
        kvp::label::recommended_labels,
        types::operator::{ProductVersion, RoleGroupName},
    },
};

use crate::{
    controller::{
        build::resource::listener::build_listener_connection_string, controller_name,
        operator_name, product_name, validate::ValidatedCluster,
    },
    crd::DruidRole,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build ConfigMap"))]
    BuildConfigMap {
        source: stackable_operator::builder::configmap::Error,
    },

    #[snafu(display("failed to configure listener discovery configmap"))]
    ListenerConfiguration {
        source: crate::controller::build::resource::listener::Error,
    },
}

/// Builds discovery [`ConfigMap`]s for connecting to a Druid cluster.
pub async fn build_discovery_configmaps(
    cluster: &ValidatedCluster,
    listener: Listener,
) -> Result<Vec<ConfigMap>, Error> {
    Ok(vec![build_discovery_configmap(cluster, listener)?])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain Druid cluster.
fn build_discovery_configmap(
    cluster: &ValidatedCluster,
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
                .name_and_namespace(cluster)
                .ownerreference(ownerreference_from_resource(cluster, None, Some(true)))
                .with_labels(recommended_labels(
                    cluster,
                    &product_name(),
                    &ProductVersion::from_str(&cluster.image.app_version_label_value)
                        .expect("a valid product version"),
                    &operator_name(),
                    &controller_name(),
                    &DruidRole::Router.to_role_name(),
                    &RoleGroupName::from_str("discovery").expect("a valid role group name"),
                ))
                .build(),
        )
        .add_data("DRUID_ROUTER", router_host)
        .add_data("DRUID_SQLALCHEMY", sqlalchemy_conn_str)
        .add_data("DRUID_AVATICA_JDBC", avatica_conn_str)
        .build()
        .context(BuildConfigMapSnafu)
}
