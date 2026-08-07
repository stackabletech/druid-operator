//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::configmap::ConfigMapBuilder, k8s_openapi::api::core::v1::ConfigMap,
};

use crate::{
    controller::{
        build::{
            PLACEHOLDER_DISCOVERY_ROLE_GROUP, object_meta,
            resource::listener::build_listener_connection_string,
        },
        validate::ValidatedCluster,
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

/// Builds the discovery [`ConfigMap`] containing information about how to connect to a certain
/// Druid cluster, or `None` while the Router group Listener is absent or has no ingress address.
///
/// The ConfigMap needs the Router group Listener's ingress address, which only the
/// listener-operator writes. Around the first reconcile runs the dereferenced Listener is absent
/// or still address-less; the ConfigMap is skipped then instead of failing the whole run -- the
/// Listener watch triggers a new run once the address is set. In that window an already existing
/// discovery ConfigMap is deleted as an orphan (only reachable when the Listener is deleted and
/// re-created) and re-created by the next run.
pub fn build_discovery_configmap(cluster: &ValidatedCluster) -> Result<Option<ConfigMap>, Error> {
    let Some(listener_address) = cluster
        .router_listener
        .as_ref()
        .and_then(|listener| listener.status.as_ref())
        .and_then(|status| status.ingress_addresses.as_ref()?.first())
    else {
        tracing::debug!(
            "the Router group Listener has no ingress address yet, \
               skipping the discovery ConfigMap"
        );
        return Ok(None);
    };

    let router_host = build_listener_connection_string(
        listener_address,
        &cluster.cluster_config.druid_tls_security,
        &DruidRole::Router.to_string(),
    )
    .context(ListenerConfigurationSnafu)?;
    let sqlalchemy_conn_str = format!("druid://{}/druid/v2/sql", router_host);
    let avatica_conn_str = format!(
        "jdbc:avatica:remote:url=http://{}/druid/v2/sql/avatica/",
        router_host
    );

    let config_map = ConfigMapBuilder::new()
        .metadata(
            object_meta(
                cluster,
                cluster.name.to_string(),
                cluster.recommended_labels(&DruidRole::Router, &PLACEHOLDER_DISCOVERY_ROLE_GROUP),
            )
            .build(),
        )
        .add_data("DRUID_ROUTER", router_host)
        .add_data("DRUID_SQLALCHEMY", sqlalchemy_conn_str)
        .add_data("DRUID_AVATICA_JDBC", avatica_conn_str)
        .build()
        .context(BuildConfigMapSnafu)?;

    Ok(Some(config_map))
}
