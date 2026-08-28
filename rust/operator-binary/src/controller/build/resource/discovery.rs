//! Discovery for Druid.  We make Druid discoverable by putting a connection string to the router service
//! inside a config map.  We only provide a connection string to the router service, since it serves as
//! a gateway to the cluster for client queries.
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    k8s_openapi::api::core::v1::ConfigMap,
};

use crate::{
    controller::{
        build::{
            object_meta, recommended_labels_for_role_resources,
            resource::listener::build_listener_connection_string,
        },
        validate::ValidatedCluster,
    },
    crd::DruidRole,
};

/// Builds the discovery [`ConfigMap`] containing information about how to connect to a certain
/// Druid cluster.
///
/// The ConfigMap needs the Router group Listener's ingress address with the expected (TLS or
/// plaintext) port, which only the listener-operator writes. There are windows where the
/// dereferenced Listener does not provide that yet: around the first reconcile runs it is absent
/// or still address-less, and right after a TLS toggle its status still carries the old port
/// name. Failing the build in such a window would prevent the apply step from running at all
/// (after a TLS toggle even permanently, as the Listener spec carrying the new port name would
/// never be applied and the status never rewritten), so instead:
///
/// - a discovery ConfigMap already stored in the cluster is re-emitted unchanged via
///   [`reemit_discovery_configmap`], keeping it tracked by the apply step;
/// - otherwise (it has never been built yet) `None` is returned and the ConfigMap is skipped
///   for this run.
///
/// Either way the Listener watch triggers a new run once the listener-operator has caught up,
/// and a fresh ConfigMap is built then.
pub fn build_discovery_configmap(cluster: &ValidatedCluster) -> Option<ConfigMap> {
    let Some(router_host) = cluster
        .router_listener
        .as_ref()
        .and_then(|listener| listener.status.as_ref())
        .and_then(|status| status.ingress_addresses.as_ref()?.first())
        .and_then(|listener_address| {
            build_listener_connection_string(
                listener_address,
                &cluster.cluster_config.druid_tls_security,
            )
        })
    else {
        return match &cluster.discovery_config_map {
            Some(existing) => {
                tracing::debug!(
                    "the Router group Listener has no ingress address with the expected port \
                       yet, re-emitting the stored discovery ConfigMap unchanged"
                );
                Some(reemit_discovery_configmap(cluster, existing))
            }
            None => {
                tracing::debug!(
                    "the Router group Listener has no ingress address with the expected port \
                       yet and no discovery ConfigMap exists, skipping it"
                );
                None
            }
        };
    };
    let sqlalchemy_conn_str = format!("druid://{}/druid/v2/sql", router_host);
    let avatica_conn_str = format!(
        "jdbc:avatica:remote:url=http://{}/druid/v2/sql/avatica/",
        router_host
    );

    let config_map = ConfigMapBuilder::new()
        .metadata(discovery_configmap_meta(cluster).build())
        .add_data("DRUID_ROUTER", router_host)
        .add_data("DRUID_SQLALCHEMY", sqlalchemy_conn_str)
        .add_data("DRUID_AVATICA_JDBC", avatica_conn_str)
        .build()
        .expect("The ConfigMap metadata is set in this function.");

    Some(config_map)
}

/// Re-emits the stored discovery [`ConfigMap`] so that the apply step keeps tracking it in
/// `ClusterResources` while no fresh one can be built (a tracked resource that is not re-added
/// in a run would be deleted as an orphan).
///
/// The fetched `data` is carried over unchanged, so applying it is a no-op on the server. The
/// metadata is built fresh instead of echoing the fetched metadata: a fetched object carries
/// server-populated fields (`resourceVersion`, `uid`, `managedFields`) that must not appear in
/// an apply patch, and the labels required by `ClusterResources::add` are added here.
fn reemit_discovery_configmap(cluster: &ValidatedCluster, existing: &ConfigMap) -> ConfigMap {
    ConfigMap {
        metadata: discovery_configmap_meta(cluster).build(),
        data: existing.data.clone(),
        ..ConfigMap::default()
    }
}

/// Shared metadata for both the freshly built and the re-emitted discovery ConfigMap, so that
/// the two are identical apart from their contents. The discovery ConfigMap is named after the
/// cluster itself. Discovery is a role-level object (it exposes the Router role), so it carries
/// the role-level recommended labels.
fn discovery_configmap_meta(cluster: &ValidatedCluster) -> ObjectMetaBuilder {
    object_meta(
        cluster,
        cluster.name.to_string(),
        recommended_labels_for_role_resources(cluster, &DruidRole::Router),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::{
        crd::listener::{self, v1alpha1::Listener},
        kube::api::ObjectMeta,
    };

    use super::*;
    use crate::{
        controller::validate::test_support::{
            MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
        },
        crd::security::PLAINTEXT_PORT_NAME,
    };

    /// A Router group Listener whose single ingress address exposes the given ports, shaped as
    /// the dereference step fetches it from the cluster.
    fn router_listener_with_ports(ports: BTreeMap<String, i32>) -> Listener {
        Listener {
            metadata: ObjectMeta::default(),
            spec: listener::v1alpha1::ListenerSpec::default(),
            status: Some(listener::v1alpha1::ListenerStatus {
                service_name: None,
                ingress_addresses: Some(vec![listener::v1alpha1::ListenerIngress {
                    address: "druid.example.com".to_string(),
                    address_type: listener::v1alpha1::AddressType::Hostname,
                    ports,
                }]),
                node_ports: None,
            }),
        }
    }

    /// Right after a TLS toggle the fetched Listener status still carries the old port name (only
    /// the listener-operator rewrites the status, and only after it has seen the new spec). The
    /// discovery ConfigMap must be skipped instead of failing the build: a build failure would
    /// prevent the apply step from ever publishing the new Listener spec, deadlocking the
    /// reconcile loop.
    #[test]
    fn address_without_the_expected_port_is_skipped() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);
        // The fixture enables TLS, so the expected port name is the TLS one; the fetched status
        // still carries only the plaintext port.
        cluster.router_listener = Some(router_listener_with_ports(BTreeMap::from([(
            PLAINTEXT_PORT_NAME.to_string(),
            8888,
        )])));

        assert!(build_discovery_configmap(&cluster).is_none());
    }

    /// While no fresh ConfigMap can be built (no usable ingress address on the Router group
    /// Listener), an already stored discovery ConfigMap is re-emitted unchanged instead of being
    /// dropped: a resource missing from a run is deleted as an orphan by the apply step, which
    /// would break Pods mounting the ConfigMap.
    #[test]
    fn reemits_the_stored_config_map_when_a_fresh_one_cannot_be_built() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);
        cluster.router_listener = None;
        let stored_data = BTreeMap::from([(
            "DRUID_ROUTER".to_string(),
            "druid.example.com:9088".to_string(),
        )]);
        cluster.discovery_config_map = Some(ConfigMap {
            metadata: ObjectMeta {
                name: Some("simple-druid".to_string()),
                resource_version: Some("42".to_string()),
                uid: Some("6a8f6428-6f45-4bd6-9a9c-3d040ec93cca".to_string()),
                ..ObjectMeta::default()
            },
            data: Some(stored_data.clone()),
            ..ConfigMap::default()
        });

        let config_map =
            build_discovery_configmap(&cluster).expect("the stored ConfigMap must be re-emitted");

        assert_eq!(
            config_map.data,
            Some(stored_data),
            "the stored values must be carried over unchanged"
        );
        assert_eq!(config_map.metadata.name.as_deref(), Some("simple-druid"));
        assert!(
            config_map.metadata.resource_version.is_none(),
            "server-populated fields must not be echoed into an apply patch"
        );
        let labels = config_map.metadata.labels.expect("labels are set");
        assert_eq!(
            labels.get("app.kubernetes.io/instance").map(String::as_str),
            Some("simple-druid"),
            "the labels required by ClusterResources::add must be set"
        );
    }
}
