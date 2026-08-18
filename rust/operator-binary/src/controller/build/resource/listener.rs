use std::str::FromStr;

use stackable_operator::{
    crd::listener::{
        self,
        v1alpha1::{Listener, ListenerIngress},
    },
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
    v2::{
        builder::pod::volume::{
            ListenerReference, listener_operator_volume_source_builder_build_pvc,
        },
        types::{
            kubernetes::{ListenerClassName, ListenerName, PersistentVolumeClaimName},
            operator::ClusterName,
        },
    },
};

use crate::{
    controller::{
        build::{object_meta, recommended_labels_for_role_resources, security::listener_ports},
        validate::ValidatedCluster,
    },
    crd::{
        DruidRole,
        security::{DruidTlsSecurity, PLAINTEXT_PORT_NAME, TLS_PORT_NAME},
    },
};

stackable_operator::constant!(pub LISTENER_VOLUME_NAME: PersistentVolumeClaimName = "listener");
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

pub fn build_group_listener(
    cluster: &ValidatedCluster,
    listener_class: &ListenerClassName,
    listener_group_name: ListenerName,
    druid_role: &DruidRole,
) -> Listener {
    // The group listener is a role-level (not role-group-level) object, so it carries the
    // role-level recommended labels.
    Listener {
        metadata: object_meta(
            cluster,
            listener_group_name.to_string(),
            recommended_labels_for_role_resources(cluster, druid_role),
        )
        .build(),
        spec: listener::v1alpha1::ListenerSpec {
            class_name: Some(listener_class.to_string()),
            ports: Some(listener_ports(
                &cluster.cluster_config.druid_tls_security,
                druid_role,
            )),
            ..listener::v1alpha1::ListenerSpec::default()
        },
        status: None,
    }
}

pub fn build_group_listener_pvc(
    group_listener_name: &ListenerName,
    unversioned_recommended_labels: &Labels,
) -> PersistentVolumeClaim {
    listener_operator_volume_source_builder_build_pvc(
        &ListenerReference::Listener(group_listener_name.clone()),
        unversioned_recommended_labels,
        &LISTENER_VOLUME_NAME,
    )
}

/// The name of the group [`Listener`] of the given role, or `None` for roles that expose no
/// Listener.
pub fn group_listener_name(
    cluster_name: &ClusterName,
    druid_role: &DruidRole,
) -> Option<ListenerName> {
    match druid_role {
        DruidRole::Coordinator | DruidRole::Broker | DruidRole::Router => {
            Some(general_group_listener_name(cluster_name, druid_role))
        }
        DruidRole::Historical | DruidRole::MiddleManager => None,
    }
}

/// Returns the name of the group listener for a specific role, without
/// checking if the role actually exposes one.
pub fn general_group_listener_name(
    cluster_name: &ClusterName,
    druid_role: &DruidRole,
) -> ListenerName {
    ListenerName::from_str(&format!(
        "{cluster_name}-{druid_role}",
        druid_role = druid_role.as_ref()
    ))
    .expect("a valid listener name")
}

/// The connection string (`<address>:<port>`) for the given ingress address, or `None` when the
/// address does not expose the expected (TLS or plaintext, depending on the TLS decision) port.
///
/// The port can be missing right after TLS is toggled on a running cluster: only the
/// listener-operator rewrites the Listener status, and only after it has seen the updated
/// Listener spec, so the fetched status still carries the old port name for a while.
pub fn build_listener_connection_string(
    listener_address: &ListenerIngress,
    druid_tls_security: &DruidTlsSecurity,
) -> Option<String> {
    let port_name = match druid_tls_security.tls_enabled() {
        true => TLS_PORT_NAME,
        false => PLAINTEXT_PORT_NAME,
    };
    let port = listener_address.ports.get(port_name)?;
    Some(format!(
        "{address}:{port}",
        address = listener_address.address
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use stackable_operator::v2::types::kubernetes::SecretClassName;

    use super::*;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    fn cluster() -> ValidatedCluster {
        validated_cluster(&druid_from_yaml(MINIMAL_DRUID_YAML))
    }

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *LISTENER_VOLUME_NAME;
    }

    #[test]
    fn group_listener_name_only_for_externally_reachable_roles() {
        let cluster_name = cluster().name;
        assert!(group_listener_name(&cluster_name, &DruidRole::Broker).is_some());
        assert!(group_listener_name(&cluster_name, &DruidRole::Coordinator).is_some());
        assert!(group_listener_name(&cluster_name, &DruidRole::Router).is_some());
        assert!(group_listener_name(&cluster_name, &DruidRole::Historical).is_none());
        assert!(group_listener_name(&cluster_name, &DruidRole::MiddleManager).is_none());
    }

    #[test]
    fn group_listener_name_is_cluster_and_role_scoped() {
        let name = group_listener_name(&cluster().name, &DruidRole::Broker)
            .expect("broker has a listener");
        assert_eq!(name.to_string(), "simple-druid-broker");
    }

    #[test]
    fn secret_volume_listener_scope_only_for_externally_reachable_roles() {
        assert_eq!(
            secret_volume_listener_scope(&DruidRole::Broker),
            Some("listener".to_string())
        );
        assert!(secret_volume_listener_scope(&DruidRole::Historical).is_none());
        assert!(secret_volume_listener_scope(&DruidRole::MiddleManager).is_none());
    }

    /// An ingress address exposing both the plaintext and TLS ports, so the connection-string builder's
    /// port selection can be exercised.
    fn ingress_with_both_ports() -> ListenerIngress {
        ListenerIngress {
            address: "druid.example.com".to_string(),
            address_type: listener::v1alpha1::AddressType::Hostname,
            ports: BTreeMap::from([
                (PLAINTEXT_PORT_NAME.to_string(), 8888),
                (TLS_PORT_NAME.to_string(), 9088),
            ]),
        }
    }

    #[test]
    fn connection_string_uses_plaintext_port_without_tls() {
        let tls = DruidTlsSecurity::new(false, None);
        let conn = build_listener_connection_string(&ingress_with_both_ports(), &tls)
            .expect("a connection string");
        assert_eq!(conn, "druid.example.com:8888");
    }

    #[test]
    fn connection_string_uses_tls_port_with_tls() {
        let tls = DruidTlsSecurity::new(
            false,
            Some(SecretClassName::from_str("tls").expect("test: valid secret class")),
        );
        let conn = build_listener_connection_string(&ingress_with_both_ports(), &tls)
            .expect("a connection string");
        assert_eq!(conn, "druid.example.com:9088");
    }

    /// Right after a TLS toggle the fetched Listener status still carries only the old port name,
    /// so the expected port is absent and no connection string can be built.
    #[test]
    fn connection_string_is_none_without_the_expected_port() {
        let tls = DruidTlsSecurity::new(
            false,
            Some(SecretClassName::from_str("tls").expect("test: valid secret class")),
        );
        let plaintext_only = ListenerIngress {
            ports: BTreeMap::from([(PLAINTEXT_PORT_NAME.to_string(), 8888)]),
            ..ingress_with_both_ports()
        };
        assert!(build_listener_connection_string(&plaintext_only, &tls).is_none());
    }
}
