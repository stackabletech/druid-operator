use std::str::FromStr;

use snafu::{OptionExt, Snafu};
use stackable_operator::{
    crd::listener::{self, v1alpha1::Listener},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
    v2::{
        builder::pod::volume::{
            ListenerReference, listener_operator_volume_source_builder_build_pvc,
        },
        types::kubernetes::{ListenerClassName, ListenerName, PersistentVolumeClaimName},
    },
};

use crate::{
    controller::{
        build::{PLACEHOLDER_LISTENER_ROLE_GROUP, security::listener_ports},
        validate::ValidatedCluster,
    },
    crd::{
        DruidRole,
        security::{DruidTlsSecurity, PLAINTEXT_PORT_NAME, TLS_PORT_NAME},
    },
};

stackable_operator::constant!(pub LISTENER_VOLUME_NAME: PersistentVolumeClaimName = "listener");
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("{role_name} listener has no adress"))]
    RoleListenerHasNoAddress { role_name: String },

    #[snafu(display("could not find port [{port_name}] for rolegroup listener {role_name}"))]
    NoServicePort {
        port_name: String,
        role_name: String,
    },
}

pub fn build_group_listener(
    cluster: &ValidatedCluster,
    listener_class: &ListenerClassName,
    listener_group_name: ListenerName,
    druid_role: &DruidRole,
) -> Listener {
    // The group listener is a role-level (not role-group-level) object, so there is no real
    // role-group name; the placeholder is used for the recommended labels.
    Listener {
        metadata: cluster
            .object_meta(
                listener_group_name.to_string(),
                druid_role,
                &PLACEHOLDER_LISTENER_ROLE_GROUP,
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

pub fn group_listener_name(
    cluster: &ValidatedCluster,
    druid_role: &DruidRole,
) -> Option<ListenerName> {
    match druid_role {
        DruidRole::Coordinator | DruidRole::Broker | DruidRole::Router => Some(
            ListenerName::from_str(&format!(
                "{cluster_name}-{druid_role}",
                cluster_name = cluster.name,
            ))
            .expect("a valid listener name"),
        ),
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use stackable_operator::{kube::api::ObjectMeta, v2::types::kubernetes::SecretClassName};

    use super::*;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    fn cluster() -> ValidatedCluster {
        validated_cluster(&druid_from_yaml(MINIMAL_DRUID_YAML))
    }

    #[test]
    fn group_listener_name_only_for_externally_reachable_roles() {
        let cluster = cluster();
        assert!(group_listener_name(&cluster, &DruidRole::Broker).is_some());
        assert!(group_listener_name(&cluster, &DruidRole::Coordinator).is_some());
        assert!(group_listener_name(&cluster, &DruidRole::Router).is_some());
        assert!(group_listener_name(&cluster, &DruidRole::Historical).is_none());
        assert!(group_listener_name(&cluster, &DruidRole::MiddleManager).is_none());
    }

    #[test]
    fn group_listener_name_is_cluster_and_role_scoped() {
        let name =
            group_listener_name(&cluster(), &DruidRole::Broker).expect("broker has a listener");
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

    /// A listener exposing both the plaintext and TLS ports, so the connection-string builder's
    /// port selection can be exercised.
    fn listener_with_both_ports() -> Listener {
        Listener {
            metadata: ObjectMeta::default(),
            spec: listener::v1alpha1::ListenerSpec::default(),
            status: Some(listener::v1alpha1::ListenerStatus {
                service_name: None,
                ingress_addresses: Some(vec![listener::v1alpha1::ListenerIngress {
                    address: "druid.example.com".to_string(),
                    address_type: listener::v1alpha1::AddressType::Hostname,
                    ports: BTreeMap::from([
                        (PLAINTEXT_PORT_NAME.to_string(), 8888),
                        (TLS_PORT_NAME.to_string(), 9088),
                    ]),
                }]),
                node_ports: None,
            }),
        }
    }

    #[test]
    fn connection_string_uses_plaintext_port_without_tls() {
        let tls = DruidTlsSecurity::new(false, None);
        let conn = build_listener_connection_string(
            listener_with_both_ports(),
            &tls,
            &"router".to_string(),
        )
        .expect("a connection string");
        assert_eq!(conn, "druid.example.com:8888");
    }

    #[test]
    fn connection_string_uses_tls_port_with_tls() {
        let tls = DruidTlsSecurity::new(false, Some(SecretClassName::from_str("tls").unwrap()));
        let conn = build_listener_connection_string(
            listener_with_both_ports(),
            &tls,
            &"router".to_string(),
        )
        .expect("a connection string");
        assert_eq!(conn, "druid.example.com:9088");
    }
}
