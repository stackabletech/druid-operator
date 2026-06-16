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
        types::kubernetes::{ListenerName, PersistentVolumeClaimName},
    },
};

use crate::{
    controller::{build::PLACEHOLDER_LISTENER_ROLE_GROUP, validate::ValidatedCluster},
    crd::{
        DruidRole,
        security::{DruidTlsSecurity, PLAINTEXT_PORT_NAME, TLS_PORT_NAME},
    },
};

pub const LISTENER_VOLUME_NAME: &str = "listener";
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
    listener_class: String,
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
            class_name: Some(listener_class),
            ports: Some(
                cluster
                    .cluster_config
                    .druid_tls_security
                    .listener_ports(druid_role),
            ),
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
        &PersistentVolumeClaimName::from_str(LISTENER_VOLUME_NAME)
            .expect("a valid persistent volume claim name"),
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
