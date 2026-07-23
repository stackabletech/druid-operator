//! Build steps that turn a `ValidatedCluster` into Kubernetes resources.

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::v2::types::operator::RoleGroupName;

use crate::{
    controller::{
        KubernetesResources,
        build::resource::{
            config_map::build_rolegroup_config_map,
            listener::{build_group_listener, group_listener_name},
            pdb::build_pdb,
            rbac::{build_role_binding, build_service_account},
            service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
            statefulset::build_rolegroup_statefulset,
        },
        validate::ValidatedCluster,
    },
    crd::DruidRole,
};

// Placeholder role-group name used for the recommended labels of the role-level discovery
// `ConfigMap` (which is not tied to a single role group).
stackable_operator::constant!(pub(crate) PLACEHOLDER_DISCOVERY_ROLE_GROUP: RoleGroupName = "discovery");

// Placeholder role-group name used for the recommended labels of the role-level `Listener`
// (which is not tied to a single role group).
stackable_operator::constant!(pub(crate) NONE_ROLE_GROUP_NAME: RoleGroupName = "none");

pub mod authentication;
pub mod graceful_shutdown;
pub mod jvm;
pub mod properties;
pub mod resource;
pub mod security;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build ConfigMap for role group {role_group}"))]
    ConfigMap {
        source: resource::config_map::Error,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build StatefulSet for role group {role_group}"))]
    StatefulSet {
        source: resource::statefulset::Error,
        role_group: RoleGroupName,
    },
}

/// Builds the Kubernetes resources for the given validated cluster.
///
/// Does not need a Kubernetes client: every reference to another Kubernetes resource is already
/// dereferenced and validated by this point.
/// The remaining errors are resource-assembly failures only.
///
/// `service_account_name` is the name of the RBAC `ServiceAccount` the role-group Pods run under
/// (RBAC resources are built and applied separately, in the reconcile step).
///
/// The Router group `Listener` and the discovery `ConfigMap`s are not built here: the discovery
/// `ConfigMap` derives from the *applied* Router listener's ingress address, so both are built and
/// applied in the reconcile step instead.
pub fn build(cluster: &ValidatedCluster) -> Result<KubernetesResources, Error> {
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut config_maps = vec![];
    let mut pod_disruption_budgets = vec![];

    for (druid_role, role_group_configs) in &cluster.role_group_configs {
        let role_config = cluster.role_config(druid_role);

        if let Some(pdb) = build_pdb(&role_config.pdb, cluster, druid_role) {
            pod_disruption_budgets.push(pdb);
        }

        // The Router group Listener is built and applied in the reconcile step instead (see the
        // module docs and [`KubernetesResources`]), so it is skipped here.
        if *druid_role != DruidRole::Router
            && let Some(listener_class) = &role_config.listener_class
            && let Some(listener_group_name) = group_listener_name(cluster, druid_role)
        {
            listeners.push(build_group_listener(
                cluster,
                listener_class,
                listener_group_name,
                druid_role,
            ));
        }

        for (role_group_name, rg) in role_group_configs {
            services.push(build_rolegroup_headless_service(
                cluster,
                druid_role,
                role_group_name,
            ));
            services.push(build_rolegroup_metrics_service(
                cluster,
                druid_role,
                role_group_name,
            ));
            config_maps.push(
                build_rolegroup_config_map(cluster, druid_role, role_group_name, rg).context(
                    ConfigMapSnafu {
                        role_group: role_group_name.clone(),
                    },
                )?,
            );
            stateful_sets.push(
                build_rolegroup_statefulset(cluster, druid_role, role_group_name, rg).context(
                    StatefulSetSnafu {
                        role_group: role_group_name.clone(),
                    },
                )?,
            );
        }
    }

    Ok(KubernetesResources {
        stateful_sets,
        services,
        listeners,
        config_maps,
        pod_disruption_budgets,
        service_accounts: vec![build_service_account(cluster)],
        role_bindings: vec![build_role_binding(cluster)],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::kube::Resource;

    use super::build;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    fn sorted_names(resources: &[impl Resource]) -> Vec<&str> {
        let mut names: Vec<&str> = resources
            .iter()
            .filter_map(|resource| resource.meta().name.as_deref())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn build_produces_expected_resource_names() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");

        // One StatefulSet and one ConfigMap per role group (one role group per role).
        let expected_role_group_names = [
            "simple-druid-broker-default",
            "simple-druid-coordinator-default",
            "simple-druid-historical-default",
            "simple-druid-middlemanager-default",
            "simple-druid-router-default",
        ];
        assert_eq!(
            sorted_names(&resources.stateful_sets),
            expected_role_group_names
        );
        assert_eq!(
            sorted_names(&resources.config_maps),
            expected_role_group_names
        );

        // Group Listeners are built for the externally reachable roles except the Router (whose
        // Listener is applied in the reconcile step): Broker and Coordinator.
        // TODO: add router listener here once properly build in the built step.
        assert_eq!(
            sorted_names(&resources.listeners),
            ["simple-druid-broker", "simple-druid-coordinator"]
        );
    }

    /// Locks the RBAC resource names, the roleRef, and the recommended label set against
    /// accidental drift. The fixture's cluster name deliberately differs from the product name so
    /// that swapped `name`/`instance` label values cannot pass unnoticed.
    #[test]
    fn build_produces_rbac() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");

        assert_eq!(
            sorted_names(&resources.service_accounts),
            ["simple-druid-serviceaccount"]
        );
        assert_eq!(
            sorted_names(&resources.role_bindings),
            ["simple-druid-rolebinding"]
        );

        let expected_labels = BTreeMap::from(
            [
                ("app.kubernetes.io/component", "none"),
                ("app.kubernetes.io/instance", "simple-druid"),
                (
                    "app.kubernetes.io/managed-by",
                    "druid.stackable.tech_druidcluster",
                ),
                ("app.kubernetes.io/name", "druid"),
                ("app.kubernetes.io/role-group", "none"),
                ("app.kubernetes.io/version", "30.0.0-stackable0.0.0-dev"),
                ("stackable.tech/vendor", "Stackable"),
            ]
            .map(|(key, value)| (key.to_string(), value.to_string())),
        );
        let service_account = resources
            .service_accounts
            .first()
            .expect("a ServiceAccount is built");
        assert_eq!(
            service_account.metadata.labels,
            Some(expected_labels.clone())
        );

        let role_binding = resources
            .role_bindings
            .first()
            .expect("a RoleBinding is built");
        assert_eq!(role_binding.metadata.labels, Some(expected_labels));
        assert_eq!(role_binding.role_ref.name, "druid-clusterrole");
    }
}
