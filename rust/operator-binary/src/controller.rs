//! Ensures that `Pod`s are configured and running for each [`DruidCluster`][v1alpha1]
//!
//! [v1alpha1]: v1alpha1::DruidCluster
use std::{str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    cluster_resources::ClusterResourceApplyStrategy,
    commons::rbac::build_rbac_resources,
    kube::{
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::{KeyValuePairError, LabelValueError},
    logging::controller::ReconcilerError,
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    v2::{
        cluster_resources::cluster_resources_new,
        types::operator::{ControllerName, OperatorName, ProductName},
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::build::resource::{
        listener::{build_group_listener, group_listener_name},
        pdb::build_pdb,
        service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
    },
    crd::{APP_NAME, DruidClusterStatus, DruidRole, OPERATOR_NAME, v1alpha1},
    internal_secret::create_shared_internal_secret,
};

mod build;
mod dereference;
pub(crate) mod validate;

use build::resource::discovery::{self, build_discovery_configmaps};

pub const DRUID_CONTROLLER_NAME: &str = "druidcluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(DRUID_CONTROLLER_NAME, '.', OPERATOR_NAME);

pub(super) const CONTAINER_IMAGE_BASE_NAME: &str = "druid";

/// The product name (`druid`) as a type-safe label value.
pub(crate) fn product_name() -> ProductName {
    ProductName::from_str(APP_NAME).expect("'druid' is a valid product name")
}

/// The operator name as a type-safe label value.
pub(crate) fn operator_name() -> OperatorName {
    OperatorName::from_str(OPERATOR_NAME).expect("the operator name is a valid label value")
}

/// The controller name as a type-safe label value.
pub(crate) fn controller_name() -> ControllerName {
    ControllerName::from_str(DRUID_CONTROLLER_NAME)
        .expect("the controller name is a valid label value")
}

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply Service for role group {role_group}"))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("failed to apply ConfigMap for role group {role_group}"))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("failed to build StatefulSet"))]
    BuildRoleGroupStatefulSet {
        source: build::resource::statefulset::Error,
    },

    #[snafu(display("failed to apply StatefulSet for role group {role_group}"))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("failed to dereference cluster objects"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to build discovery ConfigMap"))]
    BuildDiscoveryConfig { source: discovery::Error },

    #[snafu(display("failed to apply discovery ConfigMap"))]
    ApplyDiscoveryConfig {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply cluster status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation {
        source: crate::internal_secret::Error,
    },

    #[snafu(display("failed to create RBAC service account"))]
    ApplyServiceAccount {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create RBAC role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build RBAC resources"))]
    BuildRbacResources {
        source: stackable_operator::commons::rbac::Error,
    },

    #[snafu(display("failed to apply PodDisruptionBudget"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to get required labels"))]
    GetRequiredLabels {
        source: KeyValuePairError<LabelValueError>,
    },

    #[snafu(display("DruidCluster object is invalid"))]
    InvalidDruidCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },

    #[snafu(display("failed to build rolegroup ConfigMap"))]
    BuildConfigMap {
        source: build::resource::config_map::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(
    druid: Arc<DeserializeGuard<v1alpha1::DruidCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");
    let druid = druid
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidDruidClusterSnafu)?;

    let client = &ctx.client;

    let dereferenced_objects = dereference::dereference(client, druid)
        .await
        .context(DereferenceSnafu)?;

    let validated_cluster =
        validate::validate(druid, &dereferenced_objects, &ctx.operator_environment)
            .context(ValidateClusterSnafu)?;

    let mut cluster_resources = cluster_resources_new(
        &product_name(),
        &operator_name(),
        &controller_name(),
        &validated_cluster.name,
        &validated_cluster.namespace,
        &validated_cluster.uid,
        ClusterResourceApplyStrategy::from(&druid.spec.cluster_operation),
        &druid.spec.object_overrides,
    );

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        druid,
        APP_NAME,
        cluster_resources
            .get_required_labels()
            .context(GetRequiredLabelsSnafu)?,
    )
    .context(BuildRbacResourcesSnafu)?;
    cluster_resources
        // We clone rbac_sa because we need to reuse it below
        .add(client, rbac_sa.clone())
        .await
        .context(ApplyServiceAccountSnafu)?;
    cluster_resources
        .add(client, rbac_rolebinding)
        .await
        .context(ApplyRoleBindingSnafu)?;

    // The internal secret is shared across all roles and role groups, so it only needs to be
    // created once per reconcile rather than inside the role loop below.
    create_shared_internal_secret(druid, client, DRUID_CONTROLLER_NAME)
        .await
        .context(FailedInternalSecretCreationSnafu)?;

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    for (druid_role, groups) in validated_cluster.role_group_configs.iter() {
        for (rolegroup_name, rg) in groups.iter() {
            let rg_headless_service =
                build_rolegroup_headless_service(&validated_cluster, druid_role, rolegroup_name);
            let rg_metrics_service =
                build_rolegroup_metrics_service(&validated_cluster, druid_role, rolegroup_name);

            let rg_configmap = build::resource::config_map::build_rolegroup_config_map(
                &validated_cluster,
                druid_role,
                rolegroup_name,
                rg,
            )
            .context(BuildConfigMapSnafu)?;
            let rg_statefulset = build::resource::statefulset::build_rolegroup_statefulset(
                &validated_cluster,
                druid_role,
                rolegroup_name,
                rg,
                &rbac_sa,
            )
            .context(BuildRoleGroupStatefulSetSnafu)?;

            cluster_resources
                .add(client, rg_headless_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;
            cluster_resources
                .add(client, rg_metrics_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;
            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;

            // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
            // to prevent unnecessary Pod restarts.
            // See https://github.com/stackabletech/commons-operator/issues/111 for details.
            ss_cond_builder.add(
                cluster_resources
                    .add(client, rg_statefulset)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        role_group: rolegroup_name.to_string(),
                    })?,
            );
        }

        if let Some(listener_class) = &validated_cluster.role_config(druid_role).listener_class
            && let Some(listener_group_name) = group_listener_name(&validated_cluster, druid_role)
        {
            let role_group_listener = build_group_listener(
                &validated_cluster,
                listener_class,
                listener_group_name,
                druid_role,
            );

            let listener = cluster_resources
                .add(client, role_group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;

            if *druid_role == DruidRole::Router {
                // discovery
                for discovery_cm in build_discovery_configmaps(&validated_cluster, listener)
                    .await
                    .context(BuildDiscoveryConfigSnafu)?
                {
                    cluster_resources
                        .add(client, discovery_cm)
                        .await
                        .context(ApplyDiscoveryConfigSnafu)?;
                }
            }
        }

        let role_config = validated_cluster.role_config(druid_role);

        if let Some(pdb) = build_pdb(&role_config.pdb, &validated_cluster, druid_role) {
            cluster_resources
                .add(client, pdb)
                .await
                .context(ApplyPdbSnafu)?;
        }
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&druid.spec.cluster_operation);

    let status = DruidClusterStatus {
        conditions: compute_conditions(druid, &[&ss_cond_builder, &cluster_operation_cond_builder]),
    };

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;
    client
        .apply_patch_status(OPERATOR_NAME, druid, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::DruidCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidDruidCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rstest::*;
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::*;
    use crate::{
        controller::build::{
            properties::ConfigFileName, resource::config_map::build_rolegroup_config_map,
        },
        crd::PROP_SEGMENT_CACHE_LOCATIONS,
    };

    #[rstest]
    #[case(
        "segment_cache.yaml",
        "default",
        "[{\"path\":\"/stackable/var/druid/segment-cache\",\"maxSize\":\"1G\",\"freeSpacePercent\":\"5\"}]"
    )]
    #[case(
        "segment_cache.yaml",
        "secondary",
        "[{\"path\":\"/stackable/var/druid/segment-cache\",\"maxSize\":\"5G\",\"freeSpacePercent\":\"2\"}]"
    )]
    fn segment_cache_location_property(
        #[case] druid_manifest: &str,
        #[case] tested_rolegroup_name: &str,
        #[case] expected_druid_segment_cache_property: &str,
    ) {
        let yaml =
            std::fs::read_to_string(format!("test/resources/druid_controller/{druid_manifest}"))
                .unwrap();
        let druid = crate::controller::validate::test_support::druid_from_yaml(&yaml);

        let cluster = crate::controller::validate::test_support::validated_cluster(&druid);

        // The segment cache property is injected dynamically by the config_map builder from the
        // merged resources of the validated role group config.
        let rg = cluster
            .role_group_configs
            .get(&DruidRole::Historical)
            .expect("historical role groups")
            .get(&RoleGroupName::from_str(tested_rolegroup_name).unwrap())
            .expect("tested rolegroup")
            .clone();

        let rg_configmap = build_rolegroup_config_map(
            &cluster,
            &DruidRole::Historical,
            &RoleGroupName::from_str(tested_rolegroup_name).unwrap(),
            &rg,
        )
        .expect("build rolegroup config map");

        let druid_segment_cache_property = rg_configmap
            .data
            .unwrap()
            .get(&ConfigFileName::RuntimeProperties.to_string())
            .unwrap()
            .to_string();

        let escaped_segment_cache_property =
            stackable_operator::v2::config_file_writer::to_java_properties_string(
                vec![(
                    &PROP_SEGMENT_CACHE_LOCATIONS.to_string(),
                    &expected_druid_segment_cache_property.to_string(),
                )]
                .into_iter(),
            )
            .unwrap();

        assert!(
            druid_segment_cache_property.contains(&escaped_segment_cache_property),
            "role group {tested_rolegroup_name}"
        );
    }
}
