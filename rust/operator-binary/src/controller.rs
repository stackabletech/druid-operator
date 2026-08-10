//! Ensures that `Pod`s are configured and running for each [`DruidCluster`][v1alpha1]
//!
//! [v1alpha1]: v1alpha1::DruidCluster
use std::{marker::PhantomData, str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    cluster_resources::ClusterResourceApplyStrategy,
    crd::listener::v1alpha1::Listener,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Secret, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    shared::time::Duration,
    v2::types::operator::{ControllerName, OperatorName, ProductName},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{apply::Applier, update_status::update_status},
    crd::{APP_NAME, OPERATOR_NAME, v1alpha1},
};

mod apply;
mod build;
mod dereference;
mod migrate;
mod update_status;
pub(crate) mod validate;

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

/// Marker for prepared Kubernetes resources which are not applied yet.
pub struct Prepared;

/// Marker for applied Kubernetes resources.
pub struct Applied;

/// Every Kubernetes resource produced by the build step.
///
/// `T` is a marker that indicates if these resources are only [`Prepared`] or already [`Applied`].
/// The marker is useful e.g. to ensure that the cluster status is updated based on the applied
/// resources.
pub struct KubernetesResources<T> {
    pub stateful_sets: Vec<StatefulSet>,
    pub services: Vec<Service>,
    pub listeners: Vec<Listener>,
    pub config_maps: Vec<ConfigMap>,
    pub pod_disruption_budgets: Vec<PodDisruptionBudget>,
    pub service_accounts: Vec<ServiceAccount>,
    pub role_bindings: Vec<RoleBinding>,
    pub internal_secret: Secret,
    pub status: PhantomData<T>,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply the Kubernetes resources"))]
    ApplyResources { source: apply::Error },

    #[snafu(display("failed to build the Kubernetes resources"))]
    BuildResources { source: build::Error },

    #[snafu(display("failed to dereference cluster objects"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to update the cluster status"))]
    UpdateStatus { source: update_status::Error },

    #[snafu(display("failed to migrate the immutable internal secret"))]
    MigrateInternalSecret { source: migrate::Error },

    #[snafu(display("DruidCluster object is invalid"))]
    InvalidDruidCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },
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

    let resources = build::build(&validated_cluster).context(BuildResourcesSnafu)?;

    // Temporary migration step; remove together with the [`migrate`] module.
    migrate::delete_immutable_internal_secret(client, &validated_cluster)
        .await
        .context(MigrateInternalSecretSnafu)?;

    let applier = Applier::new(
        client,
        &validated_cluster,
        ClusterResourceApplyStrategy::from(&druid.spec.cluster_operation),
        &druid.spec.object_overrides,
    );

    let applied = applier
        .apply(resources)
        .await
        .context(ApplyResourcesSnafu)?;

    update_status(client, druid, &applied)
        .await
        .context(UpdateStatusSnafu)?;

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

    use crate::{
        controller::build::{
            properties::ConfigFileName, resource::config_map::build_rolegroup_config_map,
        },
        crd::{DruidRole, PROP_SEGMENT_CACHE_LOCATIONS},
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
