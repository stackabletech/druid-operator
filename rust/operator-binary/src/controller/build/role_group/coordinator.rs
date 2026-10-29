//! Coordinator role groups.

use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::v2::types::operator::RoleGroupName;

use super::{Error, HeapMemorySnafu, RoleGroupBuilder, RoleGroupInputs};
use crate::{
    controller::{
        build::{properties::runtime_properties, resource::listener::group_listener_name},
        validate::{CoordinatorRoleGroupConfig, ValidatedCluster, ValidatedCoordinatorConfig},
    },
    crd::{DruidRole, resource::heap_memory},
};

pub(crate) const ROLE: DruidRole = DruidRole::Coordinator;

/// The error log file of the Coordinator's embedded Derby, the default metadata store.
const DERBY_LOG_FILE: &str = "/stackable/var/druid/derby.log";

/// The JVM argument that points Derby's error log at [`DERBY_LOG_FILE`].
pub(crate) fn derby_log_jvm_argument() -> String {
    format!("-Dderby.stream.error.file={DERBY_LOG_FILE}")
}

/// Resolves one Coordinator role group into its [`RoleGroupBuilder`].
pub(crate) fn build<'a>(
    cluster: &'a ValidatedCluster,
    role_group_name: &RoleGroupName,
    rg_config: &CoordinatorRoleGroupConfig,
) -> Result<RoleGroupBuilder<'a>, Error> {
    let ValidatedCoordinatorConfig {
        resources,
        logging,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config;

    // The Coordinator needs no direct memory, so the whole allocatable memory is heap.
    let heap = heap_memory(resources, None).context(HeapMemorySnafu)?;

    RoleGroupBuilder::new(RoleGroupInputs {
        cluster,
        role: ROLE,
        role_group_name: role_group_name.clone(),
        affinity: affinity.clone(),
        graceful_shutdown_timeout: *graceful_shutdown_timeout,
        requested_secret_lifetime: *requested_secret_lifetime,
        resources: resources.clone().into(),
        heap,
        direct_memory: None,
        logging: logging.clone(),
        listener: Some(group_listener_name(&cluster.name, &ROLE)),
        role_pod_volumes: Vec::new(),
        role_druid_mounts: Vec::new(),
        resource_runtime_properties: BTreeMap::new(),
        indexer_java_opts: None,
        // The Coordinator's embedded Derby (the default metadata store) logs its errors to a file.
        role_jvm_args: vec![derby_log_jvm_argument()],
        druid_pre_stop: None,
        oidc_enabled: true,
        role_runtime_defaults: runtime_properties::defaults(&ROLE),
        replicas: rg_config.replicas,
        config_overrides: rg_config.config_overrides.clone(),
        env_overrides: rg_config.env_overrides.clone(),
        pod_overrides: rg_config.pod_overrides.clone(),
        jvm_argument_overrides: rg_config
            .product_specific_common_config
            .jvm_argument_overrides
            .clone(),
    })
}
