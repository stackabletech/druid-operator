//! Router role groups.

use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::{memory::MemoryQuantity, v2::types::operator::RoleGroupName};

use super::{Error, HeapMemorySnafu, RoleGroupBuilder, RoleGroupInputs};
use crate::{
    controller::{
        build::{properties::runtime_properties, resource::listener::group_listener_name},
        validate::{RouterRoleGroupConfig, ValidatedCluster, ValidatedRouterConfig},
    },
    crd::{DruidRole, resource::heap_memory},
};

pub(crate) const ROLE: DruidRole = DruidRole::Router;

/// Resolves one Router role group into its [`RoleGroupBuilder`].
pub(crate) fn build<'a>(
    cluster: &'a ValidatedCluster,
    role_group_name: &RoleGroupName,
    rg_config: &RouterRoleGroupConfig,
) -> Result<RoleGroupBuilder<'a>, Error> {
    let ValidatedRouterConfig {
        resources,
        logging,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config;

    // Routers reserve 128 MiB of direct memory for their query processing buffers.
    let direct_memory = MemoryQuantity::from_mebi(128.);
    let heap = heap_memory(resources, Some(direct_memory)).context(HeapMemorySnafu)?;

    RoleGroupBuilder::new(RoleGroupInputs {
        cluster,
        role: ROLE,
        role_group_name: role_group_name.clone(),
        affinity: affinity.clone(),
        graceful_shutdown_timeout: *graceful_shutdown_timeout,
        requested_secret_lifetime: *requested_secret_lifetime,
        resources: resources.clone().into(),
        heap,
        direct_memory: Some(direct_memory),
        logging: logging.clone(),
        listener: Some(group_listener_name(&cluster.name, &ROLE)),
        role_pod_volumes: Vec::new(),
        role_druid_mounts: Vec::new(),
        resource_runtime_properties: BTreeMap::new(),
        indexer_java_opts: None,
        role_jvm_args: Vec::new(),
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
