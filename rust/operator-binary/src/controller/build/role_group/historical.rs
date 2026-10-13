//! Historical role groups.

use std::collections::BTreeMap;

use snafu::{OptionExt, ResultExt};
use stackable_operator::v2::types::operator::RoleGroupName;

use super::{
    DeriveMemorySettingsSnafu, Error, MissingSecretLifetimeSnafu, RoleGroupBuilder, RoleGroupInputs,
};
use crate::{
    controller::{
        build::properties::runtime_properties,
        validate::{HistoricalRoleGroupConfig, ValidatedCluster},
    },
    crd::{
        DruidRole, HistoricalConfig, PROP_SEGMENT_CACHE_LOCATIONS,
        memory::HistoricalDerivedSettings,
        resource::{segment_cache_locations, segment_cache_volume, segment_cache_volume_mount},
    },
};

pub(crate) const ROLE: DruidRole = DruidRole::Historical;

/// Resolves one Historical role group into its [`RoleGroupBuilder`].
///
/// Historicals are the one role whose JVM memory and `runtime.properties` processing settings
/// are derived from the resources, and the one role with a segment cache volume.
pub(crate) fn build<'a>(
    cluster: &'a ValidatedCluster,
    role_group_name: &RoleGroupName,
    rg_config: &HistoricalRoleGroupConfig,
) -> Result<RoleGroupBuilder<'a>, Error> {
    let HistoricalConfig {
        resources,
        // Validated up front into `rg_config.config.logging`.
        logging: _,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config.config;

    let derived_settings =
        HistoricalDerivedSettings::try_from(resources).context(DeriveMemorySettingsSnafu)?;

    let segment_cache = &resources.storage.segment_cache;
    let mut resource_runtime_properties = BTreeMap::new();
    resource_runtime_properties.insert(
        PROP_SEGMENT_CACHE_LOCATIONS.to_string(),
        segment_cache_locations(segment_cache),
    );
    derived_settings.add_settings(&mut resource_runtime_properties);

    RoleGroupBuilder::new(RoleGroupInputs {
        cluster,
        role: ROLE,
        role_group_name: role_group_name.clone(),
        affinity: affinity.clone(),
        graceful_shutdown_timeout: *graceful_shutdown_timeout,
        requested_secret_lifetime: requested_secret_lifetime.context(MissingSecretLifetimeSnafu)?,
        resources: resources.clone().into(),
        heap: derived_settings.heap_memory(),
        direct_memory: Some(derived_settings.direct_access_memory()),
        logging: rg_config.config.logging.clone(),
        listener: None,
        role_pod_volumes: vec![segment_cache_volume(segment_cache)],
        role_druid_mounts: vec![segment_cache_volume_mount()],
        resource_runtime_properties,
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
