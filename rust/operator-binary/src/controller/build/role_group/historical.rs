//! Historical role groups.

use std::collections::BTreeMap;

use snafu::ResultExt;
use stackable_operator::v2::types::operator::RoleGroupName;

use super::{DeriveMemorySettingsSnafu, Error, RoleGroupBuilder, RoleGroupInputs};
use crate::{
    controller::{
        build::properties::runtime_properties,
        validate::{HistoricalRoleGroupConfig, ValidatedCluster, ValidatedHistoricalConfig},
    },
    crd::{
        DruidRole, PROP_SEGMENT_CACHE_LOCATIONS,
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
    let ValidatedHistoricalConfig {
        resources,
        logging,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config;

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
        requested_secret_lifetime: *requested_secret_lifetime,
        resources: resources.clone().into(),
        heap: derived_settings.heap_memory(),
        direct_memory: Some(derived_settings.direct_access_memory()),
        logging: logging.clone(),
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;
    use crate::controller::{
        build::properties::ConfigFileName,
        validate::test_support::{druid_from_yaml, validated_cluster},
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
        let druid = druid_from_yaml(&yaml);

        let cluster = validated_cluster(&druid);
        let role_group_name =
            RoleGroupName::from_str(tested_rolegroup_name).expect("valid role group name");

        // The segment cache property is derived from the merged resources of the role group and
        // rendered into runtime.properties.
        let druid_segment_cache_property = build(
            &cluster,
            &role_group_name,
            cluster
                .historical_role_group_configs
                .get(&role_group_name)
                .expect("the role group exists"),
        )
        .expect("the role group resolves")
        .config_map_data
        .get(&ConfigFileName::RuntimeProperties.to_string())
        .expect("runtime.properties is rendered")
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
