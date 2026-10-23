use std::{str::FromStr, sync::LazyLock};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::pod::volume::VolumeBuilder,
    commons::resources::{
        CpuLimitsFragment, MemoryLimitsFragment, NoRuntimeLimits, NoRuntimeLimitsFragment,
        Resources, ResourcesFragment,
    },
    constant,
    k8s_openapi::{
        api::core::v1::{EmptyDirVolumeSource, Volume, VolumeMount},
        apimachinery::pkg::api::resource::Quantity,
    },
    memory::MemoryQuantity,
    v2::types::kubernetes::VolumeName,
};

use crate::crd::{
    memory::RESERVED_OS_MEMORY,
    storage::{self, FreePercentageEmptyDir, default_free_percentage_empty_dir_fragment},
};

const PATH_SEGMENT_CACHE: &str = "/stackable/var/druid/segment-cache";

// volume names
constant!(pub(crate) SEGMENT_CACHE_VOLUME_NAME: VolumeName = "segment-cache");

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to get memory limits"))]
    GetMemoryLimit,

    #[snafu(display("failed to parse memory quantity"))]
    ParseMemoryQuantity {
        source: stackable_operator::memory::Error,
    },
}

/// The heap size of a role whose JVM settings are not derived from its CPU: the memory limit
/// minus the OS reserve and minus the role's direct memory, if it has any.
pub fn heap_memory(
    resources: &Resources<storage::DruidStorage, NoRuntimeLimits>,
    direct_memory: Option<MemoryQuantity>,
) -> Result<MemoryQuantity, Error> {
    let total_memory = MemoryQuantity::try_from(
        resources
            .memory
            .limit
            .as_ref()
            .context(GetMemoryLimitSnafu)?,
    )
    .context(ParseMemoryQuantitySnafu)?;
    let heap_memory = total_memory - *RESERVED_OS_MEMORY;
    Ok(match direct_memory {
        Some(direct_memory) => heap_memory - direct_memory,
        None => heap_memory,
    })
}

/// The value of `druid.segmentCache.locations` for a Historical: its one segment cache location,
/// sized from the segment cache storage.
pub fn segment_cache_locations(segment_cache: &FreePercentageEmptyDir) -> String {
    let free_percentage = segment_cache.free_percentage.unwrap_or(5u16);
    let capacity = &segment_cache.empty_dir.capacity;
    format!(
        r#"[{{"path":"{path}","maxSize":"{max_size}","freeSpacePercent":"{free_space_percent}"}}]"#,
        path = PATH_SEGMENT_CACHE,
        max_size = capacity.0,
        free_space_percent = free_percentage,
    )
}

/// The segment cache volume of a Historical: an `emptyDir` sized from the segment cache storage.
pub fn segment_cache_volume(segment_cache: &FreePercentageEmptyDir) -> Volume {
    VolumeBuilder::new(&*SEGMENT_CACHE_VOLUME_NAME)
        .empty_dir(EmptyDirVolumeSource {
            medium: segment_cache.empty_dir.medium.clone(),
            size_limit: Some(segment_cache.empty_dir.capacity.clone()),
        })
        .build()
}

/// The `druid` container's mount of the segment cache volume.
pub fn segment_cache_volume_mount() -> VolumeMount {
    VolumeMount {
        name: SEGMENT_CACHE_VOLUME_NAME.to_string(),
        mount_path: PATH_SEGMENT_CACHE.to_string(),
        ..VolumeMount::default()
    }
}

pub(crate) static MIDDLE_MANAGER_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("300m".to_owned())),
        max: Some(Quantity("1200m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("1500Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

pub(crate) static BROKER_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("300m".to_owned())),
        max: Some(Quantity("1200m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("1500Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

pub(crate) static HISTORICAL_RESOURCES: LazyLock<
    ResourcesFragment<storage::HistoricalStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("300m".to_owned())),
        max: Some(Quantity("1200m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("1500Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::HistoricalStorageFragment {
        segment_cache: default_free_percentage_empty_dir_fragment(),
    },
});

pub(crate) static COORDINATOR_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("100m".to_owned())),
        max: Some(Quantity("400m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("768Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

pub(crate) static ROUTER_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("300m".to_owned())),
        max: Some(Quantity("1200m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("512Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rstest::*;
    use stackable_operator::{
        commons::resources::{
            CpuLimits, CpuLimitsFragment, MemoryLimits, MemoryLimitsFragment,
            NoRuntimeLimitsFragment,
        },
        config::{fragment, merge::Merge},
        k8s_openapi::apimachinery::pkg::api::resource::Quantity,
        utils::yaml_from_str_singleton_map,
        v2::types::operator::RoleGroupName,
    };

    use super::*;
    use crate::{
        controller::validate::test_support::validated_cluster,
        crd::{
            storage::{HistoricalStorage, default_free_percentage_empty_dir},
            v1alpha1,
        },
    };

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *SEGMENT_CACHE_VOLUME_NAME;
    }

    #[rstest]
    #[case(
        Some(ResourcesFragment{
            cpu: CpuLimitsFragment{
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment{
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment{},
            },
            storage: storage::HistoricalStorageFragment{
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        None,
        None,
        Resources{
            cpu: CpuLimits{
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits{
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits{},
            },
            storage: storage::HistoricalStorage{
                segment_cache: default_free_percentage_empty_dir(),
            },
        },
     )]
    #[case(
        Some(ResourcesFragment {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        Some(ResourcesFragment  {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment {},
            },
            storage: storage::HistoricalStorageFragment {
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        None,
        Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
                segment_cache: default_free_percentage_empty_dir(),
            },
        },
     )]
    #[case(
        Some(ResourcesFragment {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        Some(ResourcesFragment  {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        Some(ResourcesFragment  {
            cpu: CpuLimitsFragment {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: default_free_percentage_empty_dir_fragment(),
            },
        }),
        Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
                segment_cache: default_free_percentage_empty_dir(),
            },
        },
     )]
    fn test_try_merge_ok(
        #[case] first: Option<ResourcesFragment<HistoricalStorage>>,
        #[case] second: Option<ResourcesFragment<HistoricalStorage>>,
        #[case] third: Option<ResourcesFragment<HistoricalStorage>>,
        #[case] expected: Resources<HistoricalStorage>,
    ) {
        // Replicates the fragment merge done by `with_validated_config` /
        // `RoleGroup::validate_config`: default <- role <- role group, then validate.
        let mut role_config = second.unwrap_or_default();
        role_config.merge(&third.unwrap_or_default());
        let mut rolegroup_config = first.unwrap_or_default();
        rolegroup_config.merge(&role_config);
        let got = fragment::validate::<Resources<HistoricalStorage>>(rolegroup_config);

        assert_eq!(expected, got.unwrap());
    }

    #[test]
    fn test_resources() {
        let cluster: v1alpha1::DruidCluster = yaml_from_str_singleton_map(include_str!(
            "../../test/resources/crd/resource_merge/druid_cluster.yaml"
        ))
        .expect("failed to parse YAML");
        let validated = validated_cluster(&cluster);
        let middle_manager_resources = |role_group: &str| {
            &validated.middle_manager_role_group_configs
                [&RoleGroupName::from_str(role_group).expect("valid role group name")]
                .config
                .config
                .resources
        };

        assert_eq!(
            middle_manager_resources("resources-from-role-group"),
            &Resources {
                cpu: CpuLimits {
                    min: Some(Quantity("300m".to_owned())),
                    max: Some(Quantity("3".to_owned())),
                },
                memory: MemoryLimits {
                    limit: Some(Quantity("3Gi".to_owned())),
                    runtime_limits: NoRuntimeLimits {},
                },
                storage: storage::DruidStorage {},
            },
            "middlemanager resources from role group"
        );

        assert_eq!(
            middle_manager_resources("resources-from-role"),
            &Resources {
                cpu: CpuLimits {
                    min: Some(Quantity("100m".to_owned())),
                    max: Some(Quantity("1".to_owned())),
                },
                memory: MemoryLimits {
                    limit: Some(Quantity("1Gi".to_owned())),
                    runtime_limits: NoRuntimeLimits {},
                },
                storage: storage::DruidStorage {},
            },
            "resources from role"
        );
    }

    #[test]
    fn test_segment_cache() {
        let cluster: v1alpha1::DruidCluster = yaml_from_str_singleton_map(include_str!(
            "../../test/resources/crd/resource_merge/segment_cache.yaml"
        ))
        .expect("failed to parse YAML");
        let validated = validated_cluster(&cluster);
        let historical_segment_cache = |role_group: &str| {
            &validated.historical_role_group_configs
                [&RoleGroupName::from_str(role_group).expect("valid role group name")]
                .config
                .config
                .resources
                .storage
                .segment_cache
        };

        assert_eq!(
            segment_cache_locations(historical_segment_cache("default")),
            r#"[{"path":"/stackable/var/druid/segment-cache","maxSize":"5g","freeSpacePercent":"3"}]"#,
            "primary"
        );
        assert_eq!(
            segment_cache_locations(historical_segment_cache("secondary")),
            r#"[{"path":"/stackable/var/druid/segment-cache","maxSize":"2g","freeSpacePercent":"7"}]"#,
            "secondary"
        );
    }
}
