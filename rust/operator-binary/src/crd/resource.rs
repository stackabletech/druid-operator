use std::{collections::BTreeMap, sync::LazyLock};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder,
    builder::pod::{container::ContainerBuilder, volume::VolumeBuilder, PodBuilder},
    commons::resources::{
        CpuLimitsFragment, MemoryLimits, MemoryLimitsFragment, NoRuntimeLimits,
        NoRuntimeLimitsFragment, Resources, ResourcesFragment,
    },
    k8s_openapi::{
        api::core::v1::{EmptyDirVolumeSource, ResourceRequirements},
        apimachinery::pkg::api::resource::Quantity,
    },
    memory::MemoryQuantity,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::crd::{
    memory::{HistoricalDerivedSettings, RESERVED_OS_MEMORY},
    storage::{self, default_free_percentage_empty_dir_fragment},
    DruidRole, PATH_SEGMENT_CACHE, PROP_SEGMENT_CACHE_LOCATIONS,
};

// volume names
const SEGMENT_CACHE_VOLUME_NAME: &str = "segment-cache";

/// This Error cannot derive PartialEq because fragment::ValidationError doesn't derive it
#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to derive Druid settings from resources"))]
    DeriveMemorySettings { source: crate::crd::memory::Error },

    #[snafu(display("failed to get memory limits"))]
    GetMemoryLimit,

    #[snafu(display("failed to parse memory quantity"))]
    ParseMemoryQuantity {
        source: stackable_operator::memory::Error,
    },

    #[snafu(display("the operator produced an internally inconsistent state"))]
    InconsistentConfiguration,

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoleResource {
    Druid(Resources<storage::DruidStorage, NoRuntimeLimits>),
    Historical(Resources<storage::HistoricalStorage, NoRuntimeLimits>),
}

impl RoleResource {
    pub fn as_resource_requirements(&self) -> ResourceRequirements {
        match self {
            Self::Druid(r) => r.clone().into(),
            Self::Historical(r) => r.clone().into(),
        }
    }

    pub fn as_memory_limits(&self) -> MemoryLimits<NoRuntimeLimits> {
        match self {
            Self::Druid(r) => r.memory.clone(),
            Self::Historical(r) => r.memory.clone(),
        }
    }

    /// Update the given configuration file with resource properties.
    /// Currently it only adds historical-specific configs for direct memory buffers, thread counts and segment cache.
    pub fn update_druid_config_file(
        &self,
        config: &mut BTreeMap<String, Option<String>>,
    ) -> Result<(), Error> {
        match self {
            Self::Historical(r) => {
                let free_percentage = r.storage.segment_cache.free_percentage.unwrap_or(5u16);
                let capacity = &r.storage.segment_cache.empty_dir.capacity;
                config
                    .entry(PROP_SEGMENT_CACHE_LOCATIONS.to_string())
                    .or_insert_with(|| {
                        Some(format!(
                            r#"[{{"path":"{}","maxSize":"{}","freeSpacePercent":"{}"}}]"#,
                            PATH_SEGMENT_CACHE, capacity.0, free_percentage
                        ))
                    });

                let settings =
                    HistoricalDerivedSettings::try_from(r).context(DeriveMemorySettingsSnafu)?;
                settings.add_settings(config);
            }
            Self::Druid(_) => (),
        }
        Ok(())
    }

    pub fn update_volumes_and_volume_mounts(
        &self,
        cb: &mut ContainerBuilder,
        pb: &mut PodBuilder,
    ) -> Result<(), Error> {
        if let Self::Historical(r) = self {
            cb.add_volume_mount(SEGMENT_CACHE_VOLUME_NAME, PATH_SEGMENT_CACHE)
                .context(AddVolumeMountSnafu)?;
            pb.add_volume(
                VolumeBuilder::new(SEGMENT_CACHE_VOLUME_NAME)
                    .empty_dir(EmptyDirVolumeSource {
                        medium: r.storage.segment_cache.empty_dir.medium.clone(),
                        size_limit: Some(r.storage.segment_cache.empty_dir.capacity.clone()),
                    })
                    .build(),
            )
            .context(AddVolumeSnafu)?;
        }

        Ok(())
    }

    /// Computes the heap and direct access memory sizes per role. The settings can be used to configure
    /// the JVM accordingly. The direct memory size is an [`Option`] because not all roles require
    /// direct access memory.
    pub fn get_memory_sizes(
        &self,
        role: &DruidRole,
    ) -> Result<(MemoryQuantity, Option<MemoryQuantity>), Error> {
        match self {
            Self::Historical(r) => {
                let settings =
                    HistoricalDerivedSettings::try_from(r).context(DeriveMemorySettingsSnafu)?;
                Ok((
                    settings.heap_memory(),
                    Some(settings.direct_access_memory()),
                ))
            }
            Self::Druid(r) => {
                let total_memory =
                    MemoryQuantity::try_from(r.memory.limit.as_ref().context(GetMemoryLimitSnafu)?)
                        .context(ParseMemoryQuantitySnafu)?;
                match role {
                    DruidRole::Historical => Err(Error::InconsistentConfiguration),
                    DruidRole::Coordinator => {
                        // The coordinator needs no direct memory
                        let heap_memory = total_memory - *RESERVED_OS_MEMORY;
                        Ok((heap_memory, None))
                    }
                    DruidRole::Broker => {
                        let direct_memory = MemoryQuantity::from_mebi(400.);
                        let heap_memory = total_memory - *RESERVED_OS_MEMORY - direct_memory;
                        Ok((heap_memory, Some(direct_memory)))
                    }
                    DruidRole::MiddleManager => {
                        // The middle manager needs no direct memory
                        let heap_memory = total_memory - *RESERVED_OS_MEMORY;
                        Ok((heap_memory, None))
                    }
                    DruidRole::Router => {
                        let direct_memory = MemoryQuantity::from_mebi(128.);
                        let heap_memory = total_memory - *RESERVED_OS_MEMORY - direct_memory;
                        Ok((heap_memory, Some(direct_memory)))
                    }
                }
            }
        }
    }
}

pub static MIDDLE_MANAGER_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("300m".to_owned())),
        max: Some(Quantity("1200m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("1Gi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

pub static BROKER_RESOURCES: LazyLock<ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>> =
    LazyLock::new(|| ResourcesFragment {
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

pub static HISTORICAL_RESOURCES: LazyLock<
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

pub static COORDINATOR_RESOURCES: LazyLock<
    ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>,
> = LazyLock::new(|| ResourcesFragment {
    cpu: CpuLimitsFragment {
        min: Some(Quantity("100m".to_owned())),
        max: Some(Quantity("400m".to_owned())),
    },
    memory: MemoryLimitsFragment {
        limit: Some(Quantity("512Mi".to_owned())),
        runtime_limits: NoRuntimeLimitsFragment {},
    },
    storage: storage::DruidStorageFragment {},
});

pub static ROUTER_RESOURCES: LazyLock<ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>> =
    LazyLock::new(|| ResourcesFragment {
        cpu: CpuLimitsFragment {
            min: Some(Quantity("100m".to_owned())),
            max: Some(Quantity("400m".to_owned())),
        },
        memory: MemoryLimitsFragment {
            limit: Some(Quantity("512Mi".to_owned())),
            runtime_limits: NoRuntimeLimitsFragment {},
        },
        storage: storage::DruidStorageFragment {},
    });

#[cfg(test)]
mod test {
    use rstest::*;
    use stackable_operator::{
        commons::resources::{
            CpuLimits, CpuLimitsFragment, MemoryLimits, MemoryLimitsFragment,
            NoRuntimeLimitsFragment,
        },
        k8s_openapi::apimachinery::pkg::api::resource::Quantity,
        role_utils::{CommonConfiguration, RoleGroup},
    };

    use super::*;
    use crate::crd::{
        storage::{default_free_percentage_empty_dir, HistoricalStorage},
        tests::deserialize_yaml_file,
        v1alpha1, MiddleManagerConfig,
    };

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
        let got = v1alpha1::DruidCluster::merged_rolegroup_config(
            &first.unwrap_or_default(),
            &second.unwrap_or_default(),
            &third.unwrap_or_default(),
        );

        assert_eq!(expected, got.unwrap());
    }

    #[test]
    fn test_resources() -> Result<(), Error> {
        let cluster = deserialize_yaml_file::<v1alpha1::DruidCluster>(
            "test/resources/crd/resource_merge/druid_cluster.yaml",
        );

        let config = cluster.merged_config().unwrap();
        if let Some(RoleGroup {
            config:
                CommonConfiguration {
                    config:
                        MiddleManagerConfig {
                            resources: middlemanager_resources_from_rg,
                            ..
                        },
                    ..
                },
            ..
        }) = config.middle_managers.get("resources-from-role-group")
        {
            let expected = Resources {
                cpu: CpuLimits {
                    min: Some(Quantity("300m".to_owned())),
                    max: Some(Quantity("3".to_owned())),
                },
                memory: MemoryLimits {
                    limit: Some(Quantity("3Gi".to_owned())),
                    runtime_limits: NoRuntimeLimits {},
                },
                storage: storage::DruidStorage {},
            };

            assert_eq!(
                middlemanager_resources_from_rg, &expected,
                "middlemanager resources from role group"
            );
        } else {
            panic!("No role group named [resources-from-role-group] found");
        }

        if let Some(RoleGroup {
            config:
                CommonConfiguration {
                    config:
                        MiddleManagerConfig {
                            resources: middlemanager_resources_from_rg,
                            ..
                        },
                    ..
                },
            ..
        }) = config.middle_managers.get("resources-from-role")
        {
            let expected = Resources {
                cpu: CpuLimits {
                    min: Some(Quantity("100m".to_owned())),
                    max: Some(Quantity("1".to_owned())),
                },
                memory: MemoryLimits {
                    limit: Some(Quantity("1Gi".to_owned())),
                    runtime_limits: NoRuntimeLimits {},
                },
                storage: storage::DruidStorage {},
            };

            assert_eq!(
                middlemanager_resources_from_rg, &expected,
                "resources from role"
            );
        } else {
            panic!("No role group named [resources-from-role] found");
        }

        Ok(())
    }

    #[test]
    fn test_segment_cache() -> Result<(), Error> {
        let cluster = deserialize_yaml_file::<v1alpha1::DruidCluster>(
            "test/resources/crd/resource_merge/segment_cache.yaml",
        );

        // ---------- default role group
        let config = cluster.merged_config().unwrap();
        let res = config
            .common_config(&DruidRole::Historical, "default")
            .unwrap()
            .resources;
        let mut got = BTreeMap::new();

        assert!(res.update_druid_config_file(&mut got).is_ok());
        assert!(got.contains_key(PROP_SEGMENT_CACHE_LOCATIONS));

        let value = got.get(PROP_SEGMENT_CACHE_LOCATIONS).unwrap();
        let expected = Some(r#"[{"path":"/stackable/var/druid/segment-cache","maxSize":"5g","freeSpacePercent":"3"}]"#.to_string());
        assert_eq!(value, &expected, "primary");

        // ---------- secondary role group
        let res = config
            .common_config(&DruidRole::Historical, "secondary")
            .unwrap()
            .resources;
        let mut got = BTreeMap::new();

        assert!(res.update_druid_config_file(&mut got).is_ok());
        assert!(got.contains_key(PROP_SEGMENT_CACHE_LOCATIONS));

        let value = got.get(PROP_SEGMENT_CACHE_LOCATIONS).unwrap();
        let expected = Some(r#"[{"path":"/stackable/var/druid/segment-cache","maxSize":"2g","freeSpacePercent":"7"}]"#.to_string());
        assert_eq!(value, &expected, "secondary");

        Ok(())
    }
}
