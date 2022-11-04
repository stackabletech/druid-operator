use crate::storage;
use lazy_static::lazy_static;
use snafu::Snafu;
use stackable_operator::{
    commons::resources::{CpuLimits, MemoryLimits, NoRuntimeLimits, Resources},
    config::merge::Merge,
    k8s_openapi::{
        api::core::v1::ResourceRequirements, apimachinery::pkg::api::resource::Quantity,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

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
            Self::Druid(r) => r.clone().memory,
            Self::Historical(r) => r.clone().memory,
        }
    }
}

#[derive(Snafu, Debug, EnumDiscriminants, PartialEq, Eq)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("no resources available for merging"))]
    NoResourcesToMerge,
    #[snafu(display("cannot merge storage types of different roles"))]
    IncompatibleStorageMerging,
}

/// Merge resources from beginning to end of the array: element 0 > element 1 > element 2.
/// Return a copy of the merged struct.
pub fn try_merge(resources: &[Option<RoleResource>]) -> Result<RoleResource, Error> {
    let mut resources = resources.iter().flatten();
    let mut result = resources.next().ok_or(Error::NoResourcesToMerge)?.clone();

    for resource in resources {
        try_merge_private(&mut result, resource)?;
    }

    Ok(result)
}

/// Merges `rb` into `ra`, i.e. `ra` has precedence over `rb`.
fn try_merge_private(ra: &mut RoleResource, rb: &RoleResource) -> Result<RoleResource, Error> {
    match (ra, rb) {
        (RoleResource::Druid(a), RoleResource::Druid(b)) => {
            a.merge(b);
            Ok(RoleResource::Druid(a.clone()))
        }
        (RoleResource::Historical(a), RoleResource::Historical(b)) => {
            a.merge(b);
            Ok(RoleResource::Historical(a.clone()))
        }
        _ => Err(Error::IncompatibleStorageMerging),
    }
}

lazy_static! {
    pub static ref DEFAULT_RESOURCES: Resources<storage::DruidStorage, NoRuntimeLimits> =
        Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::DruidStorage {},
        };
    pub static ref HISTORICAL_RESOURCES: Resources<storage::HistoricalStorage, NoRuntimeLimits> =
        Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {},
        };
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        None,
        None,
        Ok(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
     )]
    #[case(
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        None,
        Ok(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
     )]
    #[case(
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        Ok(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
     )]
    #[case(
        Some(RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
            },
        })),
        Some(RoleResource::Druid(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::DruidStorage { },
        })),
        None,
        Err(Error::IncompatibleStorageMerging),
     )]
    #[case(None, None, None, Err(Error::NoResourcesToMerge))]
    pub fn test_try_merge(
        #[case] first: Option<RoleResource>,
        #[case] second: Option<RoleResource>,
        #[case] third: Option<RoleResource>,
        #[case] expected: Result<RoleResource, Error>,
    ) {
        let got = try_merge(&[first, second, third]);

        assert_eq!(expected, got);
    }
}
