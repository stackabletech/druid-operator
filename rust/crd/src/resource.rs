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
pub enum RoleResourceEnum {
    Druid(Resources<storage::DruidStorage, NoRuntimeLimits>),
    Historical(Resources<storage::HistoricalStorage, NoRuntimeLimits>),
}

impl RoleResourceEnum {
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

/// Merge resources from left to right: first > second > third.
/// Return a copy of the merged struct.
pub fn try_merge(
    first: Option<&mut RoleResourceEnum>,
    second: Option<&mut RoleResourceEnum>,
    third: Option<&mut RoleResourceEnum>,
) -> Result<RoleResourceEnum, Error> {
    let mut some = [first, second, third]
        .into_iter()
        .flatten()
        .collect::<Vec<&mut RoleResourceEnum>>();

    match some.len() {
        1 => Ok(some[0].clone()),
        2 => {
            let tmp = some[0].clone();
            try_merge_private(some[1], &tmp)
        }
        3 => {
            let mut tmp = some[0].clone();
            tmp = try_merge_private(some[1], &tmp)?;
            try_merge_private(some[2], &tmp)
        }
        _ => Err(Error::NoResourcesToMerge),
    }
}

/// Merges `rb` into `ra`, i.e. `ra` has precedence over `rb`.
fn try_merge_private(
    ra: &mut RoleResourceEnum,
    rb: &RoleResourceEnum,
) -> Result<RoleResourceEnum, Error> {
    match (ra, rb) {
        (RoleResourceEnum::Druid(a), RoleResourceEnum::Druid(b)) => {
            a.merge(b);
            Ok(RoleResourceEnum::Druid(a.clone()))
        }
        (RoleResourceEnum::Historical(a), RoleResourceEnum::Historical(b)) => {
            a.merge(b);
            Ok(RoleResourceEnum::Historical(a.clone()))
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Ok(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Ok(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Ok(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Historical(Resources {
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
        Some(RoleResourceEnum::Druid(Resources {
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
        #[case] mut first: Option<RoleResourceEnum>,
        #[case] mut second: Option<RoleResourceEnum>,
        #[case] mut third: Option<RoleResourceEnum>,
        #[case] expected: Result<RoleResourceEnum, Error>,
    ) {
        let got = try_merge(first.as_mut(), second.as_mut(), third.as_mut());

        assert_eq!(expected, got);
    }
}
