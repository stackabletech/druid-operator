use crate::storage;
use lazy_static::lazy_static;
use snafu::Snafu;
use stackable_operator::{
    commons::resources::{CpuLimits, MemoryLimits, NoRuntimeLimits, PvcConfig, Resources},
    config::merge::Merge,
    k8s_openapi::{
        api::core::v1::ResourceRequirements, apimachinery::pkg::api::resource::Quantity,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Debug, Clone)]
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

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to merge resources"))]
    ResourceMergeFailure,
}

/// Merge resources from left to right: first > second > third.
/// Return a copy of the merged struct.
pub fn merge(
    first: Option<&mut RoleResourceEnum>,
    second: Option<&mut RoleResourceEnum>,
    third: Option<&mut RoleResourceEnum>,
) -> Result<RoleResourceEnum, Error> {
    let some = [first, second, third]
        .into_iter()
        .flatten()
        .collect::<Vec<&mut RoleResourceEnum>>();

    match some.len() {
        1 => Ok(some[0].clone()),
        2 => {
            let mut tmp = some[0].clone();
            maybe_merge(&mut tmp, some[1])
        }
        3 => {
            let mut tmp = some[0].clone();
            tmp = maybe_merge(&mut tmp, some[1])?;
            maybe_merge(&mut tmp, some[2])
        }
        _ => Err(Error::ResourceMergeFailure),
    }
}

fn maybe_merge(
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
        _ => Err(Error::ResourceMergeFailure),
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
            storage: storage::HistoricalStorage {
                segment_cache: PvcConfig {
                    capacity: Some(Quantity("1g".to_string())),
                    storage_class: None,
                    selectors: None,
                },
            },
        };
}
