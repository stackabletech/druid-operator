use crate::storage::{self, FreePercentageEmptyDirFragment};
use crate::{DruidCluster, DruidRole};
use lazy_static::lazy_static;
use snafu::{ResultExt, Snafu};
use stackable_operator::config::fragment;
use stackable_operator::role_utils::RoleGroupRef;
use stackable_operator::{
    commons::resources::{
        CpuLimitsFragment, MemoryLimits, MemoryLimitsFragment, NoRuntimeLimits,
        NoRuntimeLimitsFragment, Resources, ResourcesFragment,
    },
    config::merge::Merge,
    k8s_openapi::{
        api::core::v1::ResourceRequirements, apimachinery::pkg::api::resource::Quantity,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

/// This Error cannot derive PartialEq because fragment::ValidationError doesn't derive it
#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("no resources available for merging"))]
    NoResourcesToMerge,
    #[snafu(display("cannot merge storage types of different roles"))]
    IncompatibleStorageMerging,
    #[snafu(display("failed to validate resources"))]
    ResourceValidation { source: fragment::ValidationError },
    #[snafu(display("failed to merge resources for {rolegroup_ref}"))]
    ResourcesMerge {
        #[snafu(source(from(Error, Box::new)))]
        source: Box<Error>,
        rolegroup_ref: RoleGroupRef<DruidCluster>,
    },
}

/// The sole purpose of this enum is to handle merging. It's needed because currently
/// the operator-rs 0.26.1 doesn't handle fragment enum merging.
#[derive(Debug, Clone, PartialEq)]
enum RoleResourceFragment {
    DruidFragment(ResourcesFragment<storage::DruidStorage, NoRuntimeLimits>),
    HistoricalFragment(ResourcesFragment<storage::HistoricalStorage, NoRuntimeLimits>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoleResource {
    Druid(Resources<storage::DruidStorage, NoRuntimeLimits>),
    Historical(Resources<storage::HistoricalStorage, NoRuntimeLimits>),
}

impl TryFrom<RoleResourceFragment> for RoleResource {
    type Error = Error;
    fn try_from(rrf: RoleResourceFragment) -> Result<Self, Error> {
        match rrf {
            RoleResourceFragment::DruidFragment(fragment) => Ok(RoleResource::Druid(
                fragment::validate(fragment).with_context(|_| ResourceValidationSnafu)?,
            )),
            RoleResourceFragment::HistoricalFragment(fragment) => Ok(RoleResource::Historical(
                fragment::validate(fragment).with_context(|_| ResourceValidationSnafu)?,
            )),
        }
    }
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

lazy_static! {
    pub static ref DEFAULT_RESOURCES: ResourcesFragment<storage::DruidStorage, NoRuntimeLimits> =
        ResourcesFragment {
            cpu: CpuLimitsFragment {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment {},
            },
            storage: storage::DruidStorageFragment {},
        };
    pub static ref HISTORICAL_RESOURCES: ResourcesFragment<storage::HistoricalStorage, NoRuntimeLimits> =
        ResourcesFragment {
            cpu: CpuLimitsFragment {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment {},
            },
            storage: storage::HistoricalStorageFragment {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        };
}

fn default_resources(role: &DruidRole) -> Option<RoleResourceFragment> {
    match role {
        DruidRole::Historical => Some(RoleResourceFragment::HistoricalFragment(
            HISTORICAL_RESOURCES.clone(),
        )),
        _ => Some(RoleResourceFragment::DruidFragment(
            DEFAULT_RESOURCES.clone(),
        )),
    }
}

fn role_resources(druid: &DruidCluster, role: &DruidRole) -> Option<RoleResourceFragment> {
    match role {
        DruidRole::Broker => druid
            .spec
            .brokers
            .config
            .config
            .resources
            .clone()
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::Coordinator => druid
            .spec
            .coordinators
            .config
            .config
            .resources
            .clone()
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::Historical => druid
            .spec
            .historicals
            .config
            .config
            .resources
            .clone()
            .map(RoleResourceFragment::HistoricalFragment),
        DruidRole::MiddleManager => druid
            .spec
            .middle_managers
            .config
            .config
            .resources
            .clone()
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::Router => druid
            .spec
            .routers
            .config
            .config
            .resources
            .clone()
            .map(RoleResourceFragment::DruidFragment),
    }
}

fn rolegroup_resources(
    druid: &DruidCluster,
    role: &DruidRole,
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
) -> Option<RoleResourceFragment> {
    match role {
        DruidRole::Broker => druid
            .spec
            .brokers
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| &rg.config.config)
            .and_then(|rg| rg.resources.clone())
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::Coordinator => druid
            .spec
            .coordinators
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| &rg.config.config)
            .and_then(|rg| rg.resources.clone())
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::MiddleManager => druid
            .spec
            .middle_managers
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| &rg.config.config)
            .and_then(|rg| rg.resources.clone())
            .map(RoleResourceFragment::DruidFragment),
        DruidRole::Historical => druid
            .spec
            .historicals
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| &rg.config.config)
            .and_then(|rg| rg.resources.clone())
            .map(RoleResourceFragment::HistoricalFragment),
        DruidRole::Router => druid
            .spec
            .routers
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| &rg.config.config)
            .and_then(|rg| rg.resources.clone())
            .map(RoleResourceFragment::DruidFragment),
    }
}

/// Retrieve and merge resource configs for role and role groups
pub fn resources(
    druid: &DruidCluster,
    role: &DruidRole,
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
) -> Result<RoleResource, Error> {
    try_merge(&[
        rolegroup_resources(druid, role, rolegroup_ref),
        role_resources(druid, role),
        default_resources(role),
    ])
    .with_context(|_| ResourcesMergeSnafu {
        rolegroup_ref: rolegroup_ref.clone(),
    })
}

/// Merge resources from beginning to end of the array: element 0 > element 1 > element 2.
/// Return a copy of the merged struct.
fn try_merge(resources: &[Option<RoleResourceFragment>]) -> Result<RoleResource, Error> {
    let mut resources = resources.iter().flatten();
    let mut result = resources.next().ok_or(Error::NoResourcesToMerge)?.clone();

    for resource in resources {
        try_merge_private(&mut result, resource)?;
    }

    RoleResource::try_from(result)
}

/// Merges `rb` into `ra`, i.e. `ra` has precedence over `rb`.
fn try_merge_private(
    ra: &mut RoleResourceFragment,
    rb: &RoleResourceFragment,
) -> Result<RoleResourceFragment, Error> {
    match (ra, rb) {
        (RoleResourceFragment::DruidFragment(a), RoleResourceFragment::DruidFragment(b)) => {
            a.merge(b);
            let _: Resources<storage::DruidStorage, NoRuntimeLimits> =
                fragment::validate(a.clone()).context(ResourceValidationSnafu)?;
            Ok(RoleResourceFragment::DruidFragment(a.clone()))
        }
        (
            RoleResourceFragment::HistoricalFragment(a),
            RoleResourceFragment::HistoricalFragment(b),
        ) => {
            a.merge(b);
            let _: Resources<storage::HistoricalStorage, NoRuntimeLimits> =
                fragment::validate(a.clone()).context(ResourceValidationSnafu)?;
            Ok(RoleResourceFragment::HistoricalFragment(a.clone()))
        }
        _ => Err(Error::IncompatibleStorageMerging),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::FreePercentageEmptyDir;

    use rstest::*;
    use stackable_operator::{
        commons::resources::{
            CpuLimits, CpuLimitsFragment, MemoryLimits, MemoryLimitsFragment,
            NoRuntimeLimitsFragment,
        },
        k8s_openapi::apimachinery::pkg::api::resource::Quantity,
        kube::runtime::reflector::ObjectRef,
    };

    #[rstest]
    #[case(
        Some(RoleResourceFragment::HistoricalFragment(ResourcesFragment{
            cpu: CpuLimitsFragment{
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment{
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment{},
            },
            storage: storage::HistoricalStorageFragment{
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        None,
        None,
        RoleResource::Historical(Resources{
            cpu: CpuLimits{
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits{
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits{},
            },
            storage: storage::HistoricalStorage{
                segment_cache: FreePercentageEmptyDir::default(),
            },
        }),
     )]
    #[case(
        Some(RoleResourceFragment::HistoricalFragment(ResourcesFragment {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        Some(RoleResourceFragment::HistoricalFragment(ResourcesFragment  {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment {},
            },
            storage: storage::HistoricalStorageFragment {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        None,
        RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
                segment_cache: FreePercentageEmptyDir::default(),
            },
        }),
     )]
    #[case(
        Some(RoleResourceFragment::HistoricalFragment(ResourcesFragment {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        Some(RoleResourceFragment::HistoricalFragment (ResourcesFragment  {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        Some(RoleResourceFragment::HistoricalFragment (ResourcesFragment  {
            cpu: CpuLimitsFragment {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        RoleResource::Historical(Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: storage::HistoricalStorage {
                segment_cache: FreePercentageEmptyDir::default(),
            },
        }),
     )]
    fn test_try_merge_ok(
        #[case] first: Option<RoleResourceFragment>,
        #[case] second: Option<RoleResourceFragment>,
        #[case] third: Option<RoleResourceFragment>,
        #[case] expected: RoleResource,
    ) {
        let got = try_merge(&[first, second, third]);

        assert_eq!(expected, got.unwrap());
    }

    #[rstest]
    #[case(
        Some(RoleResourceFragment::HistoricalFragment(ResourcesFragment {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment  {},
            },
            storage: storage::HistoricalStorageFragment  {
                segment_cache: FreePercentageEmptyDirFragment::default(),
            },
        })),
        Some(RoleResourceFragment ::DruidFragment (ResourcesFragment  {
            cpu: CpuLimitsFragment  {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimitsFragment  {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimitsFragment {},
            },
            storage: storage::DruidStorageFragment  { },
        })),
        None,
        Error::IncompatibleStorageMerging,
     )]
    #[case(None, None, None, Error::NoResourcesToMerge)]
    fn test_try_merge_err(
        #[case] first: Option<RoleResourceFragment>,
        #[case] second: Option<RoleResourceFragment>,
        #[case] third: Option<RoleResourceFragment>,
        #[case] expected: Error,
    ) {
        let got = try_merge(&[first, second, third]);

        // Poor man's assert_eq since Error cannot derive PartialEq
        match (expected, got.err().unwrap()) {
            (Error::IncompatibleStorageMerging, Error::IncompatibleStorageMerging) => (),
            (Error::NoResourcesToMerge, Error::NoResourcesToMerge) => (),
            _ => panic!("something went wrong here"),
        }
    }

    #[test]
    fn test_resources() -> Result<(), Error> {
        let cluster_cr =
            std::fs::File::open("test/resources/resource_merge/druid_cluster.yaml").unwrap();
        let cluster: DruidCluster = serde_yaml::from_reader(&cluster_cr).unwrap();

        let resources_from_role_group = RoleGroupRef {
            cluster: ObjectRef::from_obj(&cluster),
            role: "middle_managers".into(),
            role_group: "resources-from-role-group".into(),
        };
        if let RoleResource::Druid(middlemanager_resources_from_rg) = resources(
            &cluster,
            &DruidRole::MiddleManager,
            &resources_from_role_group,
        )? {
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

            assert_eq!(middlemanager_resources_from_rg, expected);
        } else {
            panic!("No role group named [resources-from-role-group] found");
        }

        let resources_from_role = RoleGroupRef {
            cluster: ObjectRef::from_obj(&cluster),
            role: "middle_managers".into(),
            role_group: "resources-from-role".into(),
        };
        if let RoleResource::Druid(middlemanager_resources_from_rg) =
            resources(&cluster, &DruidRole::MiddleManager, &resources_from_role)?
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

            assert_eq!(middlemanager_resources_from_rg, expected);
        } else {
            panic!("No role group named [resources-from-role] found");
        }

        Ok(())
    }
}
