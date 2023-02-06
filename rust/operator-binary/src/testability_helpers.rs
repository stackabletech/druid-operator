use stackable_druid_crd::DruidCluster;
use stackable_operator::{
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Secret, Service},
    },
    role_utils::RoleGroupRef,
};

pub enum AppliableClusterResource {
    RoleService(Service),
    DiscoveryConfigMap(ConfigMap),
    InternalSecret(Secret),
    RolegroupService(Service, RoleGroupRef<DruidCluster>),
    RolegroupConfigMap(ConfigMap, RoleGroupRef<DruidCluster>),
    RolegroupStatefulSet(StatefulSet, RoleGroupRef<DruidCluster>),
}
