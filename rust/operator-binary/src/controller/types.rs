use stackable_druid_crd::{authentication::ResolvedAuthenticationClasses, DruidCluster};
use stackable_operator::{
    commons::{product_image_selection::ResolvedProductImage, s3::S3ConnectionSpec},
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Secret, Service},
    },
    role_utils::RoleGroupRef,
};

pub struct AdditionalData {
    pub opa_connstr: Option<String>,
    pub resolved_authentication_classes: ResolvedAuthenticationClasses,
    pub resolved_product_image: ResolvedProductImage,
    pub zk_connstr: String,
    pub s3_conn: Option<S3ConnectionSpec>,
    pub deep_storage_bucket_name: Option<String>,
}

pub enum AppliableClusterResource {
    RoleService(Service),
    DiscoveryConfigMap(ConfigMap),
    InternalSecret(Secret),
    RolegroupService(Service, RoleGroupRef<DruidCluster>),
    RolegroupConfigMap(ConfigMap, RoleGroupRef<DruidCluster>),
    RolegroupStatefulSet(StatefulSet, RoleGroupRef<DruidCluster>),
}
