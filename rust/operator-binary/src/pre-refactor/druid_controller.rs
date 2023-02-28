//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::get_jvm_config,
    discovery::{self, build_discovery_configmaps},
    extensions::get_extension_list,
    internal_secret::{
        build_shared_internal_secret_name, create_shared_internal_secret, env_var_from_secret,
        ENV_INTERNAL_SECRET,
    },
    product_logging::{extend_role_group_config_map, resolve_vector_aggregator_address},
    OPERATOR_NAME,
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    authorization::DruidAuthorization,
    build_string_list,
    ldap::{
        DruidLdapSettings, PLACEHOLDER_INTERNAL_CLIENT_PASSWORD, PLACEHOLDER_LDAP_BIND_PASSWORD,
        PLACEHOLDER_LDAP_BIND_USER,
    },
    security::{resolve_authentication_classes, DruidTlsSecurity},
    CommonRoleGroupConfig, DeepStorageSpec, DruidCluster, DruidRole, APP_NAME,
    AUTH_AUTHORIZER_OPA_URI, CERTS_DIR, CREDENTIALS_SECRET_PROPERTY, DRUID_CONFIG_DIRECTORY,
    DS_BUCKET, EXTENSIONS_LOADLIST, HDFS_CONFIG_DIRECTORY, JVM_CONFIG, LOG_CONFIG_DIRECTORY,
    LOG_DIR, LOG_VOLUME_SIZE_IN_MIB, RUNTIME_PROPS, RW_CONFIG_DIRECTORY, S3_ENDPOINT_URL,
    S3_PATH_STYLE_ACCESS, S3_SECRET_DIR_NAME, ZOOKEEPER_CONNECTION_STRING,
};
use stackable_druid_crd::{build_recommended_labels, Container};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder,
    },
    cluster_resources::ClusterResources,
    commons::{
        opa::OpaApiVersion,
        product_image_selection::ResolvedProductImage,
        s3::{S3AccessStyle, S3ConnectionSpec},
        tls::{CaCert, TlsVerification},
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, EnvVar, Service, ServiceSpec},
        },
        apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        Resource,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    product_logging::{
        self,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
    role_utils::RoleGroupRef,
};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display(
        "failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display("failed to get valid S3 connection"))]
    GetS3Connection { source: stackable_druid_crd::Error },
    #[snafu(display("failed to get deep storage bucket"))]
    GetDeepStorageBucket {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },
    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("failed to format runtime properties"))]
    PropertiesWriteError {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("failed to build discovery ConfigMap"))]
    BuildDiscoveryConfig { source: discovery::Error },
    #[snafu(display("failed to apply discovery ConfigMap"))]
    ApplyDiscoveryConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "Druid does not support skipping the verification of the tls enabled S3 server"
    ))]
    S3TlsNoVerificationNotSupported,
    #[snafu(display("could not parse Druid role [{role}]"))]
    UnidentifiedDruidRole {
        source: strum::ParseError,
        role: String,
    },
    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: stackable_druid_crd::Error },
    #[snafu(display("invalid configuration"))]
    InvalidConfiguration { source: stackable_druid_crd::Error },
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to create container builder with name [{name}]"))]
    FailedContainerBuilderCreation {
        source: stackable_operator::error::Error,
        name: String,
    },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext {
        source: stackable_druid_crd::security::Error,
    },
    #[snafu(display("failed to get JVM config"))]
    GetJvmConfig { source: crate::config::Error },
    #[snafu(display("failed to derive Druid memory settings from resources"))]
    DeriveMemorySettings {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation {
        source: crate::internal_secret::Error,
    },
    #[snafu(display(
        "failed to access bind credentials although they are required for LDAP to work"
    ))]
    LdapBindCredentialsAreRequired,
    #[snafu(display("failed to resolve the Vector aggregator address"))]
    ResolveVectorAggregatorAddress {
        source: crate::product_logging::Error,
    },
    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },
}
