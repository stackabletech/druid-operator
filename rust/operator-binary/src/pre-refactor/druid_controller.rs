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

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(druid: Arc<DruidCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");
    let client = &ctx.client;
    let namespace = &druid
        .metadata
        .namespace
        .clone()
        .with_context(|| ObjectHasNoNamespaceSnafu {})?;
    let resolved_product_image: ResolvedProductImage =
        druid.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);

    let zk_confmap = druid.spec.cluster_config.zookeeper_config_map_name.clone();
    let zk_connstr = client
        .get::<ConfigMap>(&zk_confmap, namespace)
        .await
        .context(GetZookeeperConnStringConfigMapSnafu {
            cm_name: zk_confmap.clone(),
        })?
        .data
        .and_then(|mut data| data.remove("ZOOKEEPER"))
        .context(MissingZookeeperConnStringSnafu {
            cm_name: zk_confmap.clone(),
        })?;

    let vector_aggregator_address = resolve_vector_aggregator_address(&druid, client)
        .await
        .context(ResolveVectorAggregatorAddressSnafu)?;

    // Assemble the OPA connection string from the discovery and the given path, if a spec is given.
    let opa_connstr = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(
                    client,
                    druid.deref(),
                    Some("allow"),
                    OpaApiVersion::V1,
                )
                .await
                .context(GetOpaConnStringSnafu {
                    cm_name: opa_config.config_map_name.clone(),
                })?,
        )
    } else {
        None
    };

    // Get the s3 connection if one is defined
    let s3_conn = druid
        .get_s3_connection(client)
        .await
        .context(GetS3ConnectionSnafu)?;

    let deep_storage_bucket_name = match &druid.spec.cluster_config.deep_storage {
        DeepStorageSpec::S3(s3_spec) => {
            s3_spec
                .bucket
                .resolve(client, namespace)
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name
        }
        _ => None,
    };

    let resolved_authentication_classes = resolve_authentication_classes(client, &druid)
        .await
        .context(FailedToInitializeSecurityContextSnafu)?;

    let druid_ldap_settings = DruidLdapSettings::new_from(&resolved_authentication_classes);

    let druid_tls_security =
        DruidTlsSecurity::new_from_druid_cluster(&druid, resolved_authentication_classes);

    let role_config = transform_all_roles_to_config(druid.as_ref(), druid.build_role_properties());
    let validated_role_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &role_config.context(ProductConfigTransformSnafu)?,
        &ctx.product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        &druid.object_ref(&()),
    )
    .context(CreateClusterResourcesSnafu)?;

    let merged_config = druid.merged_config().context(FailedToResolveConfigSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(
            &druid,
            &resolved_product_image,
            &druid_role,
            &druid_tls_security,
        )?;
        cluster_resources
            .add(client, &role_service)
            .await
            .context(ApplyRoleServiceSnafu)?;

        create_shared_internal_secret(&druid, client, CONTROLLER_NAME)
            .await
            .context(FailedInternalSecretCreationSnafu)?;

        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let merged_rolegroup_config = merged_config
                .common_config(druid_role.clone(), rolegroup_name)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_services(
                &druid,
                &resolved_product_image,
                &rolegroup,
                &druid_tls_security,
            )?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                &zk_connstr,
                vector_aggregator_address.as_deref(),
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                s3_conn.as_ref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            cluster_resources
                .add(client, &rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            cluster_resources
                .add(client, &rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            cluster_resources
                .add(client, &rg_statefulset)
                .await
                .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
        }
    }

    // discovery
    for discovery_cm in build_discovery_configmaps(
        &druid,
        &*druid,
        &resolved_product_image,
        &druid_tls_security,
    )
    .await
    .context(BuildDiscoveryConfigSnafu)?
    {
        cluster_resources
            .add(client, &discovery_cm)
            .await
            .context(ApplyDiscoveryConfigSnafu)?;
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(Action::await_change())
}

pub fn error_policy(_obj: Arc<DruidCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
