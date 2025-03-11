//! Ensures that `Pod`s are configured and running for each [`DruidCluster`][v1alpha1]
//!
//! [v1alpha1]: v1alpha1::DruidCluster
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
};

use const_format::concatcp;
use product_config::{
    types::PropertyNameKind,
    writer::{to_java_properties_string, PropertiesWriterError},
    ProductConfigManager,
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        configmap::ConfigMapBuilder,
        meta::ObjectMetaBuilder,
        pod::{
            container::ContainerBuilder, resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder, volume::VolumeBuilder, PodBuilder,
        },
    },
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        opa::OpaApiVersion,
        product_image_selection::ResolvedProductImage,
        rbac::build_rbac_resources,
        s3::{S3AccessStyle, S3ConnectionSpec, S3Error},
        tls_verification::TlsClientDetailsError,
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, EnvVar, Service, ServiceAccount, ServiceSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
        DeepMerge,
    },
    kube::{
        core::{error_boundary, DeserializeGuard},
        runtime::{controller::Action, reflector::ObjectRef},
        Resource, ResourceExt,
    },
    kvp::{KeyValuePairError, Label, LabelError, LabelValueError, Labels},
    logging::controller::ReconcilerError,
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    product_logging::{
        self,
        framework::LoggingError,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
    role_utils::RoleGroupRef,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::DruidAuthenticationConfig,
    config::jvm::construct_jvm_args,
    crd::{
        authentication::AuthenticationClassesResolved, authorization::DruidAuthorization,
        build_recommended_labels, build_string_list, security::DruidTlsSecurity, v1alpha1,
        CommonRoleGroupConfig, Container, DeepStorageSpec, DruidClusterStatus, DruidRole, APP_NAME,
        AUTH_AUTHORIZER_OPA_URI, CREDENTIALS_SECRET_PROPERTY, DB_PASSWORD_ENV, DB_USERNAME_ENV,
        DRUID_CONFIG_DIRECTORY, DS_BUCKET, EXTENSIONS_LOADLIST, HDFS_CONFIG_DIRECTORY, JVM_CONFIG,
        JVM_SECURITY_PROPERTIES_FILE, LOG_CONFIG_DIRECTORY, MAX_DRUID_LOG_FILES_SIZE,
        OPERATOR_NAME, RUNTIME_PROPS, RW_CONFIG_DIRECTORY, S3_ACCESS_KEY, S3_ENDPOINT_URL,
        S3_PATH_STYLE_ACCESS, S3_REGION_NAME, S3_SECRET_KEY, STACKABLE_LOG_DIR,
        ZOOKEEPER_CONNECTION_STRING,
    },
    discovery::{self, build_discovery_configmaps},
    extensions::get_extension_list,
    internal_secret::{create_shared_internal_secret, env_var_from_secret},
    operations::{graceful_shutdown::add_graceful_shutdown_config, pdb::add_pdbs},
    product_logging::{extend_role_group_config_map, resolve_vector_aggregator_address},
};

pub const DRUID_CONTROLLER_NAME: &str = "druidcluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(DRUID_CONTROLLER_NAME, '.', OPERATOR_NAME);

const DRUID_UID: i64 = 1000;
const DOCKER_IMAGE_BASE_NAME: &str = "druid";

// volume names
const DRUID_CONFIG_VOLUME_NAME: &str = "config";
const HDFS_CONFIG_VOLUME_NAME: &str = "hdfs";
const LOG_CONFIG_VOLUME_NAME: &str = "log-config";
const LOG_VOLUME_NAME: &str = "log";
const RW_CONFIG_VOLUME_NAME: &str = "rwconfig";
const USERDATA_MOUNTPOINT: &str = "/stackable/userdata";

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
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("invalid product configuration"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid authentication configuration"))]
    InvalidDruidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display(
        "failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::client::Error,
        cm_name: String,
    },

    #[snafu(display(
        "failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::commons::opa::Error,
        cm_name: String,
    },

    #[snafu(display("failed to get valid S3 connection"))]
    GetS3Connection { source: crate::crd::Error },

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 { source: S3Error },

    #[snafu(display("failed to configure S3 TLS client details"))]
    ConfigureS3TlsClientDetails { source: TlsClientDetailsError },

    #[snafu(display("failed to get deep storage bucket"))]
    GetDeepStorageBucket { source: S3Error },

    #[snafu(display(
        "failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },

    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("failed to format runtime properties"))]
    PropertiesWriteError { source: PropertiesWriterError },

    #[snafu(display("failed to build discovery ConfigMap"))]
    BuildDiscoveryConfig { source: discovery::Error },

    #[snafu(display("failed to apply discovery ConfigMap"))]
    ApplyDiscoveryConfig {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply cluster status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
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
    FailedToResolveConfig { source: crate::crd::Error },

    #[snafu(display("invalid configuration"))]
    InvalidConfiguration { source: crate::crd::Error },

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create container builder with name [{name}]"))]
    FailedContainerBuilderCreation {
        source: stackable_operator::builder::pod::container::Error,
        name: String,
    },

    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext { source: crate::crd::security::Error },

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display("failed to get JVM config"))]
    GetJvmConfig { source: crate::config::jvm::Error },

    #[snafu(display("failed to derive Druid memory settings from resources"))]
    DeriveMemorySettings { source: crate::crd::resource::Error },

    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources { source: crate::crd::resource::Error },

    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation {
        source: crate::internal_secret::Error,
    },

    #[snafu(display("failed to resolve the Vector aggregator address"))]
    ResolveVectorAggregatorAddress {
        source: crate::product_logging::Error,
    },

    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },

    #[snafu(display("failed to create RBAC service account"))]
    ApplyServiceAccount {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create RBAC role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build RBAC resources"))]
    BuildRbacResources {
        source: stackable_operator::commons::rbac::Error,
    },

    #[snafu(display(
        "failed to serialize [{JVM_SECURITY_PROPERTIES_FILE}] for {}",
        rolegroup
    ))]
    JvmSecurityProperties {
        source: PropertiesWriterError,
        rolegroup: String,
    },

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::operations::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
    },

    #[snafu(display("failed to build TLS certificate SecretClass Volume"))]
    TlsCertSecretClassVolumeBuild {
        source: stackable_operator::builder::pod::volume::SecretOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to build S3 credentials SecretClass Volume"))]
    S3CredentialsSecretClassVolumeBuild {
        source: stackable_operator::commons::secret_class::SecretClassVolumeError,
    },

    #[snafu(display("failed to add OIDC Volumes and VolumeMounts to the Pod and containers"))]
    AuthVolumesBuild {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to build labels"))]
    LabelBuild { source: LabelError },

    #[snafu(display("failed to build metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to get required labels"))]
    GetRequiredLabels {
        source: KeyValuePairError<LabelValueError>,
    },

    #[snafu(display("there was an error generating the authentication runtime settings"))]
    GenerateAuthenticationRuntimeSettings {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to build vector container"))]
    BuildVectorContainer { source: LoggingError },

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },

    #[snafu(display("DruidCluster object is invalid"))]
    InvalidDruidCluster {
        source: error_boundary::InvalidObject,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(
    druid: Arc<DeserializeGuard<v1alpha1::DruidCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");
    let druid = druid
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidDruidClusterSnafu)?;

    let client = &ctx.client;
    let namespace = &druid
        .metadata
        .namespace
        .clone()
        .with_context(|| ObjectHasNoNamespaceSnafu {})?;
    let resolved_product_image: ResolvedProductImage = druid
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION);

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

    let vector_aggregator_address = resolve_vector_aggregator_address(druid, client)
        .await
        .context(ResolveVectorAggregatorAddressSnafu)?;

    // Assemble the OPA connection string from the discovery and the given path, if a spec is given.
    let opa_connstr = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(client, druid, Some("allow"), OpaApiVersion::V1)
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
        DeepStorageSpec::S3(s3_spec) => Some(
            s3_spec
                .bucket
                .clone()
                .resolve(client, namespace)
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name,
        ),
        _ => None,
    };

    let resolved_auth_classes =
        AuthenticationClassesResolved::from(&druid.spec.cluster_config, client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;

    let druid_tls_security =
        DruidTlsSecurity::new_from_druid_cluster(druid, &resolved_auth_classes);

    let druid_auth_config = DruidAuthenticationConfig::try_from(resolved_auth_classes)
        .context(InvalidDruidAuthenticationConfigSnafu)?;

    let role_config = transform_all_roles_to_config(druid, druid.build_role_properties());
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
        DRUID_CONTROLLER_NAME,
        &druid.object_ref(&()),
        ClusterResourceApplyStrategy::from(&druid.spec.cluster_operation),
    )
    .context(CreateClusterResourcesSnafu)?;

    let merged_config = druid.merged_config().context(FailedToResolveConfigSnafu)?;

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        druid,
        APP_NAME,
        cluster_resources
            .get_required_labels()
            .context(GetRequiredLabelsSnafu)?,
    )
    .context(BuildRbacResourcesSnafu)?;
    cluster_resources
        // We clone rbac_sa because we need to reuse it below
        .add(client, rbac_sa.clone())
        .await
        .context(ApplyServiceAccountSnafu)?;
    cluster_resources
        .add(client, rbac_rolebinding)
        .await
        .context(ApplyRoleBindingSnafu)?;

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(
            druid,
            &resolved_product_image,
            &druid_role,
            &druid_tls_security,
        )?;
        cluster_resources
            .add(client, role_service)
            .await
            .context(ApplyRoleServiceSnafu)?;

        create_shared_internal_secret(druid, client, DRUID_CONTROLLER_NAME)
            .await
            .context(FailedInternalSecretCreationSnafu)?;

        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let merged_rolegroup_config = merged_config
                .common_config(&druid_role, rolegroup_name)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_services(
                druid,
                &resolved_product_image,
                &rolegroup,
                &druid_tls_security,
            )?;
            let rg_configmap = build_rolegroup_config_map(
                druid,
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
                &druid_auth_config,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                druid,
                &resolved_product_image,
                &druid_role,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                s3_conn.as_ref(),
                &druid_tls_security,
                &druid_auth_config,
                &rbac_sa,
            )?;
            cluster_resources
                .add(client, rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            ss_cond_builder.add(
                cluster_resources
                    .add(client, rg_statefulset)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        rolegroup: rolegroup.clone(),
                    })?,
            );
        }

        let role_config = druid.role_config(&druid_role);

        add_pdbs(
            &role_config.pod_disruption_budget,
            druid,
            &druid_role,
            client,
            &mut cluster_resources,
        )
        .await
        .context(FailedToCreatePdbSnafu)?;
    }

    // discovery
    for discovery_cm in build_discovery_configmaps(
        druid,
        druid,
        &client.kubernetes_cluster_info,
        &resolved_product_image,
        &druid_tls_security,
    )
    .await
    .context(BuildDiscoveryConfigSnafu)?
    {
        cluster_resources
            .add(client, discovery_cm)
            .await
            .context(ApplyDiscoveryConfigSnafu)?;
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&druid.spec.cluster_operation);

    let status = DruidClusterStatus {
        conditions: compute_conditions(druid, &[&ss_cond_builder, &cluster_operation_cond_builder]),
    };

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;
    client
        .apply_patch_status(OPERATOR_NAME, druid, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
pub fn build_role_service(
    druid: &v1alpha1::DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    role: &DruidRole,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Service> {
    let role_name = role.to_string();
    let role_svc_name = format!(
        "{}-{}",
        druid.metadata.name.as_ref().unwrap_or(&"druid".to_string()),
        role_name
    );
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&role_svc_name)
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &role_name,
                "global",
            ))
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(ServiceSpec {
            type_: Some(druid.spec.cluster_config.listener_class.k8s_service_type()),
            ports: Some(druid_tls_security.service_ports(role)),
            selector: Some(
                Labels::role_selector(druid, APP_NAME, &role_name)
                    .context(LabelBuildSnafu)?
                    .into(),
            ),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

#[allow(clippy::too_many_arguments)]
/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    druid: &v1alpha1::DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<v1alpha1::DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_rolegroup_config: &CommonRoleGroupConfig,
    zk_connstr: &str,
    vector_aggregator_address: Option<&str>,
    opa_connstr: Option<&str>,
    s3_conn: Option<&S3ConnectionSpec>,
    deep_storage_bucket_name: Option<&str>,
    druid_tls_security: &DruidTlsSecurity,
    druid_auth_config: &Option<DruidAuthenticationConfig>,
) -> Result<ConfigMap> {
    let druid_role =
        DruidRole::from_str(&rolegroup.role).with_context(|_| UnidentifiedDruidRoleSnafu {
            role: &rolegroup.role,
        })?;
    let role = druid.get_role(&druid_role);
    let mut cm_conf_data = BTreeMap::new(); // filename -> filecontent

    for (property_name_kind, config) in rolegroup_config {
        let mut conf: BTreeMap<String, Option<String>> = Default::default();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == RUNTIME_PROPS => {
                // Add any properties derived from storage manifests, such as segment cache locations.
                // This has to be done here since there is no other suitable place for it.
                // Previously such properties were added in the compute_files() function,
                // but that code path is now incompatible with the design of fragment merging.
                merged_rolegroup_config
                    .resources
                    .update_druid_config_file(&mut conf)
                    .context(UpdateDruidConfigFromResourcesSnafu)?;
                // NOTE: druid.host can be set manually - if it isn't, the canonical host name of
                // the local host is used.  This should work with the agent and k8s host networking
                // but might need to be revisited in the future
                conf.insert(
                    ZOOKEEPER_CONNECTION_STRING.to_string(),
                    Some(zk_connstr.to_string()),
                );

                conf.insert(
                    EXTENSIONS_LOADLIST.to_string(),
                    Some(build_string_list(&get_extension_list(
                        druid,
                        druid_tls_security,
                        druid_auth_config,
                    ))),
                );

                if let Some(opa_str) = opa_connstr {
                    conf.insert(
                        AUTH_AUTHORIZER_OPA_URI.to_string(),
                        Some(opa_str.to_string()),
                    );
                };

                if let Some(s3) = s3_conn {
                    conf.insert(S3_REGION_NAME.to_string(), Some(s3.region.name.to_string()));

                    conf.insert(
                        S3_ENDPOINT_URL.to_string(),
                        Some(s3.endpoint().context(ConfigureS3Snafu)?.to_string()),
                    );

                    if let Some((access_key_file, secret_key_file)) = s3.credentials_mount_paths() {
                        conf.insert(
                            S3_ACCESS_KEY.to_string(),
                            Some(format!("${{file:UTF-8:{access_key_file}}}")),
                        );
                        conf.insert(
                            S3_SECRET_KEY.to_string(),
                            Some(format!("${{file:UTF-8:{secret_key_file}}}")),
                        );
                    }

                    conf.insert(
                        S3_PATH_STYLE_ACCESS.to_string(),
                        Some((s3.access_style == S3AccessStyle::Path).to_string()),
                    );
                }
                conf.insert(
                    DS_BUCKET.to_string(),
                    deep_storage_bucket_name.map(str::to_string),
                );

                // add tls encryption / auth properties
                druid_tls_security.add_tls_config_properties(&mut conf, &druid_role);

                if let Some(auth_config) = druid_auth_config {
                    conf.extend(
                        auth_config
                            .generate_runtime_properties_config(&druid_role)
                            .context(GenerateAuthenticationRuntimeSettingsSnafu)?,
                    );
                };

                let transformed_config: BTreeMap<String, Option<String>> = config
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect();
                // extend the config to respect overrides
                conf.extend(transformed_config);

                let runtime_properties =
                    to_java_properties_string(conf.iter()).context(PropertiesWriteSnafu)?;
                cm_conf_data.insert(RUNTIME_PROPS.to_string(), runtime_properties);
            }

            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let (heap, direct) = merged_rolegroup_config
                    .resources
                    .get_memory_sizes(&druid_role)
                    .context(DeriveMemorySettingsSnafu)?;
                let jvm_config =
                    construct_jvm_args(&druid_role, &role, &rolegroup.role_group, heap, direct)
                        .context(GetJvmConfigSnafu)?;
                cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config);
            }

            PropertyNameKind::File(file_name) if file_name == JVM_SECURITY_PROPERTIES_FILE => {
                let jvm_sec_props: BTreeMap<String, Option<String>> = rolegroup_config
                    .get(&PropertyNameKind::File(
                        JVM_SECURITY_PROPERTIES_FILE.to_string(),
                    ))
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, Some(v)))
                    .collect();
                cm_conf_data.insert(
                    JVM_SECURITY_PROPERTIES_FILE.to_string(),
                    to_java_properties_string(jvm_sec_props.iter()).with_context(|_| {
                        JvmSecurityPropertiesSnafu {
                            rolegroup: rolegroup.role_group.clone(),
                        }
                    })?,
                );
            }
            _ => {}
        }
    }

    let mut config_map_builder = ConfigMapBuilder::new();
    config_map_builder.metadata(
        ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(rolegroup.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .build(),
    );

    for (filename, file_content) in cm_conf_data.iter() {
        config_map_builder.add_data(filename, file_content);
    }

    extend_role_group_config_map(
        rolegroup,
        vector_aggregator_address,
        &merged_rolegroup_config.logging,
        &mut config_map_builder,
    )
    .context(InvalidLoggingConfigSnafu {
        cm_name: rolegroup.object_name(),
    })?;

    config_map_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_rolegroup_services(
    druid: &v1alpha1::DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<v1alpha1::DruidCluster>,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Service> {
    let role = DruidRole::from_str(&rolegroup.role).unwrap();

    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(rolegroup.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .with_label(Label::try_from(("prometheus.io/scrape", "true")).context(LabelBuildSnafu)?)
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(druid_tls_security.service_ports(&role)),
            selector: Some(
                Labels::role_group_selector(
                    druid,
                    APP_NAME,
                    &rolegroup.role,
                    &rolegroup.role_group,
                )
                .context(LabelBuildSnafu)?
                .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

#[allow(clippy::too_many_arguments)]
/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_services`]).
fn build_rolegroup_statefulset(
    druid: &v1alpha1::DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    role: &DruidRole,
    rolegroup_ref: &RoleGroupRef<v1alpha1::DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_rolegroup_config: &CommonRoleGroupConfig,
    s3_conn: Option<&S3ConnectionSpec>,
    druid_tls_security: &DruidTlsSecurity,
    druid_auth_config: &Option<DruidAuthenticationConfig>,
    service_account: &ServiceAccount,
) -> Result<StatefulSet> {
    // prepare container builder
    let prepare_container_name = Container::Prepare.to_string();
    let mut cb_prepare = ContainerBuilder::new(&prepare_container_name).context(
        FailedContainerBuilderCreationSnafu {
            name: &prepare_container_name,
        },
    )?;
    // druid container builder
    let druid_container_name = Container::Druid.to_string();
    let mut cb_druid = ContainerBuilder::new(&druid_container_name).context(
        FailedContainerBuilderCreationSnafu {
            name: &druid_container_name,
        },
    )?;
    // init pod builder
    let mut pb = PodBuilder::new();
    pb.affinity(&merged_rolegroup_config.affinity);
    add_graceful_shutdown_config(
        role,
        druid_tls_security,
        merged_rolegroup_config.graceful_shutdown_timeout,
        &mut pb,
        &mut cb_druid,
    )
    .context(GracefulShutdownSnafu)?;

    let credentials_secret = druid
        .spec
        .cluster_config
        .metadata_storage_database
        .credentials_secret
        .as_ref();
    let mut main_container_commands = role.main_container_prepare_commands(s3_conn);
    let mut prepare_container_commands = vec![];
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = merged_rolegroup_config
        .logging
        .containers
        .get(&Container::Prepare)
    {
        // This command needs to be added at the beginning of the shell commands,
        // otherwise the output of the following commands will not be captured!
        prepare_container_commands.push(product_logging::framework::capture_shell_output(
            STACKABLE_LOG_DIR,
            &prepare_container_name,
            log_config,
        ));
    }
    prepare_container_commands.extend(druid_tls_security.build_tls_key_stores_cmd());

    if let Some(auth_config) = druid_auth_config {
        auth_config
            .add_volumes_and_mounts(&mut pb, &mut cb_druid, &mut cb_prepare)
            .context(AuthVolumesBuildSnafu)?;
        prepare_container_commands.extend(auth_config.prepare_container_commands());
        main_container_commands.extend(auth_config.main_container_commands())
    }

    // volume and volume mounts
    druid_tls_security
        .add_tls_volume_and_volume_mounts(
            &mut cb_prepare,
            &mut cb_druid,
            &mut pb,
            &merged_rolegroup_config.requested_secret_lifetime,
        )
        .context(FailedToInitializeSecurityContextSnafu)?;

    if let Some(s3) = s3_conn {
        if s3.tls.uses_tls() && !s3.tls.uses_tls_verification() {
            S3TlsNoVerificationNotSupportedSnafu.fail()?;
        }
        s3.add_volumes_and_mounts(&mut pb, vec![&mut cb_druid])
            .context(ConfigureS3Snafu)?;
    }

    add_config_volume_and_volume_mounts(rolegroup_ref, &mut cb_druid, &mut pb)?;
    add_log_config_volume_and_volume_mounts(
        rolegroup_ref,
        merged_rolegroup_config,
        &mut cb_druid,
        &mut pb,
    )?;
    add_log_volume_and_volume_mounts(&mut cb_druid, &mut cb_prepare, &mut pb)?;
    add_hdfs_cm_volume_and_volume_mounts(
        &druid.spec.cluster_config.deep_storage,
        &mut cb_druid,
        &mut pb,
    )?;
    merged_rolegroup_config
        .resources
        .update_volumes_and_volume_mounts(&mut cb_druid, &mut pb)
        .context(UpdateDruidConfigFromResourcesSnafu)?;

    cb_prepare
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![prepare_container_commands.join("\n")])
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("100m")
                .with_cpu_limit("400m")
                .with_memory_request("512Mi")
                .with_memory_limit("512Mi")
                .build(),
        );

    // rest of env
    let mut rest_env = rolegroup_config
        .get(&PropertyNameKind::Env)
        .iter()
        .flat_map(|env_vars| env_vars.iter())
        .filter(|(k, _)| k != &&CREDENTIALS_SECRET_PROPERTY.to_string())
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..EnvVar::default()
        })
        .collect::<Vec<_>>();

    // load database credentials to environment variables: these will be used to replace
    // the placeholders in runtime.properties so that the operator does not "touch" the secret.
    if let Some(credentials_secret_name) = credentials_secret {
        rest_env.push(env_var_from_secret(
            credentials_secret_name,
            Some("username"),
            DB_USERNAME_ENV,
        ));
        rest_env.push(env_var_from_secret(
            credentials_secret_name,
            Some("password"),
            DB_PASSWORD_ENV,
        ));
    }

    if let Some(auth_config) = druid_auth_config {
        rest_env.extend(auth_config.get_env_var_mounts(druid, role))
    }

    // Needed for the `containerdebug` process to log it's tracing information to.
    rest_env.push(EnvVar {
        name: "CONTAINERDEBUG_LOG_DIRECTORY".to_string(),
        value: Some(format!("{STACKABLE_LOG_DIR}/containerdebug")),
        value_from: None,
    });

    main_container_commands.push(role.main_container_start_command());
    cb_druid
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![main_container_commands.join("\n")])
        .add_env_vars(rest_env)
        .add_container_ports(druid_tls_security.container_ports(role))
        // 10s * 30 = 300s to come up
        .startup_probe(druid_tls_security.get_tcp_socket_probe(30, 10, 30, 3))
        // 10s * 1 = 10s to get removed from service
        .readiness_probe(druid_tls_security.get_tcp_socket_probe(10, 10, 1, 3))
        // 10s * 3 = 30s to be restarted
        .liveness_probe(druid_tls_security.get_tcp_socket_probe(10, 10, 3, 3))
        .resources(merged_rolegroup_config.resources.as_resource_requirements());

    // Add extra mounts if any are specified and the current role is MiddleManager
    // Extra mounts may be needed for ingestion to add required certificates, truststores or similar
    // files.
    // Mounts are added to all roles, as we are currently unsure where they may be needed
    // Known roles are MiddleManagers for ingestion and Historicals for deep storage (GCS plugin)
    // We may at some time in the future revisit this and limit it again to avoid needlessly
    // propagating potentially confidential files throughout the cluster
    for volume in &druid.spec.cluster_config.extra_volumes {
        // Extract values into vars so we make it impossible to log something other than
        // what we actually use to create the mounts - maybe paranoid, but hey ..
        let volume_name = &volume.name;
        let mount_point = format!("{USERDATA_MOUNTPOINT}/{}", volume.name);

        tracing::info!(
            ?volume_name,
            ?mount_point,
            ?role,
            "Adding user specified extra volume",
        );
        pb.add_volume(volume.clone()).context(AddVolumeSnafu)?;
        cb_druid
            .add_volume_mount(volume_name, mount_point)
            .context(AddVolumeMountSnafu)?;
    }

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(build_recommended_labels(
            druid,
            DRUID_CONTROLLER_NAME,
            &resolved_product_image.app_version_label,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        ))
        .context(MetadataBuildSnafu)?
        .build();

    pb.image_pull_secrets_from_product_image(resolved_product_image)
        .add_init_container(cb_prepare.build())
        .add_container(cb_druid.build())
        .metadata(metadata)
        .service_account_name(service_account.name_any())
        .security_context(
            PodSecurityContextBuilder::new()
                .run_as_user(DRUID_UID)
                .run_as_group(0)
                .fs_group(1000)
                .build(),
        );

    if merged_rolegroup_config.logging.enable_vector_agent {
        pb.add_container(
            product_logging::framework::vector_container(
                resolved_product_image,
                DRUID_CONFIG_VOLUME_NAME,
                LOG_VOLUME_NAME,
                merged_rolegroup_config
                    .logging
                    .containers
                    .get(&Container::Vector),
                ResourceRequirementsBuilder::new()
                    .with_cpu_request("250m")
                    .with_cpu_limit("500m")
                    .with_memory_request("128Mi")
                    .with_memory_limit("128Mi")
                    .build(),
            )
            .context(BuildVectorContainerSnafu)?,
        );
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(druid.pod_overrides_for_role(role).clone());
    if let Some(pod_overrides) = druid.pod_overrides_for_role_group(role, &rolegroup_ref.role_group)
    {
        pod_template.merge_from(pod_overrides.clone());
    }

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: merged_rolegroup_config.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        druid,
                        APP_NAME,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: rolegroup_ref.object_name(),
            template: pod_template,
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

fn add_hdfs_cm_volume_and_volume_mounts(
    deep_storage_spec: &DeepStorageSpec,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    // hdfs deep storage mount
    if let DeepStorageSpec::Hdfs(hdfs) = deep_storage_spec {
        cb_druid
            .add_volume_mount(HDFS_CONFIG_VOLUME_NAME, HDFS_CONFIG_DIRECTORY)
            .context(AddVolumeMountSnafu)?;
        pb.add_volume(
            VolumeBuilder::new(HDFS_CONFIG_VOLUME_NAME)
                .with_config_map(&hdfs.config_map_name)
                .build(),
        )
        .context(AddVolumeSnafu)?;
    }

    Ok(())
}

fn add_config_volume_and_volume_mounts(
    rolegroup_ref: &RoleGroupRef<v1alpha1::DruidCluster>,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    cb_druid
        .add_volume_mount(DRUID_CONFIG_VOLUME_NAME, DRUID_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(DRUID_CONFIG_VOLUME_NAME)
            .with_config_map(rolegroup_ref.object_name())
            .build(),
    )
    .context(AddVolumeSnafu)?;
    cb_druid
        .add_volume_mount(RW_CONFIG_VOLUME_NAME, RW_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(RW_CONFIG_VOLUME_NAME)
            .with_empty_dir(Some(""), None)
            .build(),
    )
    .context(AddVolumeSnafu)?;

    Ok(())
}

fn add_log_config_volume_and_volume_mounts(
    rolegroup_ref: &RoleGroupRef<v1alpha1::DruidCluster>,
    merged_rolegroup_config: &CommonRoleGroupConfig,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    cb_druid
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;

    let config_map = if let Some(ContainerLogConfig {
        choice:
            Some(ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
                custom: ConfigMapLogConfig { config_map },
            })),
    }) = merged_rolegroup_config
        .logging
        .containers
        .get(&Container::Druid)
    {
        config_map.into()
    } else {
        rolegroup_ref.object_name()
    };

    pb.add_volume(
        VolumeBuilder::new(LOG_CONFIG_VOLUME_NAME)
            .with_config_map(config_map)
            .build(),
    )
    .context(AddVolumeSnafu)?;

    Ok(())
}

fn add_log_volume_and_volume_mounts(
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    cb_druid
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_prepare
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(LOG_VOLUME_NAME)
            .with_empty_dir(
                Some(""),
                Some(product_logging::framework::calculate_log_volume_size_limit(
                    &[MAX_DRUID_LOG_FILES_SIZE],
                )),
            )
            .build(),
    )
    .context(AddVolumeSnafu)?;

    Ok(())
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::DruidCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidDruidCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

#[cfg(test)]
mod test {
    use product_config::{writer, ProductConfigManager};
    use rstest::*;

    use super::*;
    use crate::crd::PROP_SEGMENT_CACHE_LOCATIONS;

    #[derive(Snafu, Debug, EnumDiscriminants)]
    #[strum_discriminants(derive(IntoStaticStr))]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        #[snafu(display("controller error"))]
        Controller { source: super::Error },
        #[snafu(display("product config error"))]
        ProductConfig {
            source: product_config::error::Error,
        },
        #[snafu(display("product config utils error"))]
        ProductConfigUtils {
            source: stackable_operator::product_config_utils::Error,
        },
        #[snafu(display("operator framework error"))]
        OperatorFramework {
            source: stackable_operator::product_config_utils::Error,
        },
        #[snafu(display("failed to resolve and merge config for role and role group"))]
        FailedToResolveConfig { source: crate::crd::Error },
        #[snafu(display("invalid configuration"))]
        InvalidConfiguration { source: crate::crd::Error },
    }

    #[rstest]
    #[case(
        "segment_cache.yaml",
        "default",
        "[{\"path\":\"/stackable/var/druid/segment-cache\",\"maxSize\":\"1G\",\"freeSpacePercent\":\"5\"}]"
    )]
    #[case(
        "segment_cache.yaml",
        "secondary",
        "[{\"path\":\"/stackable/var/druid/segment-cache\",\"maxSize\":\"5G\",\"freeSpacePercent\":\"2\"}]"
    )]
    fn segment_cache_location_property(
        #[case] druid_manifest: &str,
        #[case] tested_rolegroup_name: &str,
        #[case] expected_druid_segment_cache_property: &str,
    ) -> Result<(), Box<Error>> {
        let cluster_cr =
            std::fs::File::open(format!("test/resources/druid_controller/{druid_manifest}"))
                .unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid: v1alpha1::DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let resolved_product_image: ResolvedProductImage = druid
            .spec
            .image
            .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION);
        let role_config = transform_all_roles_to_config(&druid, druid.build_role_properties());

        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/resources/druid_controller/properties.yaml")
                .context(ProductConfigSnafu)?;

        let validated_role_config = validate_all_roles_and_groups_config(
            &resolved_product_image.product_version,
            &role_config.context(ProductConfigUtilsSnafu)?,
            &product_config_manager,
            false,
            false,
        )
        .context(OperatorFrameworkSnafu)?;

        let druid_tls_security = DruidTlsSecurity::new(
            &AuthenticationClassesResolved {
                auth_classes: vec![],
            },
            Some("tls".to_string()),
        );

        let mut druid_segment_cache_property = "invalid".to_string();

        let config = druid.merged_config().context(FailedToResolveConfigSnafu)?;

        for (role_name, role_config) in validated_role_config.iter() {
            for (rolegroup_name, rolegroup_config) in role_config.iter() {
                if rolegroup_name == tested_rolegroup_name
                    && role_name == &DruidRole::Historical.to_string()
                {
                    let rolegroup_ref = RoleGroupRef {
                        cluster: ObjectRef::from_obj(&druid),
                        role: role_name.into(),
                        role_group: rolegroup_name.clone(),
                    };

                    let merged_rolegroup_config = config
                        .common_config(&DruidRole::Historical, rolegroup_name)
                        .context(InvalidConfigurationSnafu)?;

                    let auth_settings: Option<DruidAuthenticationConfig> = None;

                    let rg_configmap = build_rolegroup_config_map(
                        &druid,
                        &resolved_product_image,
                        &rolegroup_ref,
                        rolegroup_config,
                        &merged_rolegroup_config,
                        "zookeeper-connection-string",
                        None,
                        None,
                        None,
                        None,
                        &druid_tls_security,
                        &auth_settings,
                    )
                    .context(ControllerSnafu)?;

                    druid_segment_cache_property = rg_configmap
                        .data
                        .unwrap()
                        .get(RUNTIME_PROPS)
                        .unwrap()
                        .to_string();

                    break;
                }
            }
        }
        let escaped_segment_cache_property = writer::to_java_properties_string(
            vec![(
                &PROP_SEGMENT_CACHE_LOCATIONS.to_string(),
                &Some(expected_druid_segment_cache_property.to_string()),
            )]
            .into_iter(),
        )
        .unwrap();

        assert!(
            druid_segment_cache_property.contains(&escaped_segment_cache_property),
            "role group {}",
            tested_rolegroup_name
        );

        Ok(())
    }
}
