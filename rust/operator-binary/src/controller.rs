//! Ensures that `Pod`s are configured and running for each [`DruidCluster`][v1alpha1]
//!
//! [v1alpha1]: v1alpha1::DruidCluster
use std::{str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder, container::ContainerBuilder, resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder, volume::VolumeBuilder,
        },
    },
    cli::OperatorEnvironmentOptions,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{product_image_selection::ResolvedProductImage, rbac::build_rbac_resources},
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    crd::s3,
    database_connections::drivers::jdbc::JdbcDatabaseConnection as _,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{EnvVar, PersistentVolumeClaim, ServiceAccount},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::{KeyValuePairError, LabelError, LabelValueError, Labels},
    logging::controller::ReconcilerError,
    product_logging,
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    v2::{
        builder::pod::container::EnvVarSet,
        product_logging::framework::{ValidatedContainerLogConfigChoice, vector_container},
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{ContainerName, VolumeName},
            operator::RoleGroupName,
        },
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::build::resource::{
        listener::{
            LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener,
            build_group_listener_pvc, group_listener_name, secret_volume_listener_scope,
        },
        pdb::add_pdbs,
        service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
    },
    crd::{
        APP_NAME, Container, DRUID_CONFIG_DIRECTORY, DeepStorageSpec, DruidClusterStatus,
        DruidRole, HDFS_CONFIG_DIRECTORY, LOG_CONFIG_DIRECTORY, METRICS_PORT, METRICS_PORT_NAME,
        OPERATOR_NAME, RW_CONFIG_DIRECTORY, STACKABLE_LOG_DIR, ValidatedDruidConfig,
        build_recommended_labels, security::DruidTlsSecurity, v1alpha1,
    },
    internal_secret::create_shared_internal_secret,
    operations::graceful_shutdown::add_graceful_shutdown_config,
};

mod build;
mod dereference;
mod validate;

use build::{
    properties::product_logging::MAX_DRUID_LOG_FILES_SIZE,
    resource::discovery::{self, build_discovery_configmaps},
};
use validate::{DruidRoleGroupConfig, ValidatedCluster};

pub const DRUID_CONTROLLER_NAME: &str = "druidcluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(DRUID_CONTROLLER_NAME, '.', OPERATOR_NAME);

pub(super) const CONTAINER_IMAGE_BASE_NAME: &str = "druid";

// volume names
const DRUID_CONFIG_VOLUME_NAME: &str = "config";
const HDFS_CONFIG_VOLUME_NAME: &str = "hdfs";
const LOG_CONFIG_VOLUME_NAME: &str = "log-config";
const LOG_VOLUME_NAME: &str = "log";
const RW_CONFIG_VOLUME_NAME: &str = "rwconfig";
const USERDATA_MOUNTPOINT: &str = "/stackable/userdata";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply Service for role group {role_group}"))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("failed to apply ConfigMap for role group {role_group}"))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("failed to apply StatefulSet for role group {role_group}"))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        role_group: String,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to dereference cluster objects"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

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

    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext { source: crate::crd::security::Error },

    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources { source: crate::crd::resource::Error },

    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation {
        source: crate::internal_secret::Error,
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

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::controller::build::resource::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
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

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration {
        source: crate::controller::build::resource::listener::Error,
    },

    #[snafu(display("failed to configure service"))]
    ServiceConfiguration {
        source: crate::controller::build::resource::service::Error,
    },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },

    #[snafu(display("failed to build rolegroup ConfigMap"))]
    BuildConfigMap {
        source: build::resource::config_map::Error,
    },

    #[snafu(display("invalid metadata database connection"))]
    InvalidMetadataDatabaseConnection {
        source: stackable_operator::database_connections::Error,
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

    let dereferenced_objects = dereference::dereference(client, druid)
        .await
        .context(DereferenceSnafu)?;

    let validated_cluster =
        validate::validate(druid, &dereferenced_objects, &ctx.operator_environment)
            .context(ValidateClusterSnafu)?;

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        DRUID_CONTROLLER_NAME,
        &druid.object_ref(&()),
        ClusterResourceApplyStrategy::from(&druid.spec.cluster_operation),
        &druid.spec.object_overrides,
    )
    .context(CreateClusterResourcesSnafu)?;

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

    for (druid_role, groups) in validated_cluster.role_group_configs.iter() {
        let role_name = druid_role.to_string();

        create_shared_internal_secret(druid, client, DRUID_CONTROLLER_NAME)
            .await
            .context(FailedInternalSecretCreationSnafu)?;

        for (rolegroup_name, rg) in groups.iter() {
            let role_group_service_recommended_labels = build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &validated_cluster.image.app_version_label_value,
                &role_name,
                rolegroup_name.as_ref(),
            );

            let role_group_service_selector =
                Labels::role_group_selector(druid, APP_NAME, &role_name, rolegroup_name.as_ref())
                    .context(LabelBuildSnafu)?;

            let rg_headless_service = build_rolegroup_headless_service(
                &validated_cluster,
                &validated_cluster.cluster_config.druid_tls_security,
                druid_role,
                rolegroup_name,
                role_group_service_recommended_labels.clone(),
                role_group_service_selector.clone().into(),
            )
            .context(ServiceConfigurationSnafu)?;
            let rg_metrics_service = build_rolegroup_metrics_service(
                &validated_cluster,
                druid_role,
                rolegroup_name,
                role_group_service_recommended_labels,
                role_group_service_selector.into(),
            )
            .context(ServiceConfigurationSnafu)?;

            let rg_configmap = build::resource::config_map::build_rolegroup_config_map(
                &validated_cluster,
                druid_role,
                rolegroup_name,
                rg,
            )
            .context(BuildConfigMapSnafu)?;
            let rg_statefulset = build_rolegroup_statefulset(
                druid,
                &validated_cluster,
                &validated_cluster.image,
                druid_role,
                rolegroup_name,
                rg,
                validated_cluster.cluster_config.s3_connection.as_ref(),
                &validated_cluster.cluster_config.druid_tls_security,
                &validated_cluster.cluster_config.druid_auth_config,
                &rbac_sa,
            )?;

            cluster_resources
                .add(client, rg_headless_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;
            cluster_resources
                .add(client, rg_metrics_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;
            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    role_group: rolegroup_name.to_string(),
                })?;

            // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
            // to prevent unnecessary Pod restarts.
            // See https://github.com/stackabletech/commons-operator/issues/111 for details.
            ss_cond_builder.add(
                cluster_resources
                    .add(client, rg_statefulset)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        role_group: rolegroup_name.to_string(),
                    })?,
            );
        }

        if let Some(listener_class) = druid_role.listener_class_name(druid)
            && let Some(listener_group_name) = group_listener_name(druid, druid_role)
        {
            let role_group_listener = build_group_listener(
                druid,
                build_recommended_labels(
                    druid,
                    DRUID_CONTROLLER_NAME,
                    &validated_cluster.image.app_version_label_value,
                    &role_name,
                    "none",
                ),
                listener_class.to_string(),
                listener_group_name,
                druid_role,
                &validated_cluster.cluster_config.druid_tls_security,
            )
            .context(ListenerConfigurationSnafu)?;

            let listener = cluster_resources
                .add(client, role_group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;

            if *druid_role == DruidRole::Router {
                // discovery
                for discovery_cm in build_discovery_configmaps(&validated_cluster, listener)
                    .await
                    .context(BuildDiscoveryConfigSnafu)?
                {
                    cluster_resources
                        .add(client, discovery_cm)
                        .await
                        .context(ApplyDiscoveryConfigSnafu)?;
                }
            }
        }

        let role_config = druid.generic_role_config(druid_role);

        add_pdbs(
            &role_config.pod_disruption_budget,
            druid,
            druid_role,
            client,
            &mut cluster_resources,
        )
        .await
        .context(FailedToCreatePdbSnafu)?;
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

#[allow(clippy::too_many_arguments)]
/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the
/// corresponding [`stackable_operator::k8s_openapi::api::core::v1::Service`] (from [`build_rolegroup_headless_service`]).
fn build_rolegroup_statefulset(
    druid: &v1alpha1::DruidCluster,
    cluster: &ValidatedCluster,
    resolved_product_image: &ResolvedProductImage,
    role: &DruidRole,
    role_group_name: &RoleGroupName,
    rg: &DruidRoleGroupConfig,
    s3_conn: Option<&s3::v1alpha1::ConnectionSpec>,
    druid_tls_security: &DruidTlsSecurity,
    druid_auth_config: &Option<DruidAuthenticationConfig>,
    service_account: &ServiceAccount,
) -> Result<StatefulSet> {
    let merged_rolegroup_config = &rg.config;
    let role_name = role.to_string();
    let resource_names = cluster.resource_names(role, role_group_name);
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

    let metadata_database_connection_details = druid
        .spec
        .cluster_config
        .metadata_database
        .jdbc_connection_details("metadata")
        .context(InvalidMetadataDatabaseConnectionSnafu)?;

    let mut main_container_commands = role.main_container_prepare_commands(s3_conn);
    let mut prepare_container_commands = vec![];
    if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
        &merged_rolegroup_config.logging.prepare_container
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
            // add listener
            secret_volume_listener_scope(role),
        )
        .context(FailedToInitializeSecurityContextSnafu)?;

    if let Some(s3) = s3_conn {
        if s3.tls.uses_tls() && !s3.tls.uses_tls_verification() {
            S3TlsNoVerificationNotSupportedSnafu.fail()?;
        }
        s3.add_volumes_and_mounts(&mut pb, vec![&mut cb_druid])
            .context(ConfigureS3Snafu)?;
    }

    add_config_volume_and_volume_mounts(&resource_names, &mut cb_druid, &mut pb)?;
    add_log_config_volume_and_volume_mounts(
        &resource_names,
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

    metadata_database_connection_details.add_to_container(&mut cb_druid);

    // rest of env: the validated env overrides, rendered in sorted-by-name order.
    let mut rest_env: Vec<EnvVar> = rg.env_overrides.clone().into();

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
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT.into())
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

    let mut pvcs: Option<Vec<PersistentVolumeClaim>> = None;

    if let Some(group_listener_name) = group_listener_name(druid, role) {
        cb_druid
            .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .context(AddVolumeMountSnafu)?;

        // Used for PVC templates that cannot be modified once they are deployed
        let unversioned_recommended_labels = Labels::recommended(&build_recommended_labels(
            druid,
            DRUID_CONTROLLER_NAME,
            // A version value is required, and we do want to use the "recommended" format for the other desired labels
            "none",
            &role_name,
            role_group_name.as_ref(),
        ))
        .context(LabelBuildSnafu)?;

        pvcs = Some(vec![
            build_group_listener_pvc(&group_listener_name, &unversioned_recommended_labels)
                .context(ListenerConfigurationSnafu)?,
        ]);
    }

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&build_recommended_labels(
            druid,
            DRUID_CONTROLLER_NAME,
            &resolved_product_image.app_version_label_value,
            &role_name,
            role_group_name.as_ref(),
        ))
        .context(MetadataBuildSnafu)?
        .build();

    pb.image_pull_secrets_from_product_image(resolved_product_image)
        .add_init_container(cb_prepare.build())
        .add_container(cb_druid.build())
        .metadata(metadata)
        .service_account_name(service_account.name_any())
        .security_context(PodSecurityContextBuilder::new().fs_group(1000).build());

    // The Vector agent reads the static `vector.yaml` (added to the rolegroup ConfigMap) from the
    // config volume; the validated aggregator address comes from the up-front `ValidatedLogging`.
    if let Some(vector_log_config) = &merged_rolegroup_config.logging.vector_container {
        pb.add_container(vector_container(
            &ContainerName::from_str(&Container::Vector.to_string())
                .expect("'vector' is a valid container name"),
            resolved_product_image,
            vector_log_config,
            &resource_names,
            &VolumeName::from_str(DRUID_CONFIG_VOLUME_NAME).expect("a valid volume name"),
            &VolumeName::from_str(LOG_VOLUME_NAME).expect("a valid volume name"),
            EnvVarSet::new(),
        ));
    }

    let mut pod_template = pb.build_template();
    // The role and rolegroup pod overrides were already merged (rolegroup wins) during validation.
    pod_template.merge_from(rg.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(resource_names.stateful_set_name().to_string())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&build_recommended_labels(
                druid,
                DRUID_CONTROLLER_NAME,
                &resolved_product_image.app_version_label_value,
                &role_name,
                role_group_name.as_ref(),
            ))
            .context(MetadataBuildSnafu)?
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: Some(i32::from(rg.replicas)),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        druid,
                        APP_NAME,
                        &role_name,
                        role_group_name.as_ref(),
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(resource_names.headless_service_name().to_string()),
            template: pod_template,
            volume_claim_templates: pvcs,
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
    resource_names: &ResourceNames,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    cb_druid
        .add_volume_mount(DRUID_CONFIG_VOLUME_NAME, DRUID_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(DRUID_CONFIG_VOLUME_NAME)
            .with_config_map(resource_names.role_group_config_map().to_string())
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
    resource_names: &ResourceNames,
    merged_rolegroup_config: &ValidatedDruidConfig,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    cb_druid
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;

    let config_map = match &merged_rolegroup_config.logging.druid_container {
        ValidatedContainerLogConfigChoice::Custom(config_map_name) => config_map_name.to_string(),
        ValidatedContainerLogConfigChoice::Automatic(_) => {
            resource_names.role_group_config_map().to_string()
        }
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
    use std::str::FromStr;

    use rstest::*;
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::*;
    use crate::{
        controller::build::{
            properties::ConfigFileName, resource::config_map::build_rolegroup_config_map,
        },
        crd::PROP_SEGMENT_CACHE_LOCATIONS,
    };

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
    ) {
        let yaml =
            std::fs::read_to_string(format!("test/resources/druid_controller/{druid_manifest}"))
                .unwrap();
        let druid = crate::controller::validate::test_support::druid_from_yaml(&yaml);

        let cluster = crate::controller::validate::test_support::validated_cluster(&druid);

        // The segment cache property is injected dynamically by the config_map builder from the
        // merged resources of the validated role group config.
        let rg = cluster
            .role_group_configs
            .get(&DruidRole::Historical)
            .expect("historical role groups")
            .get(&RoleGroupName::from_str(tested_rolegroup_name).unwrap())
            .expect("tested rolegroup")
            .clone();

        let rg_configmap = build_rolegroup_config_map(
            &cluster,
            &DruidRole::Historical,
            &RoleGroupName::from_str(tested_rolegroup_name).unwrap(),
            &rg,
        )
        .expect("build rolegroup config map");

        let druid_segment_cache_property = rg_configmap
            .data
            .unwrap()
            .get(&ConfigFileName::RuntimeProperties.to_string())
            .unwrap()
            .to_string();

        let escaped_segment_cache_property =
            stackable_operator::v2::config_file_writer::to_java_properties_string(
                vec![(
                    &PROP_SEGMENT_CACHE_LOCATIONS.to_string(),
                    &expected_druid_segment_cache_property.to_string(),
                )]
                .into_iter(),
            )
            .unwrap();

        assert!(
            druid_segment_cache_property.contains(&escaped_segment_cache_property),
            "role group {tested_rolegroup_name}"
        );
    }
}
