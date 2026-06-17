//! Builds the rolegroup [`StatefulSet`] from a [`ValidatedCluster`].

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder, container::ContainerBuilder, resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder, volume::VolumeBuilder,
        },
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{EnvVar, PersistentVolumeClaim, ServiceAccount},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::ResourceExt,
    product_logging,
    v2::{
        builder::pod::container::{EnvVarSet, new_container_builder},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{ContainerName, VolumeName},
            operator::RoleGroupName,
        },
    },
};

use crate::{
    controller::{
        build::{
            UNVERSIONED_PRODUCT_VERSION, authentication,
            graceful_shutdown::add_graceful_shutdown_config,
            properties::product_logging::MAX_DRUID_LOG_FILES_SIZE,
            resource::listener::{
                LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener_pvc,
                group_listener_name, secret_volume_listener_scope,
            },
            security::{
                add_tls_volume_and_volume_mounts, build_tls_key_stores_cmd, container_ports,
                get_tcp_socket_probe,
            },
        },
        validate::{DruidRoleGroupConfig, ValidatedCluster},
    },
    crd::{
        Container, DRUID_CONFIG_DIRECTORY, DeepStorageSpec, DruidRole, HDFS_CONFIG_DIRECTORY,
        LOG_CONFIG_DIRECTORY, METRICS_PORT, METRICS_PORT_NAME, RW_CONFIG_DIRECTORY,
        ValidatedDruidConfig,
    },
};

// volume names
stackable_operator::constant!(DRUID_CONFIG_VOLUME_NAME: VolumeName = "config");
stackable_operator::constant!(HDFS_CONFIG_VOLUME_NAME: VolumeName = "hdfs");
stackable_operator::constant!(LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
stackable_operator::constant!(LOG_VOLUME_NAME: VolumeName = "log");
stackable_operator::constant!(RW_CONFIG_VOLUME_NAME: VolumeName = "rwconfig");

// volume mount directory (not a volume name)
const USERDATA_MOUNTPOINT: &str = "/stackable/userdata";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::controller::build::graceful_shutdown::Error,
    },

    #[snafu(display("failed to add OIDC Volumes and VolumeMounts to the Pod and containers"))]
    AuthVolumesBuild {
        source: crate::controller::build::authentication::Error,
    },

    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext {
        source: crate::controller::build::security::Error,
    },

    #[snafu(display(
        "Druid does not support skipping the verification of the tls enabled S3 server"
    ))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources { source: crate::crd::resource::Error },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn build_rolegroup_statefulset(
    cluster: &ValidatedCluster,
    role: &DruidRole,
    role_group_name: &RoleGroupName,
    rg: &DruidRoleGroupConfig,
    service_account: &ServiceAccount,
) -> Result<StatefulSet> {
    let merged_rolegroup_config = &rg.config;
    let resource_names = cluster.resource_names(role, role_group_name);
    // Everything below used to be threaded in as separate parameters; it all lives on the
    // `ValidatedCluster` now.
    let resolved_product_image = &cluster.image;
    let s3_conn = cluster.cluster_config.s3_connection.as_ref();
    let druid_tls_security = &cluster.cluster_config.druid_tls_security;
    let druid_auth_config = &cluster.cluster_config.druid_auth_config;
    // prepare container builder
    let prepare_container_name = ContainerName::from_str(&Container::Prepare.to_string())
        .expect("'prepare' is a valid container name");
    let mut cb_prepare = new_container_builder(&prepare_container_name);
    // druid container builder
    let druid_container_name = ContainerName::from_str(&Container::Druid.to_string())
        .expect("'druid' is a valid container name");
    let mut cb_druid = new_container_builder(&druid_container_name);
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

    let metadata_database_connection_details = &cluster.cluster_config.metadata_db_connection;

    let mut main_container_commands = role.main_container_prepare_commands(s3_conn);
    let mut prepare_container_commands = vec![];
    if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
        &merged_rolegroup_config.logging.prepare_container
    {
        // This command needs to be added at the beginning of the shell commands,
        // otherwise the output of the following commands will not be captured!
        prepare_container_commands.push(product_logging::framework::capture_shell_output(
            STACKABLE_LOG_DIR,
            prepare_container_name.as_ref(),
            log_config,
        ));
    }
    prepare_container_commands.extend(build_tls_key_stores_cmd(druid_tls_security));

    if let Some(auth_config) = druid_auth_config {
        authentication::add_volumes_and_mounts(
            auth_config,
            &mut pb,
            &mut cb_druid,
            &mut cb_prepare,
        )
        .context(AuthVolumesBuildSnafu)?;
        prepare_container_commands.extend(authentication::prepare_container_commands(auth_config));
        main_container_commands.extend(authentication::main_container_commands(auth_config))
    }

    // volume and volume mounts
    add_tls_volume_and_volume_mounts(
        druid_tls_security,
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
        &cluster.cluster_config.deep_storage,
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
        rest_env.extend(authentication::get_env_var_mounts(
            auth_config,
            cluster,
            role,
        ))
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
        .add_container_ports(container_ports(druid_tls_security, role))
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT.into())
        // 10s * 30 = 300s to come up
        .startup_probe(get_tcp_socket_probe(druid_tls_security, 30, 10, 30, 3))
        // 10s * 1 = 10s to get removed from service
        .readiness_probe(get_tcp_socket_probe(druid_tls_security, 10, 10, 1, 3))
        // 10s * 3 = 30s to be restarted
        .liveness_probe(get_tcp_socket_probe(druid_tls_security, 10, 10, 3, 3))
        .resources(merged_rolegroup_config.resources.as_resource_requirements());

    // Add extra mounts if any are specified and the current role is MiddleManager
    // Extra mounts may be needed for ingestion to add required certificates, truststores or similar
    // files.
    // Mounts are added to all roles, as we are currently unsure where they may be needed
    // Known roles are MiddleManagers for ingestion and Historicals for deep storage (GCS plugin)
    // We may at some time in the future revisit this and limit it again to avoid needlessly
    // propagating potentially confidential files throughout the cluster
    for volume in &cluster.cluster_config.extra_volumes {
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

    if let Some(group_listener_name) = group_listener_name(cluster, role) {
        cb_druid
            .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .context(AddVolumeMountSnafu)?;

        // Used for PVC templates that cannot be modified once they are deployed
        // A version value is required, and we do want to use the "recommended" format for the
        // other desired labels, hence the unversioned product version.
        let unversioned_recommended_labels =
            cluster.recommended_labels_for(role, &UNVERSIONED_PRODUCT_VERSION, role_group_name);

        pvcs = Some(vec![build_group_listener_pvc(
            &group_listener_name,
            &unversioned_recommended_labels,
        )]);
    }

    let metadata = ObjectMetaBuilder::new()
        .with_labels(cluster.recommended_labels(role, role_group_name))
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
            &DRUID_CONFIG_VOLUME_NAME,
            &LOG_VOLUME_NAME,
            EnvVarSet::new(),
        ));
    }

    let mut pod_template = pb.build_template();
    // The role and rolegroup pod overrides were already merged (rolegroup wins) during validation.
    pod_template.merge_from(rg.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: cluster
            .object_meta(
                resource_names.stateful_set_name().to_string(),
                role,
                role_group_name,
            )
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: Some(i32::from(rg.replicas)),
            selector: LabelSelector {
                match_labels: Some(cluster.role_group_selector(role, role_group_name).into()),
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
            .add_volume_mount(&*HDFS_CONFIG_VOLUME_NAME, HDFS_CONFIG_DIRECTORY)
            .context(AddVolumeMountSnafu)?;
        pb.add_volume(
            VolumeBuilder::new(&*HDFS_CONFIG_VOLUME_NAME)
                .with_config_map(hdfs.config_map_name.to_string())
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
        .add_volume_mount(&*DRUID_CONFIG_VOLUME_NAME, DRUID_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(&*DRUID_CONFIG_VOLUME_NAME)
            .with_config_map(resource_names.role_group_config_map().to_string())
            .build(),
    )
    .context(AddVolumeSnafu)?;
    cb_druid
        .add_volume_mount(&*RW_CONFIG_VOLUME_NAME, RW_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(&*RW_CONFIG_VOLUME_NAME)
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
        .add_volume_mount(&*LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIRECTORY)
        .context(AddVolumeMountSnafu)?;

    let config_map = match &merged_rolegroup_config.logging.druid_container {
        ValidatedContainerLogConfigChoice::Custom(config_map_name) => config_map_name.to_string(),
        ValidatedContainerLogConfigChoice::Automatic(_) => {
            resource_names.role_group_config_map().to_string()
        }
    };

    pb.add_volume(
        VolumeBuilder::new(&*LOG_CONFIG_VOLUME_NAME)
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
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_prepare
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?;
    pb.add_volume(
        VolumeBuilder::new(&*LOG_VOLUME_NAME)
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
