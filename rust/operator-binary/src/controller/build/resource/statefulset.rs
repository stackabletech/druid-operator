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
            core::v1::{EnvVar, PersistentVolumeClaim},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    product_logging,
    v2::{
        builder::pod::container::{EnvVarName, EnvVarSet, new_container_builder},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        role_group_utils::ResourceNames,
        types::{kubernetes::VolumeName, operator::RoleGroupName},
    },
};

use crate::{
    controller::{
        build::{
            authentication,
            graceful_shutdown::add_graceful_shutdown_config,
            object_meta,
            properties::product_logging::MAX_DRUID_LOG_FILES_SIZE,
            recommended_labels_for_role_group_resources,
            recommended_labels_for_unversioned_role_group_resources,
            resource::listener::{
                LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener_pvc,
                group_listener_name, secret_volume_listener_scope,
            },
            role_group_selector,
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

// Needed for the `containerdebug` process to log its tracing information to.
stackable_operator::constant!(CONTAINERDEBUG_LOG_DIRECTORY: EnvVarName = "CONTAINERDEBUG_LOG_DIRECTORY");

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

    #[snafu(display(
        "Druid does not support skipping the verification of the tls enabled S3 server"
    ))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

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
) -> Result<StatefulSet> {
    let merged_rolegroup_config = &rg.config;
    let resource_names = cluster.role_group_resource_names(role, role_group_name);
    // Everything below used to be threaded in as separate parameters; it all lives on the
    // `ValidatedCluster` now.
    let resolved_product_image = &cluster.image;
    let s3_conn = cluster.cluster_config.s3_connection.as_ref();
    let druid_tls_security = &cluster.cluster_config.druid_tls_security;
    let druid_auth_config = &cluster.cluster_config.druid_auth_config;
    // prepare container builder
    let prepare_container_name = Container::Prepare.to_container_name();
    let mut cb_prepare = new_container_builder(&prepare_container_name);
    // druid container builder
    let druid_container_name = Container::Druid.to_container_name();
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

    // Operator-managed volumes and volume mounts first: their names and paths are constants, so
    // they cannot collide with each other and the adds are infallible. Volumes and mounts derived
    // from user input (authentication, S3, `extraVolumes`) are added afterwards and stay fallible,
    // as they can collide with the operator-managed ones.
    add_tls_volume_and_volume_mounts(
        druid_tls_security,
        &mut cb_prepare,
        &mut cb_druid,
        &mut pb,
        &merged_rolegroup_config.requested_secret_lifetime,
        // add listener
        secret_volume_listener_scope(role),
    );
    add_config_volume_and_volume_mounts(&resource_names, &mut cb_druid, &mut pb);
    add_log_config_volume_and_volume_mounts(
        &resource_names,
        merged_rolegroup_config,
        &mut cb_druid,
        &mut pb,
    );
    add_log_volume_and_volume_mounts(&mut cb_druid, &mut cb_prepare, &mut pb);
    add_hdfs_cm_volume_and_volume_mounts(
        &cluster.cluster_config.deep_storage,
        &mut cb_druid,
        &mut pb,
    );
    merged_rolegroup_config
        .resources
        .update_volumes_and_volume_mounts(&mut cb_druid, &mut pb);

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

    if let Some(s3) = s3_conn {
        if s3.tls.uses_tls() && !s3.tls.uses_tls_verification() {
            S3TlsNoVerificationNotSupportedSnafu.fail()?;
        }
        s3.add_volumes_and_mounts(&mut pb, vec![&mut cb_druid])
            .context(ConfigureS3Snafu)?;
    }

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

    // All operator-set environment variables of the druid container, collected into an
    // `EnvVarSet` so that every name occurs only once.
    let mut env_vars = EnvVarSet::new();

    for env_var in metadata_database_connection_details
        .username_env
        .iter()
        .chain(metadata_database_connection_details.password_env.iter())
    {
        env_vars = env_vars.with_env_var(env_var.clone()).expect(
            "the database credential env var names are generated by operator-rs from the \
             unique database name and are therefore valid",
        );
    }

    if let Some(auth_config) = druid_auth_config {
        env_vars = env_vars.merge(authentication::get_env_var_mounts(
            auth_config,
            cluster,
            role,
        ));
    }

    env_vars = env_vars.with_value(
        &CONTAINERDEBUG_LOG_DIRECTORY,
        format!("{STACKABLE_LOG_DIR}/containerdebug"),
    );

    // Environment variable overrides (highest precedence), merged from role and role group.
    // They are merged in last so that they override any operator-set environment variable.
    let env_vars = env_vars.merge(rg.env_overrides.clone());

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
        .add_env_vars(Vec::<EnvVar>::from(env_vars))
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

    if let Some(group_listener_name) = group_listener_name(&cluster.name, role) {
        cb_druid
            .add_volume_mount(&*LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .expect("The mount paths are statically defined and there should be no duplicates.");

        // Used for PVC templates, which cannot be modified once they are deployed. The version
        // label is omitted so the labels stay stable across version upgrades.
        let unversioned_recommended_labels =
            recommended_labels_for_unversioned_role_group_resources(cluster, role, role_group_name);

        pvcs = Some(vec![build_group_listener_pvc(
            &group_listener_name,
            &unversioned_recommended_labels,
        )]);
    }

    let metadata = ObjectMetaBuilder::new()
        .with_labels(recommended_labels_for_role_group_resources(
            cluster,
            role,
            role_group_name,
        ))
        .build();

    pb.image_pull_secrets_from_product_image(resolved_product_image)
        .add_init_container(cb_prepare.build())
        .add_container(cb_druid.build())
        .metadata(metadata)
        .service_account_name(
            cluster
                .cluster_resource_names()
                .service_account_name()
                .to_string(),
        )
        .security_context(
            PodSecurityContextBuilder::with_stackable_defaults()
                .fs_group(1000)
                .build(),
        );

    // The Vector agent reads the static `vector.yaml` (added to the rolegroup ConfigMap) from the
    // config volume; the validated aggregator address comes from the up-front `ValidatedLogging`.
    if let Some(vector_log_config) = &merged_rolegroup_config.logging.vector_container {
        pb.add_container(vector_container(
            &Container::Vector.to_container_name(),
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
        metadata: object_meta(
            cluster,
            resource_names.stateful_set_name().to_string(),
            recommended_labels_for_role_group_resources(cluster, role, role_group_name),
        )
        .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
        .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            // Leave `replicas` unset when the role group does not specify a count, so a
            // HorizontalPodAutoscaler can own the replica count without the operator fighting it.
            replicas: rg.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(role_group_selector(cluster, role, role_group_name).into()),
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
) {
    // hdfs deep storage mount
    if let DeepStorageSpec::Hdfs(hdfs) = deep_storage_spec {
        cb_druid
            .add_volume_mount(&*HDFS_CONFIG_VOLUME_NAME, HDFS_CONFIG_DIRECTORY)
            .expect("The mount paths are statically defined and there should be no duplicates.");
        pb.add_volume(
            VolumeBuilder::new(&*HDFS_CONFIG_VOLUME_NAME)
                .with_config_map(hdfs.config_map_name.to_string())
                .build(),
        )
        .expect("The volume names are statically defined and there should be no duplicates.");
    }
}

fn add_config_volume_and_volume_mounts(
    resource_names: &ResourceNames,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    cb_druid
        .add_volume_mount(&*DRUID_CONFIG_VOLUME_NAME, DRUID_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pb.add_volume(
        VolumeBuilder::new(&*DRUID_CONFIG_VOLUME_NAME)
            .with_config_map(resource_names.role_group_config_map().to_string())
            .build(),
    )
    .expect("The volume names are statically defined and there should be no duplicates.");
    cb_druid
        .add_volume_mount(&*RW_CONFIG_VOLUME_NAME, RW_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pb.add_volume(
        VolumeBuilder::new(&*RW_CONFIG_VOLUME_NAME)
            .with_empty_dir(Some(""), None)
            .build(),
    )
    .expect("The volume names are statically defined and there should be no duplicates.");
}

fn add_log_config_volume_and_volume_mounts(
    resource_names: &ResourceNames,
    merged_rolegroup_config: &ValidatedDruidConfig,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    cb_druid
        .add_volume_mount(&*LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");

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
    .expect("The volume names are statically defined and there should be no duplicates.");
}

fn add_log_volume_and_volume_mounts(
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    cb_druid
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    cb_prepare
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.");
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
    .expect("The volume names are statically defined and there should be no duplicates.");
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        k8s_openapi::api::core::v1::{ConfigMapVolumeSource, Volume},
        v2::types::operator::RoleGroupName,
    };

    use super::*;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *DRUID_CONFIG_VOLUME_NAME;
        let _ = *HDFS_CONFIG_VOLUME_NAME;
        let _ = *LOG_CONFIG_VOLUME_NAME;
        let _ = *LOG_VOLUME_NAME;
        let _ = *RW_CONFIG_VOLUME_NAME;
        let _ = *CONTAINERDEBUG_LOG_DIRECTORY;
    }

    /// The user-supplied `envOverrides` must be merged in after all operator-set environment
    /// variables, so that they can override any of them. `CONTAINERDEBUG_LOG_DIRECTORY` is used
    /// as the example here because it is set unconditionally by the operator.
    #[test]
    fn env_overrides_override_operator_set_env_vars() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let role_group_name = RoleGroupName::from_str("default").expect("valid role group name");
        let mut rg = cluster
            .role_group_configs
            .get(&DruidRole::Broker)
            .expect("broker role groups")
            .get(&role_group_name)
            .expect("default role group")
            .clone();
        rg.env_overrides = EnvVarSet::new().with_value(
            &EnvVarName::from_str("CONTAINERDEBUG_LOG_DIRECTORY").expect("valid env var name"),
            "/custom/log/dir",
        );

        let stateful_set =
            build_rolegroup_statefulset(&cluster, &DruidRole::Broker, &role_group_name, &rg)
                .expect("the StatefulSet builds");

        let env = stateful_set
            .spec
            .expect("the StatefulSet has a spec")
            .template
            .spec
            .expect("the pod template has a spec")
            .containers
            .into_iter()
            .find(|container| container.name == "druid")
            .expect("the druid container exists")
            .env
            .expect("the druid container has env vars");

        let containerdebug: Vec<_> = env
            .iter()
            .filter(|env_var| env_var.name == "CONTAINERDEBUG_LOG_DIRECTORY")
            .collect();
        assert_eq!(
            containerdebug.len(),
            1,
            "the override must replace the operator-set value, not duplicate it"
        );
        assert_eq!(containerdebug[0].value.as_deref(), Some("/custom/log/dir"));
    }

    /// A user-supplied extra volume whose name collides with an operator-managed volume must be
    /// reported as an error (the operator's own volumes are added first and are infallible, so
    /// the collision must surface on the user-supplied side, never as a panic).
    #[test]
    fn extra_volume_colliding_with_operator_volume_is_an_error() {
        let mut druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        druid.spec.cluster_config.extra_volumes = vec![user_volume(LOG_VOLUME_NAME.as_ref())];
        let cluster = validated_cluster(&druid);
        let role_group_name = RoleGroupName::from_str("default").expect("valid role group name");
        let rg = broker_default_role_group(&cluster, &role_group_name);

        let Err(error) =
            build_rolegroup_statefulset(&cluster, &DruidRole::Broker, &role_group_name, &rg)
        else {
            panic!("the colliding extra volume must be rejected");
        };
        assert!(
            matches!(error, Error::AddVolume { .. }),
            "unexpected error: {error:?}"
        );
    }

    fn user_volume(name: &str) -> Volume {
        Volume {
            name: name.to_owned(),
            config_map: Some(ConfigMapVolumeSource {
                name: "user-cm".to_owned(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        }
    }

    fn broker_default_role_group(
        cluster: &ValidatedCluster,
        role_group_name: &RoleGroupName,
    ) -> DruidRoleGroupConfig {
        cluster
            .role_group_configs
            .get(&DruidRole::Broker)
            .expect("broker role groups")
            .get(role_group_name)
            .expect("default role group")
            .clone()
    }
}
