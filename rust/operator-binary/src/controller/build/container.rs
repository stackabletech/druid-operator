//! Builds the containers of a role group's pod and collects the volumes they mount.
//!
//! Every Druid role runs the same containers: the `prepare` init container, the `druid` container
//! and, when the Vector agent is enabled, the Vector sidecar. What differs between roles arrives
//! resolved in the [`RoleGroupInputs`]; the role itself is read only for the values that are
//! functions of it (ports, process name, container commands) and for the object names.

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pod::{
        container::ContainerBuilder, resources::ResourceRequirementsBuilder, volume::VolumeBuilder,
    },
    k8s_openapi::api::core::v1::{
        Container as PodContainer, EnvVar, PersistentVolumeClaim, Volume,
    },
    product_logging,
    v2::{
        builder::pod::container::{EnvVarName, EnvVarSet, new_container_builder},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        role_group_utils::ResourceNames,
        types::kubernetes::VolumeName,
    },
};

use crate::{
    controller::build::{
        authentication,
        properties::product_logging::MAX_DRUID_LOG_FILES_SIZE,
        recommended_labels_for_unversioned_role_group_resources,
        resource::listener::{LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener_pvc},
        role_group::RoleGroupInputs,
        security::{
            self, add_tls_volume_and_volume_mounts, build_tls_key_stores_cmd, container_ports,
            get_tcp_socket_probe,
        },
    },
    crd::{
        Container, DRUID_CONFIG_DIRECTORY, DeepStorageSpec, HDFS_CONFIG_DIRECTORY,
        LOG_CONFIG_DIRECTORY, METRICS_PORT, METRICS_PORT_NAME, RW_CONFIG_DIRECTORY,
    },
};

// volume names
stackable_operator::constant!(pub(crate) DRUID_CONFIG_VOLUME_NAME: VolumeName = "config");
stackable_operator::constant!(pub(crate) HDFS_CONFIG_VOLUME_NAME: VolumeName = "hdfs");
stackable_operator::constant!(pub(crate) LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
stackable_operator::constant!(pub(crate) LOG_VOLUME_NAME: VolumeName = "log");
stackable_operator::constant!(pub(crate) RW_CONFIG_VOLUME_NAME: VolumeName = "rwconfig");

// Needed for the `containerdebug` process to log its tracing information to.
stackable_operator::constant!(pub(crate) CONTAINERDEBUG_LOG_DIRECTORY: EnvVarName = "CONTAINERDEBUG_LOG_DIRECTORY");

// volume mount directory (not a volume name)
const USERDATA_MOUNTPOINT: &str = "/stackable/userdata";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build the authentication volumes and volume mounts"))]
    AuthenticationVolumes { source: authentication::Error },

    #[snafu(display("failed to build the TLS volumes and volume mounts"))]
    TlsVolumes { source: security::Error },

    #[snafu(display(
        "Druid does not support skipping the verification of the tls enabled S3 server"
    ))]
    S3TlsNoVerificationNotSupported,

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The containers of a role group's pod and the volumes they mount, in pod order.
pub(crate) struct ContainersAndVolumes {
    /// The `prepare` init container.
    pub(crate) init_containers: Vec<PodContainer>,
    /// The `druid` container, then the Vector sidecar when the Vector agent is enabled.
    pub(crate) containers: Vec<PodContainer>,
    /// The pod volumes in the order the pod lists them; see [`containers_and_volumes`].
    pub(crate) pod_volumes: Vec<Volume>,
    /// The listener claim template of a role with a Listener. `None` for the other roles, which
    /// keeps their StatefulSets without a `volumeClaimTemplates` field.
    pub(crate) volume_claim_templates: Option<Vec<PersistentVolumeClaim>>,
}

/// Builds the containers every role runs and collects the volumes they mount.
///
/// The pod volumes are collected in the order they are mounted: the operator-managed volumes
/// (TLS, config, log config, log, HDFS), then the volumes only the role has (the Historical
/// segment cache), then the volumes derived from user input (authentication, S3, `extraVolumes`).
/// This order is part of the pod template, so changing it restarts every pod; it is pinned by
/// `pod_volumes_keep_their_order` in `build/mod.rs`. A volume whose name collides with another's
/// is rejected when the StatefulSet builder adds the volumes to the pod.
pub(crate) fn containers_and_volumes(inputs: &RoleGroupInputs) -> Result<ContainersAndVolumes> {
    let cluster = inputs.cluster;
    let role = &inputs.role;
    let resource_names = cluster.role_group_resource_names(role, &inputs.role_group_name);
    let resolved_product_image = &cluster.image;
    let s3_conn = cluster.cluster_config.s3_connection.as_ref();
    let druid_tls_security = &cluster.cluster_config.druid_tls_security;
    let druid_auth_config = &cluster.cluster_config.druid_auth_config;
    let metadata_database_connection_details = &cluster.cluster_config.metadata_db_connection;

    let mut cb_prepare = new_container_builder(Container::Prepare.name());
    let mut cb_druid = new_container_builder(Container::Druid.name());
    let mut pod_volumes: Vec<Volume> = Vec::new();

    if let Some(pre_stop) = &inputs.druid_pre_stop {
        cb_druid.lifecycle_pre_stop(pre_stop.clone());
    }

    let mut main_container_commands = role.main_container_prepare_commands(s3_conn);
    let mut prepare_container_commands = vec![];
    if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
        &inputs.logging.prepare_container
    {
        // This command needs to be added at the beginning of the shell commands,
        // otherwise the output of the following commands will not be captured!
        prepare_container_commands.push(product_logging::framework::capture_shell_output(
            STACKABLE_LOG_DIR,
            Container::Prepare.name().as_ref(),
            log_config,
        ));
    }
    prepare_container_commands.extend(build_tls_key_stores_cmd(druid_tls_security));

    // Operator-managed volumes and volume mounts first. Their mount paths are constants, so the
    // mounts cannot collide with each other and adding them is infallible. Volumes and mounts
    // derived from user input (authentication, S3, `extraVolumes`) come afterwards; their mounts
    // stay fallible, as they can collide with the operator-managed ones.
    //
    // The TLS certificate of a role with a Listener also carries the Listener's address, so its
    // secret volume is scoped to the listener volume.
    let listener_volume_scope = inputs
        .listener
        .is_some()
        .then(|| LISTENER_VOLUME_NAME.to_string());
    add_tls_volume_and_volume_mounts(
        druid_tls_security,
        &mut cb_prepare,
        &mut cb_druid,
        &mut pod_volumes,
        &inputs.requested_secret_lifetime,
        listener_volume_scope,
    )
    .context(TlsVolumesSnafu)?;
    add_config_volume_and_volume_mounts(&resource_names, &mut cb_druid, &mut pod_volumes);
    add_log_config_volume_and_volume_mounts(
        &resource_names,
        &inputs.logging.druid_container,
        &mut cb_druid,
        &mut pod_volumes,
    );
    add_log_volume_and_volume_mounts(&mut cb_druid, &mut cb_prepare, &mut pod_volumes);
    add_hdfs_cm_volume_and_volume_mounts(
        &cluster.cluster_config.deep_storage,
        &mut cb_druid,
        &mut pod_volumes,
    );

    // The volumes only this role has (the Historical segment cache) and their mounts come after
    // the operator-managed volumes: the pod's `volumes` are an ordered list and this position is
    // pinned by `pod_volumes_keep_their_order` in `build/mod.rs`. Their mount paths are constants
    // of the role module, distinct from the operator-managed mounts above.
    cb_druid
        .add_volume_mounts(inputs.role_druid_mounts.iter().cloned())
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pod_volumes.extend(inputs.role_pod_volumes.iter().cloned());

    // The listener volume mount is static as well, so it belongs here, before the derived volumes
    // and mounts below. The listener volume itself is a claim template.
    let mut volume_claim_templates = None;
    if let Some(listener) = &inputs.listener {
        cb_druid
            .add_volume_mount(&*LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .expect("The mount paths are statically defined and there should be no duplicates.");

        // Used for PVC templates, which cannot be modified once they are deployed. The version
        // label is omitted so the labels stay stable across version upgrades.
        let unversioned_recommended_labels =
            recommended_labels_for_unversioned_role_group_resources(
                cluster,
                role,
                &inputs.role_group_name,
            );

        volume_claim_templates = Some(vec![build_group_listener_pvc(
            listener,
            &unversioned_recommended_labels,
        )]);
    }

    if let Some(auth_config) = druid_auth_config {
        let (volumes, mounts) =
            authentication::volumes_and_mounts(auth_config).context(AuthenticationVolumesSnafu)?;
        pod_volumes.extend(volumes);
        cb_druid
            .add_volume_mounts(mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_prepare
            .add_volume_mounts(mounts)
            .context(AddVolumeMountSnafu)?;
        prepare_container_commands.extend(authentication::prepare_container_commands(auth_config));
        main_container_commands.extend(authentication::main_container_commands(auth_config))
    }

    if let Some(s3) = s3_conn {
        if s3.tls.uses_tls() && !s3.tls.uses_tls_verification() {
            S3TlsNoVerificationNotSupportedSnafu.fail()?;
        }
        let (volumes, mounts) = s3.volumes_and_mounts().context(ConfigureS3Snafu)?;
        pod_volumes.extend(volumes);
        cb_druid
            .add_volume_mounts(mounts)
            .context(AddVolumeMountSnafu)?;
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
            inputs.oidc_enabled,
        ));
    }

    env_vars = env_vars.with_value(
        &CONTAINERDEBUG_LOG_DIRECTORY,
        format!("{STACKABLE_LOG_DIR}/containerdebug"),
    );

    // Environment variable overrides (highest precedence), merged from role and role group.
    // They are merged in last so that they override any operator-set environment variable.
    let env_vars = env_vars.merge(inputs.env_overrides.clone());

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
        .resources(inputs.resources.clone());

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
        pod_volumes.push(volume.clone());
        cb_druid
            .add_volume_mount(volume_name, mount_point)
            .context(AddVolumeMountSnafu)?;
    }

    let mut containers = vec![cb_druid.build()];

    // The Vector agent reads the static `vector.yaml` (added to the rolegroup ConfigMap) from the
    // config volume; the validated aggregator address comes from the up-front `ValidatedLogging`.
    if let Some(vector_log_config) = &inputs.logging.vector_container {
        containers.push(vector_container(
            Container::Vector.name(),
            resolved_product_image,
            vector_log_config,
            &resource_names,
            &DRUID_CONFIG_VOLUME_NAME,
            &LOG_VOLUME_NAME,
            EnvVarSet::new(),
        ));
    }

    Ok(ContainersAndVolumes {
        init_containers: vec![cb_prepare.build()],
        containers,
        pod_volumes,
        volume_claim_templates,
    })
}

/// Adds the HDFS discovery ConfigMap volume and its mount if HDFS deep storage is configured.
///
/// # Panics
///
/// Panics if the volume mounts cannot be added to the container builder. Only call this on a
/// container builder whose mount paths are still distinct from the ones added here.
fn add_hdfs_cm_volume_and_volume_mounts(
    deep_storage_spec: &DeepStorageSpec,
    cb_druid: &mut ContainerBuilder,
    pod_volumes: &mut Vec<Volume>,
) {
    // hdfs deep storage mount
    if let DeepStorageSpec::Hdfs(hdfs) = deep_storage_spec {
        cb_druid
            .add_volume_mount(&*HDFS_CONFIG_VOLUME_NAME, HDFS_CONFIG_DIRECTORY)
            .expect("The mount paths are statically defined and there should be no duplicates.");
        pod_volumes.push(
            VolumeBuilder::new(&*HDFS_CONFIG_VOLUME_NAME)
                .with_config_map(hdfs.config_map_name.to_string())
                .build(),
        );
    }
}

/// Adds the config and rwconfig volumes and their mounts.
///
/// # Panics
///
/// Panics if the volume mounts cannot be added to the container builder. Only call this on a
/// container builder whose mount paths are still distinct from the ones added here.
fn add_config_volume_and_volume_mounts(
    resource_names: &ResourceNames,
    cb_druid: &mut ContainerBuilder,
    pod_volumes: &mut Vec<Volume>,
) {
    cb_druid
        .add_volume_mount(&*DRUID_CONFIG_VOLUME_NAME, DRUID_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pod_volumes.push(
        VolumeBuilder::new(&*DRUID_CONFIG_VOLUME_NAME)
            .with_config_map(resource_names.role_group_config_map().to_string())
            .build(),
    );
    cb_druid
        .add_volume_mount(&*RW_CONFIG_VOLUME_NAME, RW_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pod_volumes.push(
        VolumeBuilder::new(&*RW_CONFIG_VOLUME_NAME)
            .with_empty_dir(Some(""), None)
            .build(),
    );
}

/// Adds the log config ConfigMap volume and its mount.
///
/// # Panics
///
/// Panics if the volume mounts cannot be added to the container builder. Only call this on a
/// container builder whose mount paths are still distinct from the ones added here.
fn add_log_config_volume_and_volume_mounts(
    resource_names: &ResourceNames,
    druid_log_config: &ValidatedContainerLogConfigChoice,
    cb_druid: &mut ContainerBuilder,
    pod_volumes: &mut Vec<Volume>,
) {
    cb_druid
        .add_volume_mount(&*LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIRECTORY)
        .expect("The mount paths are statically defined and there should be no duplicates.");

    let config_map = match druid_log_config {
        ValidatedContainerLogConfigChoice::Custom(config_map_name) => config_map_name.to_string(),
        ValidatedContainerLogConfigChoice::Automatic(_) => {
            resource_names.role_group_config_map().to_string()
        }
    };

    pod_volumes.push(
        VolumeBuilder::new(&*LOG_CONFIG_VOLUME_NAME)
            .with_config_map(config_map)
            .build(),
    );
}

/// Adds the log volume and its mounts on the druid and prepare containers.
///
/// # Panics
///
/// Panics if the volume mounts cannot be added to the container builders. Only call this on
/// container builders whose mount paths are still distinct from the ones added here.
fn add_log_volume_and_volume_mounts(
    cb_druid: &mut ContainerBuilder,
    cb_prepare: &mut ContainerBuilder,
    pod_volumes: &mut Vec<Volume>,
) {
    cb_druid
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    cb_prepare
        .add_volume_mount(&*LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.");
    pod_volumes.push(
        VolumeBuilder::new(&*LOG_VOLUME_NAME)
            .with_empty_dir(
                Some(""),
                Some(product_logging::framework::calculate_log_volume_size_limit(
                    &[MAX_DRUID_LOG_FILES_SIZE],
                )),
            )
            .build(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
