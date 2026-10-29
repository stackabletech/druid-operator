//! MiddleManager role groups.

use std::collections::BTreeMap;

use indoc::formatdoc;
use semver::Version;
use snafu::ResultExt;
use stackable_operator::{
    crd::s3,
    k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler},
    shared::time::Duration,
    v2::types::operator::RoleGroupName,
};

use super::{Error, HeapMemorySnafu, RoleGroupBuilder, RoleGroupInputs};
use crate::{
    controller::{
        build::{jvm::AWS_REGION, properties::runtime_properties},
        validate::{MiddleManagerRoleGroupConfig, ValidatedCluster, ValidatedMiddleManagerConfig},
    },
    crd::{
        DruidRole, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
        STACKABLE_TRUST_STORE_TYPE, build_string_list, resource::heap_memory,
        security::DruidTlsSecurity,
    },
};

pub(crate) const ROLE: DruidRole = DruidRole::MiddleManager;

/// The value of `druid.indexer.runner.javaOptsArray`: the JVM options of the tasks a
/// MiddleManager spawns, which run in their own JVMs.
fn indexer_java_opts(
    s3_conn: Option<&s3::v1alpha1::ConnectionSpec>,
    druid_version: &Result<Version, semver::Error>,
) -> String {
    let mut java_opts = vec![
        format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
        format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
        format!("-Djavax.net.ssl.trustStoreType={STACKABLE_TRUST_STORE_TYPE}"),
    ];

    // TODO (@NickLarsenNZ): Remove the condition (keep the body) once we no longer support Druid
    // less than 37.0.0.
    // Druid >= 37.0.0 uses the AWS SDK v2, which requires a region to be set via the JVM system
    // property `aws.region` for the Peon processes spawned by the MiddleManager.
    if matches!(druid_version, Ok(v) if *v >= Version::new(37, 0, 0))
        && let Some(s3) = s3_conn
    {
        java_opts.push(format!(
            "-D{AWS_REGION}={region_name}",
            region_name = s3.region.name
        ));
    }

    build_string_list(&java_opts)
}

/// The `druid` container's pre-stop hook that drains a MiddleManager before it stops: the hook
/// disables the MiddleManager so the Overlord sends it no new tasks, then waits until the running
/// tasks finish or the termination grace period elapses.
///
/// See: <https://druid.apache.org/docs/latest/operations/rolling-updates/#rolling-restart-graceful-termination-based>
///
/// The role is read for the port the hook talks to. The `DRUID_PID` file is written by
/// [`DruidRole::main_container_start_command`].
fn drain_pre_stop_hook(
    role: &DruidRole,
    tls_security: &DruidTlsSecurity,
    termination_grace_period: &Duration,
) -> LifecycleHandler {
    let (protocol, port) = if tls_security.tls_enabled() {
        ("https", role.get_https_port())
    } else {
        ("http", role.get_http_port())
    };

    let middle_manager_host = format!("{protocol}://127.0.0.1:{port}");
    let debug_message = "$(date --utc +%FT%T,%3N) INFO [stackable_lifecycle_pre_stop] -";
    let sleep_interval = 2;

    LifecycleHandler {
        exec: Some(ExecAction {
            command: Some(vec![
                "/bin/bash".to_string(),
                "-x".to_string(),
                "-euo".to_string(),
                "pipefail".to_string(),
                "-c".to_string(),
                formatdoc!(
                    r#"
                    log() {{
                      echo "{debug_message} $1" >> /proc/$(cat /tmp/DRUID_PID)/fd/1 2>&1
                    }}

                    response=$(curl -v --fail --insecure -X POST {middle_manager_host}/druid/worker/v1/disable)
                    log "Disable middle manager to stop overlord from sending tasks: $response"

                    end_time_seconds=$(date --date="+{termination_grace_period_seconds} seconds" '+%s')
                    while :
                    do
                      current_time_seconds=$(date '+%s')
                      log "Check if termination grace period ({termination_grace_period_seconds} seconds) is reached..."
                      if [ $current_time_seconds -gt $end_time_seconds ]
                      then
                        log "The termination grace period is reached!"
                        break
                      fi

                      tasks=$(curl -v --fail --insecure -X GET {middle_manager_host}/druid/worker/v1/tasks)
                      log "Check if all tasks are finished... Running: $tasks"
                      if [ $tasks = "[]" ]
                      then
                        log "All tasks finished!"
                         break
                      fi

                      log "Sleeping {sleep_interval} seconds..."
                      log ""
                      sleep {sleep_interval}
                    done
                    log "All done!"
                    "#,
                    termination_grace_period_seconds = termination_grace_period.as_secs()
                ),
            ]),
        }),
        ..Default::default()
    }
}

/// Resolves one MiddleManager role group into its [`RoleGroupBuilder`].
pub(crate) fn build<'a>(
    cluster: &'a ValidatedCluster,
    role_group_name: &RoleGroupName,
    rg_config: &MiddleManagerRoleGroupConfig,
) -> Result<RoleGroupBuilder<'a>, Error> {
    let ValidatedMiddleManagerConfig {
        resources,
        logging,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config;

    // The MiddleManager needs no direct memory, so the whole allocatable memory is heap.
    let heap = heap_memory(resources, None).context(HeapMemorySnafu)?;

    RoleGroupBuilder::new(RoleGroupInputs {
        cluster,
        role: ROLE,
        role_group_name: role_group_name.clone(),
        affinity: affinity.clone(),
        graceful_shutdown_timeout: *graceful_shutdown_timeout,
        requested_secret_lifetime: *requested_secret_lifetime,
        resources: resources.clone().into(),
        heap,
        direct_memory: None,
        logging: logging.clone(),
        listener: None,
        role_pod_volumes: Vec::new(),
        role_druid_mounts: Vec::new(),
        resource_runtime_properties: BTreeMap::new(),
        // The tasks a MiddleManager spawns run in their own JVMs, which need the trust store (and
        // the S3 region for the AWS SDK v2).
        indexer_java_opts: Some(indexer_java_opts(
            cluster.cluster_config.s3_connection.as_ref(),
            &Version::parse(&cluster.image.product_version),
        )),
        role_jvm_args: Vec::new(),
        // MiddleManagers drain their running tasks before they stop, for at most the termination
        // grace period.
        druid_pre_stop: Some(drain_pre_stop_hook(
            &ROLE,
            &cluster.cluster_config.druid_tls_security,
            graceful_shutdown_timeout,
        )),
        // End users never talk to MiddleManagers directly, and OIDC on them breaks their
        // communication with the Coordinators during ingestion.
        oidc_enabled: false,
        role_runtime_defaults: runtime_properties::defaults(&ROLE),
        replicas: rg_config.replicas,
        config_overrides: rg_config.config_overrides.clone(),
        env_overrides: rg_config.env_overrides.clone(),
        pod_overrides: rg_config.pod_overrides.clone(),
        jvm_argument_overrides: rg_config
            .product_specific_common_config
            .jvm_argument_overrides
            .clone(),
    })
}
