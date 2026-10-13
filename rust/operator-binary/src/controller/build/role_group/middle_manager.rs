//! MiddleManager role groups.

use std::collections::BTreeMap;

use semver::Version;
use snafu::{OptionExt, ResultExt};
use stackable_operator::{crd::s3, v2::types::operator::RoleGroupName};

use super::{
    Error, HeapMemorySnafu, MissingSecretLifetimeSnafu, RoleGroupBuilder, RoleGroupInputs,
};
use crate::{
    controller::{
        build::{
            graceful_shutdown::drain_pre_stop_hook, jvm::AWS_REGION, properties::runtime_properties,
        },
        validate::{MiddleManagerRoleGroupConfig, ValidatedCluster},
    },
    crd::{
        DruidRole, MiddleManagerConfig, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
        STACKABLE_TRUST_STORE_TYPE, build_string_list, resource::heap_memory,
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

/// Resolves one MiddleManager role group into its [`RoleGroupBuilder`].
pub(crate) fn build<'a>(
    cluster: &'a ValidatedCluster,
    role_group_name: &RoleGroupName,
    rg_config: &MiddleManagerRoleGroupConfig,
) -> Result<RoleGroupBuilder<'a>, Error> {
    let MiddleManagerConfig {
        resources,
        // Validated up front into `rg_config.config.logging`.
        logging: _,
        affinity,
        graceful_shutdown_timeout,
        requested_secret_lifetime,
    } = &rg_config.config.config;

    // The MiddleManager needs no direct memory, so the whole allocatable memory is heap.
    let heap = heap_memory(resources, None).context(HeapMemorySnafu)?;

    RoleGroupBuilder::new(RoleGroupInputs {
        cluster,
        role: ROLE,
        role_group_name: role_group_name.clone(),
        affinity: affinity.clone(),
        graceful_shutdown_timeout: *graceful_shutdown_timeout,
        requested_secret_lifetime: requested_secret_lifetime.context(MissingSecretLifetimeSnafu)?,
        resources: resources.clone().into(),
        heap,
        direct_memory: None,
        logging: rg_config.config.logging.clone(),
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
        // MiddleManagers drain their running tasks before they stop. The hook needs the
        // termination grace period, which the config merge always sets.
        druid_pre_stop: graceful_shutdown_timeout.map(|termination_grace_period| {
            drain_pre_stop_hook(
                &ROLE,
                &cluster.cluster_config.druid_tls_security,
                &termination_grace_period,
            )
        }),
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
