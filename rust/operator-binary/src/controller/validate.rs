//! The validate step in the DruidCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedCluster`], consumed by the rest of `reconcile_druid`.

use std::collections::{BTreeMap, HashMap};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection::{self, ResolvedProductImage},
    crd::s3,
    kube::ResourceExt,
};
use strum::IntoEnumIterator;

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::{
        build::properties::{ConfigFileName, runtime_properties, security_properties},
        dereference::DereferencedObjects,
    },
    crd::{
        CommonRoleGroupConfig, DruidConfigOverrides, DruidRole, INDEXER_JAVA_OPTS,
        STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD, build_string_list,
        security::DruidTlsSecurity, v1alpha1,
    },
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("invalid authentication configuration"))]
    InvalidDruidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type RoleGroupName = String;

/// The merged config plus the per-file "validated config" maps that used to be produced by
/// product-config. These are computed from first principles so that rendered config stays
/// byte-identical.
#[derive(Clone)]
pub struct DruidRoleGroupConfig {
    pub merged_config: CommonRoleGroupConfig,
    /// The runtime.properties "validated config" (compute_files + recommended defaults + merged overrides).
    pub runtime_config: BTreeMap<String, Option<String>>,
    /// The security.properties "validated config".
    pub security_config: BTreeMap<String, Option<String>>,
    /// Merged env overrides (role <- rolegroup). compute_env is empty for druid.
    pub env: BTreeMap<String, String>,
}

/// Cluster-wide resolved fields that are not role/rolegroup specific.
pub struct ValidatedClusterConfig {
    pub zookeeper_connection_string: String,
    pub opa_connection_string: Option<String>,
    pub s3_connection: Option<s3::v1alpha1::ConnectionSpec>,
    pub deep_storage_bucket_name: Option<String>,
    pub druid_tls_security: DruidTlsSecurity,
    pub druid_auth_config: Option<DruidAuthenticationConfig>,
}

/// Synchronous inputs the rest of `reconcile_druid` needs after dereferencing.
pub struct ValidatedCluster {
    // Currently unused by the build steps, but part of the documented `ValidatedCluster` shape;
    // consumed by later tasks.
    #[allow(dead_code)]
    pub name: String,
    pub image: ResolvedProductImage,
    pub cluster_config: ValidatedClusterConfig,
    pub role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>>,
}

/// Returns the user-supplied key/value overrides for the given config file from a
/// [`DruidConfigOverrides`], as a product-config style map.
fn key_value_overrides(
    overrides: &DruidConfigOverrides,
    file: ConfigFileName,
) -> BTreeMap<String, Option<String>> {
    let kv = match file {
        ConfigFileName::RuntimeProperties => overrides.runtime_properties.as_ref(),
        ConfigFileName::SecurityProperties => overrides.security_properties.as_ref(),
    };
    kv.map(
        stackable_operator::config_overrides::KeyValueConfigOverrides::as_product_config_overrides,
    )
    .unwrap_or_default()
}

/// Builds the precomputed per-file config for a single rolegroup. Pure assembly: combines the
/// role-level overrides with the rolegroup-level overrides (rolegroup wins) on top of the
/// computed defaults. No behavior change vs. the inline loop body it was extracted from.
#[allow(clippy::too_many_arguments)]
fn build_role_group_config(
    druid: &v1alpha1::DruidCluster,
    druid_role: &DruidRole,
    merged_config: CommonRoleGroupConfig,
    role_runtime_overrides: &BTreeMap<String, Option<String>>,
    role_security_overrides: &BTreeMap<String, Option<String>>,
    role_env_overrides: &HashMap<String, String>,
    rg_config_overrides: &DruidConfigOverrides,
    rg_env_overrides: &HashMap<String, String>,
) -> DruidRoleGroupConfig {
    // ----- runtime.properties -----
    let mut runtime_config = druid.compute_runtime_properties();
    if *druid_role == DruidRole::MiddleManager {
        let (k, v) = middlemanager_indexer_java_opts();
        runtime_config.insert(k, v);
    }
    runtime_config.extend(runtime_properties::defaults(druid_role));
    // merged user overrides (role <- rolegroup; rolegroup wins)
    let mut runtime_overrides = role_runtime_overrides.clone();
    runtime_overrides.extend(key_value_overrides(
        rg_config_overrides,
        ConfigFileName::RuntimeProperties,
    ));
    runtime_config.extend(runtime_overrides);

    // ----- security.properties -----
    let mut security_config: BTreeMap<String, Option<String>> = BTreeMap::new();
    if *druid_role == DruidRole::MiddleManager {
        let (k, v) = middlemanager_indexer_java_opts();
        security_config.insert(k, v);
    }
    let mut security_overrides = role_security_overrides.clone();
    security_overrides.extend(key_value_overrides(
        rg_config_overrides,
        ConfigFileName::SecurityProperties,
    ));
    security_config.extend(security_properties::build(&security_overrides));

    // ----- env -----
    let mut env: BTreeMap<String, String> = role_env_overrides
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    env.extend(rg_env_overrides.iter().map(|(k, v)| (k.clone(), v.clone())));

    DruidRoleGroupConfig {
        merged_config,
        runtime_config,
        security_config,
        env,
    }
}

/// The `druid.indexer.runner.javaOptsArray` entry that `MiddleManagerConfigFragment::compute_files`
/// adds for *every* file (runtime.properties and security.properties).
fn middlemanager_indexer_java_opts() -> (String, Option<String>) {
    (
        INDEXER_JAVA_OPTS.to_string(),
        Some(build_string_list(&[
            format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
            format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
            "-Djavax.net.ssl.trustStoreType=pkcs12".to_owned(),
        ])),
    )
}

/// Validates the cluster spec and the dereferenced inputs.
pub fn validate(
    druid: &v1alpha1::DruidCluster,
    dereferenced_objects: &DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
) -> Result<ValidatedCluster> {
    let image = druid
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
        druid,
        &dereferenced_objects.resolved_authentication_classes,
    );

    let druid_auth_config = DruidAuthenticationConfig::try_from(
        dereferenced_objects.resolved_authentication_classes.clone(),
    )
    .context(InvalidDruidAuthenticationConfigSnafu)?;

    let merged = druid.merged_config().context(FailedToResolveConfigSnafu)?;

    let mut role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>> =
        BTreeMap::new();

    for druid_role in DruidRole::iter() {
        // The role-level overrides (role <- rolegroup precedence starts here).
        let role = druid.get_role(&druid_role);
        let role_runtime_overrides = key_value_overrides(
            &role.config.config_overrides,
            ConfigFileName::RuntimeProperties,
        );
        let role_security_overrides = key_value_overrides(
            &role.config.config_overrides,
            ConfigFileName::SecurityProperties,
        );
        let role_env_overrides = role.config.env_overrides.clone();

        let rolegroups = merged.role_group_names(&druid_role);

        let mut group_map: BTreeMap<RoleGroupName, DruidRoleGroupConfig> = BTreeMap::new();
        for rg_name in rolegroups {
            let merged_config = merged
                .common_config(&druid_role, &rg_name)
                .context(FailedToResolveConfigSnafu)?;
            // The rolegroup-level config/env overrides (rolegroup wins over role).
            // The rolegroup is guaranteed to exist because `rg_name` comes from
            // `role_group_names` and `common_config` above already resolved it.
            let (rg_config_overrides, rg_env_overrides) = merged
                .role_group_overrides(&druid_role, &rg_name)
                .expect("role group resolved by common_config must exist");

            group_map.insert(
                rg_name,
                build_role_group_config(
                    druid,
                    &druid_role,
                    merged_config,
                    &role_runtime_overrides,
                    &role_security_overrides,
                    &role_env_overrides,
                    rg_config_overrides,
                    rg_env_overrides,
                ),
            );
        }
        role_group_configs.insert(druid_role, group_map);
    }

    Ok(ValidatedCluster {
        name: druid.name_any(),
        image,
        cluster_config: ValidatedClusterConfig {
            zookeeper_connection_string: dereferenced_objects.zookeeper_connection_string.clone(),
            opa_connection_string: dereferenced_objects.opa_connection_string.clone(),
            s3_connection: dereferenced_objects.s3_connection.clone(),
            deep_storage_bucket_name: dereferenced_objects.deep_storage_bucket_name.clone(),
            druid_tls_security,
            druid_auth_config,
        },
        role_group_configs,
    })
}
