//! Builds the rolegroup [`ConfigMap`] from a [`ValidatedCluster`].
//!
//! The per-file configs (runtime.properties / security.properties / jvm.config) are rendered here
//! from the merged [`DruidRoleGroupConfig`] (config plus the merged config overrides, including the
//! merged JVM argument overrides used for `jvm.config`); the recommended cluster-level runtime
//! properties are carried on `ValidatedCluster`.
//!
//! Metadata, owner reference and recommended labels are derived entirely from `ValidatedCluster`
//! (which carries the validated name/namespace/uid and implements `Resource`).
//!
//! The builder does not read the raw [`v1alpha1::DruidCluster`] at all: everything it needs is
//! carried on `ValidatedCluster` (resolved during the validate step).

use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::configmap::ConfigMapBuilder,
    crd::s3,
    k8s_openapi::api::core::v1::{ConfigMap, EnvVar},
    product_logging::framework::VECTOR_CONFIG_FILE,
    v2::{config_file_writer::to_java_properties_string, types::operator::RoleGroupName},
};

use crate::{
    controller::{
        build::{
            authentication::generate_runtime_properties_config as generate_auth_runtime_properties,
            jvm::construct_jvm_args,
            properties::{
                ConfigFileName,
                extensions::get_extension_list,
                product_logging::{build_log4j2, vector_config_file_content},
                runtime_properties, security_properties,
            },
            security::add_tls_config_properties,
        },
        validate::{DruidRoleGroupConfig, ValidatedCluster},
    },
    crd::{
        DruidConfigOverrides, DruidRole, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
        STACKABLE_TRUST_STORE_TYPE, build_string_list, env_var_reference, file_reference,
    },
};

// Druid `runtime.properties` config-property keys assembled into the rolegroup ConfigMap here.
const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
const ZOOKEEPER_CONNECTION_STRING: &str = "druid.zk.service.host";
const DS_BUCKET: &str = "druid.storage.bucket";
const S3_ENDPOINT_URL: &str = "druid.s3.endpoint.url";
const S3_ACCESS_KEY: &str = "druid.s3.accessKey";
const S3_SECRET_KEY: &str = "druid.s3.secretKey";
const S3_PATH_STYLE_ACCESS: &str = "druid.s3.enablePathStyleAccess";
const AUTH_AUTHORIZER_OPA_URI: &str = "druid.auth.authorizer.OpaAuthorizer.opaUri";

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to build ConfigMap for role group {role_group}"))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        role_group: String,
    },

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to serialize [runtime.properties]"))]
    SerializeRuntimeProperties {
        source: stackable_operator::v2::config_file_writer::PropertiesWriterError,
    },

    #[snafu(display("failed to serialize [security.properties] for {rolegroup}"))]
    JvmSecurityProperties {
        source: stackable_operator::v2::config_file_writer::PropertiesWriterError,
        rolegroup: String,
    },

    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources { source: crate::crd::resource::Error },

    #[snafu(display("there was an error generating the authentication runtime settings"))]
    GenerateAuthenticationRuntimeSettings {
        source: crate::controller::build::authentication::Error,
    },

    #[snafu(display("failed to derive Druid memory settings from resources"))]
    DeriveMemorySettings { source: crate::crd::resource::Error },

    #[snafu(display("failed to construct the jvm.config"))]
    GetJvmConfig {
        source: crate::controller::build::jvm::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

const INDEXER_JAVA_OPTS: &str = "druid.indexer.runner.javaOptsArray";

/// The `druid.indexer.runner.javaOptsArray` entry that must be present in *every* rendered file
/// (runtime.properties and security.properties) for MiddleManagers.
fn middlemanager_indexer_java_opts() -> (String, String) {
    (
        INDEXER_JAVA_OPTS.to_string(),
        build_string_list(&[
            format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
            format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
            format!("-Djavax.net.ssl.trustStoreType={STACKABLE_TRUST_STORE_TYPE}"),
        ]),
    )
}

/// Returns the user-supplied key/value overrides for the given config file from a
/// [`DruidConfigOverrides`].
fn key_value_overrides(
    overrides: &DruidConfigOverrides,
    file: ConfigFileName,
) -> BTreeMap<String, String> {
    match file {
        ConfigFileName::RuntimeProperties => overrides.runtime_properties.overrides.clone(),
        ConfigFileName::SecurityProperties => overrides.security_properties.overrides.clone(),
        // log4j2.properties is rendered by the logging framework, and jvm.config is rendered from
        // JVM argument overrides; neither is assembled from key/value overrides here.
        ConfigFileName::Log4j2Properties | ConfigFileName::JvmConfig => BTreeMap::new(),
    }
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
pub fn build_rolegroup_config_map(
    cluster: &ValidatedCluster,
    role: &DruidRole,
    role_group_name: &RoleGroupName,
    rg: &DruidRoleGroupConfig,
) -> Result<ConfigMap> {
    let resource_names = cluster.resource_names(role, role_group_name);
    let cluster_config = &cluster.cluster_config;
    let druid_tls_security = &cluster_config.druid_tls_security;
    let druid_auth_config = &cluster_config.druid_auth_config;
    let zk_connstr = cluster_config.zookeeper_connection_string.as_str();
    let opa_connstr = cluster_config.opa_connection_string.as_deref();
    let s3_conn = cluster_config.s3_connection.as_ref();
    let deep_storage_bucket_name = cluster_config.deep_storage_bucket_name.as_deref();

    let mut cm_conf_data = BTreeMap::new(); // filename -> filecontent
    let metadata_database_connection_details = &cluster_config.metadata_db_connection;

    // ----- runtime.properties -----
    {
        let mut conf: BTreeMap<String, String> = Default::default();

        // Add any properties derived from storage manifests, such as segment cache locations.
        // This has to be done here since there is no other suitable place for it.
        // Previously such properties were added in the compute_files() function,
        // but that code path is now incompatible with the design of fragment merging.
        rg.config
            .resources
            .update_druid_config_file(&mut conf)
            .context(UpdateDruidConfigFromResourcesSnafu)?;
        // NOTE: druid.host can be set manually - if it isn't, the canonical host name of
        // the local host is used.  This should work with the agent and k8s host networking
        // but might need to be revisited in the future
        conf.insert(
            ZOOKEEPER_CONNECTION_STRING.to_string(),
            zk_connstr.to_string(),
        );

        let extensions = get_extension_list(
            &cluster_config.metadata_database,
            druid_tls_security.tls_enabled(),
            cluster_config.uses_s3(),
            &cluster_config.additional_extensions,
            druid_auth_config,
        );
        conf.insert(
            EXTENSIONS_LOADLIST.to_string(),
            build_string_list(&extensions),
        );

        if let Some(opa_str) = opa_connstr {
            conf.insert(AUTH_AUTHORIZER_OPA_URI.to_string(), opa_str.to_string());
        };

        conf.insert(
            crate::crd::database::METADATA_STORAGE_TYPE.to_string(),
            cluster_config
                .metadata_database
                .as_metadata_storage_type()
                .to_string(),
        );

        conf.insert(
            crate::crd::database::METADATA_STORAGE_CONNECTOR_CONNECT_URI.to_string(),
            metadata_database_connection_details
                .connection_url
                .to_string(),
        );

        if let Some(EnvVar {
            name: username_env_name,
            ..
        }) = &metadata_database_connection_details.username_env
        {
            conf.insert(
                crate::crd::database::METADATA_STORAGE_USER.to_string(),
                env_var_reference(username_env_name),
            );
        }

        if let Some(EnvVar {
            name: password_env_name,
            ..
        }) = &metadata_database_connection_details.password_env
        {
            conf.insert(
                crate::crd::database::METADATA_STORAGE_PASSWORD.to_string(),
                env_var_reference(password_env_name),
            );
        }

        if let Some(s3) = s3_conn {
            if !s3.region.is_default_config() {
                // Raising this as warning instead of returning an error, better safe than sorry.
                // It might still work out for the user.
                tracing::warn!(
                    region = ?s3.region,
                    "You configured a non-default region on the S3Connection.
                    The S3Connection region field is ignored because Druid uses the AWS SDK v1, which ignores the region if the endpoint is set. \
                    The host is a required field, therefore the endpoint will always be set."
                )
            }

            conf.insert(
                S3_ENDPOINT_URL.to_string(),
                s3.endpoint().context(ConfigureS3Snafu)?.to_string(),
            );

            if let Some((access_key_file, secret_key_file)) = s3.credentials_mount_paths() {
                conf.insert(S3_ACCESS_KEY.to_string(), file_reference(access_key_file));
                conf.insert(S3_SECRET_KEY.to_string(), file_reference(secret_key_file));
            }

            conf.insert(
                S3_PATH_STYLE_ACCESS.to_string(),
                (s3.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string(),
            );
        }
        // When no deep-storage bucket is set (e.g. HDFS deep storage) this renders an empty
        // `druid.storage.bucket=`, matching the previous `None` -> empty-value behavior.
        conf.insert(
            DS_BUCKET.to_string(),
            deep_storage_bucket_name.unwrap_or_default().to_string(),
        );

        // add tls encryption / auth properties
        add_tls_config_properties(druid_tls_security, &mut conf, role);

        if let Some(auth_config) = druid_auth_config {
            conf.extend(
                generate_auth_runtime_properties(auth_config, role)
                    .context(GenerateAuthenticationRuntimeSettingsSnafu)?,
            );
        };

        // Role/rolegroup runtime.properties: the recommended cluster-config-derived properties,
        // the MiddleManager indexer opts, the per-role defaults and finally the user overrides
        // (each layer wins over the previous, and over the cluster-level properties above).
        conf.extend(runtime_properties::cluster_runtime_properties(
            &cluster_config.deep_storage,
            cluster_config.opa_connection_string.is_some(),
        ));
        if *role == DruidRole::MiddleManager {
            let (k, v) = middlemanager_indexer_java_opts();
            conf.insert(k, v);
        }
        conf.extend(runtime_properties::defaults(role));
        conf.extend(key_value_overrides(
            &rg.config_overrides,
            ConfigFileName::RuntimeProperties,
        ));

        let runtime_properties =
            to_java_properties_string(conf.iter()).context(SerializeRuntimePropertiesSnafu)?;
        cm_conf_data.insert(
            ConfigFileName::RuntimeProperties.to_string(),
            runtime_properties,
        );
    }

    // ----- jvm.config -----
    {
        let (heap, direct) = rg
            .config
            .resources
            .get_memory_sizes(role)
            .context(DeriveMemorySettingsSnafu)?;
        let jvm_config = construct_jvm_args(
            role,
            &rg.product_specific_common_config.jvm_argument_overrides,
            heap,
            direct,
        )
        .context(GetJvmConfigSnafu)?;
        cm_conf_data.insert(ConfigFileName::JvmConfig.to_string(), jvm_config);
    }

    // ----- security.properties -----
    {
        let mut security_config: BTreeMap<String, String> = BTreeMap::new();
        if *role == DruidRole::MiddleManager {
            let (k, v) = middlemanager_indexer_java_opts();
            security_config.insert(k, v);
        }
        let security_overrides =
            key_value_overrides(&rg.config_overrides, ConfigFileName::SecurityProperties);
        security_config.extend(security_properties::build(security_overrides));

        cm_conf_data.insert(
            ConfigFileName::SecurityProperties.to_string(),
            to_java_properties_string(security_config.iter()).with_context(|_| {
                JvmSecurityPropertiesSnafu {
                    rolegroup: role_group_name.to_string(),
                }
            })?,
        );
    }

    let mut config_map_builder = ConfigMapBuilder::new();
    config_map_builder.metadata(
        cluster
            .object_meta(
                resource_names.role_group_config_map().to_string(),
                role,
                role_group_name,
            )
            .build(),
    );

    for (filename, file_content) in cm_conf_data.iter() {
        config_map_builder.add_data(filename, file_content);
    }

    if let Some(log4j2_config) = build_log4j2(&rg.config.logging.druid_container) {
        config_map_builder.add_data(ConfigFileName::Log4j2Properties.to_string(), log4j2_config);
    }

    // The Vector agent config (`vector.yaml`) is a static, env-var-parameterized file (mirroring
    // the hive-/opensearch-operator). It is only added when the Vector agent is enabled.
    if rg.config.logging.enable_vector_agent {
        config_map_builder.add_data(VECTOR_CONFIG_FILE, vector_config_file_content());
    }

    config_map_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            role_group: role_group_name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stackable_operator::{
        k8s_openapi::api::core::v1::ConfigMap, v2::types::operator::RoleGroupName,
    };

    use super::*;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    /// Builds the rolegroup `ConfigMap` for `<role>/<role_group>` from the minimal test fixture.
    fn build_cm(role: DruidRole, role_group: &str) -> ConfigMap {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let role_group_name = RoleGroupName::from_str(role_group).unwrap();
        let rg = cluster
            .role_group_configs
            .get(&role)
            .expect("role present")
            .get(&role_group_name)
            .expect("role group present")
            .clone();
        build_rolegroup_config_map(&cluster, &role, &role_group_name, &rg).expect("config map")
    }

    #[test]
    fn contains_the_operator_written_config_files() {
        let cm = build_cm(DruidRole::Broker, "default");
        let data = cm.data.expect("config map has data");

        // Always-present operator-written files.
        assert!(data.contains_key(&ConfigFileName::RuntimeProperties.to_string()));
        assert!(data.contains_key(&ConfigFileName::SecurityProperties.to_string()));
        assert!(data.contains_key(&ConfigFileName::JvmConfig.to_string()));
        // Automatic logging is the default, so log4j2 is rendered.
        assert!(data.contains_key(&ConfigFileName::Log4j2Properties.to_string()));
        // The Vector agent is disabled by default, so no `vector.yaml` is added.
        assert!(!data.contains_key(VECTOR_CONFIG_FILE));
    }

    #[test]
    fn has_the_expected_name_and_recommended_labels() {
        let cm = build_cm(DruidRole::Broker, "default");
        let meta = cm.metadata;

        assert_eq!(meta.name.as_deref(), Some("simple-druid-broker-default"));

        let labels = meta.labels.expect("recommended labels");
        assert_eq!(
            labels.get("app.kubernetes.io/name").map(String::as_str),
            Some("druid")
        );
        assert_eq!(
            labels.get("app.kubernetes.io/instance").map(String::as_str),
            Some("simple-druid")
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some("broker")
        );
        assert_eq!(
            labels
                .get("app.kubernetes.io/role-group")
                .map(String::as_str),
            Some("default")
        );
    }
}
