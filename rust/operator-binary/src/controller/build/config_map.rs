//! Builds the rolegroup [`ConfigMap`] from a [`ValidatedCluster`].
//!
//! The per-file "validated config" maps (runtime.properties / security.properties) are taken
//! from the [`DruidRoleGroupConfig`] precomputed in the validate step; product-config is no
//! longer involved.
//!
//! Residual reads from the owning [`v1alpha1::DruidCluster`] remain for things that are not yet
//! modelled on `ValidatedCluster`: the owner reference + recommended labels, the extensions load
//! list (`get_extension_list`), the metadata-database connection
//! (`spec.cluster_config.metadata_database` / `as_metadata_storage_type`), and `get_role` for the
//! jvm.config. Fully removing these is a follow-up.

use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    crd::s3,
    database_connections::drivers::jdbc::JdbcDatabaseConnection as _,
    k8s_openapi::api::core::v1::{ConfigMap, EnvVar},
    role_utils::RoleGroupRef,
};

use crate::{
    config::jvm::construct_jvm_args,
    controller::{
        DRUID_CONTROLLER_NAME,
        build::properties::{ConfigFileName, writer::to_java_properties_string},
        validate::{DruidRoleGroupConfig, ValidatedCluster},
    },
    crd::{
        AUTH_AUTHORIZER_OPA_URI, DS_BUCKET, DruidRole, EXTENSIONS_LOADLIST, S3_ACCESS_KEY,
        S3_ENDPOINT_URL, S3_PATH_STYLE_ACCESS, S3_SECRET_KEY, ZOOKEEPER_CONNECTION_STRING,
        build_recommended_labels, build_string_list, v1alpha1,
    },
    extensions::get_extension_list,
    product_logging::extend_role_group_config_map,
};

// jvm.config is built by `config::jvm`, not a properties builder, so it is not part
// of `ConfigFileName`.
const JVM_CONFIG: &str = "jvm.config";

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<v1alpha1::DruidCluster>,
    },

    #[snafu(display("failed to configure S3 connection"))]
    ConfigureS3 {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to serialize [runtime.properties]"))]
    SerializeRuntimeProperties {
        source: crate::controller::build::properties::writer::PropertiesWriterError,
    },

    #[snafu(display("failed to serialize [security.properties] for {rolegroup}"))]
    JvmSecurityProperties {
        source: crate::controller::build::properties::writer::PropertiesWriterError,
        rolegroup: String,
    },

    #[snafu(display("failed to get JVM config"))]
    GetJvmConfig { source: crate::config::jvm::Error },

    #[snafu(display("failed to derive Druid memory settings from resources"))]
    DeriveMemorySettings { source: crate::crd::resource::Error },

    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources { source: crate::crd::resource::Error },

    #[snafu(display("failed to build metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("there was an error generating the authentication runtime settings"))]
    GenerateAuthenticationRuntimeSettings {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },

    #[snafu(display("invalid metadata database connection"))]
    InvalidMetadataDatabaseConnection {
        source: stackable_operator::database_connections::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
pub fn build_rolegroup_config_map(
    cluster: &ValidatedCluster,
    role: &DruidRole,
    rolegroup: &RoleGroupRef<v1alpha1::DruidCluster>,
    rg: &DruidRoleGroupConfig,
    owner: &v1alpha1::DruidCluster,
) -> Result<ConfigMap> {
    let cluster_config = &cluster.cluster_config;
    let druid_tls_security = &cluster_config.druid_tls_security;
    let druid_auth_config = &cluster_config.druid_auth_config;
    let zk_connstr = cluster_config.zookeeper_connection_string.as_str();
    let opa_connstr = cluster_config.opa_connection_string.as_deref();
    let s3_conn = cluster_config.s3_connection.as_ref();
    let deep_storage_bucket_name = cluster_config.deep_storage_bucket_name.as_deref();

    let role_obj = owner.get_role(role);
    let mut cm_conf_data = BTreeMap::new(); // filename -> filecontent
    let metadata_database_connection_details = owner
        .spec
        .cluster_config
        .metadata_database
        .jdbc_connection_details("metadata")
        .context(InvalidMetadataDatabaseConnectionSnafu)?;

    // ----- runtime.properties -----
    {
        let mut conf: BTreeMap<String, Option<String>> = Default::default();

        // Add any properties derived from storage manifests, such as segment cache locations.
        // This has to be done here since there is no other suitable place for it.
        // Previously such properties were added in the compute_files() function,
        // but that code path is now incompatible with the design of fragment merging.
        rg.merged_config
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
                owner,
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

        conf.insert(
            crate::crd::database::METADATA_STORAGE_TYPE.to_string(),
            Some(
                owner
                    .spec
                    .cluster_config
                    .metadata_database
                    .as_metadata_storage_type()
                    .to_string(),
            ),
        );

        conf.insert(
            crate::crd::database::METADATA_STORAGE_CONNECTOR_CONNECT_URI.to_string(),
            Some(
                metadata_database_connection_details
                    .connection_url
                    .to_string(),
            ),
        );

        if let Some(EnvVar {
            name: username_env_name,
            ..
        }) = &metadata_database_connection_details.username_env
        {
            conf.insert(
                crate::crd::database::METADATA_STORAGE_USER.to_string(),
                Some(format!("${{env:{username_env_name}}}",)),
            );
        }

        if let Some(EnvVar {
            name: password_env_name,
            ..
        }) = &metadata_database_connection_details.password_env
        {
            conf.insert(
                crate::crd::database::METADATA_STORAGE_PASSWORD.to_string(),
                Some(format!("${{env:{password_env_name}}}",)),
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
                Some((s3.access_style == s3::v1alpha1::S3AccessStyle::Path).to_string()),
            );
        }
        conf.insert(
            DS_BUCKET.to_string(),
            deep_storage_bucket_name.map(str::to_string),
        );

        // add tls encryption / auth properties
        druid_tls_security.add_tls_config_properties(&mut conf, role);

        if let Some(auth_config) = druid_auth_config {
            conf.extend(
                auth_config
                    .generate_runtime_properties_config(role)
                    .context(GenerateAuthenticationRuntimeSettingsSnafu)?,
            );
        };

        // extend the config to respect the precomputed defaults and overrides
        conf.extend(rg.runtime_config.clone());

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
            .merged_config
            .resources
            .get_memory_sizes(role)
            .context(DeriveMemorySettingsSnafu)?;
        let jvm_config = construct_jvm_args(role, &role_obj, &rolegroup.role_group, heap, direct)
            .context(GetJvmConfigSnafu)?;
        cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config);
    }

    // ----- security.properties -----
    {
        cm_conf_data.insert(
            ConfigFileName::SecurityProperties.to_string(),
            to_java_properties_string(rg.security_config.iter()).with_context(|_| {
                JvmSecurityPropertiesSnafu {
                    rolegroup: rolegroup.role_group.clone(),
                }
            })?,
        );
    }

    let mut config_map_builder = ConfigMapBuilder::new();
    config_map_builder.metadata(
        ObjectMetaBuilder::new()
            .name_and_namespace(owner)
            .name(rolegroup.object_name())
            .ownerreference_from_resource(owner, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&build_recommended_labels(
                owner,
                DRUID_CONTROLLER_NAME,
                &cluster.image.app_version_label_value,
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
        &rg.merged_config.logging,
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
