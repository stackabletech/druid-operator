//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::{get_jvm_config, get_log4j_config},
    discovery::{self, build_discovery_configmaps},
    extensions::get_extension_list,
    internal_secret::{
        build_shared_internal_secret_name, create_shared_internal_secret, env_var_from_secret,
        ENV_INTERNAL_SECRET,
    },
    OPERATOR_NAME,
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::build_recommended_labels;
use stackable_druid_crd::{
    authentication::ldap::{
        DruidLdapSettings, PLACEHOLDER_INTERNAL_CLIENT_PASSWORD, PLACEHOLDER_LDAP_BIND_PASSWORD,
        PLACEHOLDER_LDAP_BIND_USER,
    },
    authorization::DruidAuthorization,
    build_string_list,
    security::{resolve_authentication_classes, DruidTlsSecurity},
    CommonRoleGroupConfig, DeepStorageSpec, DruidCluster, DruidRole, APP_NAME,
    AUTH_AUTHORIZER_OPA_URI, CERTS_DIR, CREDENTIALS_SECRET_PROPERTY, DRUID_CONFIG_DIRECTORY,
    DS_BUCKET, EXTENSIONS_LOADLIST, HDFS_CONFIG_DIRECTORY, JVM_CONFIG, LOG4J2_CONFIG,
    RUNTIME_PROPS, RW_CONFIG_DIRECTORY, S3_ENDPOINT_URL, S3_PATH_STYLE_ACCESS, S3_SECRET_DIR_NAME,
    ZOOKEEPER_CONNECTION_STRING,
};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder,
    },
    cluster_resources::ClusterResources,
    commons::{
        opa::OpaApiVersion,
        product_image_selection::ResolvedProductImage,
        s3::{S3AccessStyle, S3ConnectionSpec},
        tls::{CaCert, TlsVerification},
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, EnvVar, Service, ServiceSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        Resource,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::RoleGroupRef,
};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

pub const CONTROLLER_NAME: &str = "druidcluster";

const DOCKER_IMAGE_BASE_NAME: &str = "druid";

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
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display(
        "failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display("failed to get valid S3 connection"))]
    GetS3Connection { source: stackable_druid_crd::Error },
    #[snafu(display("failed to get deep storage bucket"))]
    GetDeepStorageBucket {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },
    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("failed to format runtime properties"))]
    PropertiesWriteError {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("failed to build discovery ConfigMap"))]
    BuildDiscoveryConfig { source: discovery::Error },
    #[snafu(display("failed to apply discovery ConfigMap"))]
    ApplyDiscoveryConfig {
        source: stackable_operator::error::Error,
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
    FailedToResolveConfig { source: stackable_druid_crd::Error },
    #[snafu(display("invalid configuration"))]
    InvalidConfiguration { source: stackable_druid_crd::Error },
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to create container builder with name [{name}]"))]
    FailedContainerBuilderCreation {
        source: stackable_operator::error::Error,
        name: String,
    },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext {
        source: stackable_druid_crd::security::Error,
    },
    #[snafu(display("failed to get JVM config"))]
    GetJvmConfig { source: crate::config::Error },
    #[snafu(display("failed to derive Druid memory settings from resources"))]
    DeriveMemorySettings {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("failed to update Druid config from resources"))]
    UpdateDruidConfigFromResources {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation {
        source: crate::internal_secret::Error,
    },
    #[snafu(display(
        "failed to access bind credentials although they are required for LDAP to work"
    ))]
    LdapBindCredentialsAreRequired,
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(druid: Arc<DruidCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");
    let client = &ctx.client;
    let namespace = &druid
        .metadata
        .namespace
        .clone()
        .with_context(|| ObjectHasNoNamespaceSnafu {})?;
    let resolved_product_image: ResolvedProductImage =
        druid.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);

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

    // Assemble the OPA connection string from the discovery and the given path, if a spec is given.
    let opa_connstr = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(
                    client,
                    druid.deref(),
                    Some("allow"),
                    OpaApiVersion::V1,
                )
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
        DeepStorageSpec::S3(s3_spec) => {
            s3_spec
                .bucket
                .resolve(client, namespace)
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name
        }
        _ => None,
    };

    let resolved_authentication_classes = resolve_authentication_classes(client, &druid)
        .await
        .context(FailedToInitializeSecurityContextSnafu)?;

    let druid_ldap_settings = DruidLdapSettings::new_from(&resolved_authentication_classes);

    let druid_tls_security =
        DruidTlsSecurity::new_from_druid_cluster(&druid, resolved_authentication_classes);

    let role_config = transform_all_roles_to_config(druid.as_ref(), druid.build_role_properties());
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
        CONTROLLER_NAME,
        &druid.object_ref(&()),
    )
    .context(CreateClusterResourcesSnafu)?;

    let merged_config = druid.merged_config().context(FailedToResolveConfigSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(
            &druid,
            &resolved_product_image,
            &druid_role,
            &druid_tls_security,
        )?;
        cluster_resources
            .add(client, &role_service)
            .await
            .context(ApplyRoleServiceSnafu)?;

        create_shared_internal_secret(&druid, client, CONTROLLER_NAME)
            .await
            .context(FailedInternalSecretCreationSnafu)?;

        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let merged_rolegroup_config = merged_config
                .common_config(druid_role.clone(), rolegroup_name)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_services(
                &druid,
                &resolved_product_image,
                &rolegroup,
                &druid_tls_security,
            )?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                &zk_connstr,
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                s3_conn.as_ref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            cluster_resources
                .add(client, &rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            cluster_resources
                .add(client, &rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            cluster_resources
                .add(client, &rg_statefulset)
                .await
                .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
        }
    }

    // discovery
    for discovery_cm in build_discovery_configmaps(
        &druid,
        &*druid,
        &resolved_product_image,
        &druid_tls_security,
    )
    .await
    .context(BuildDiscoveryConfigSnafu)?
    {
        cluster_resources
            .add(client, &discovery_cm)
            .await
            .context(ApplyDiscoveryConfigSnafu)?;
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(Action::await_change())
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
pub fn build_role_service(
    druid: &DruidCluster,
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
                CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &role_name,
                "global",
            ))
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(druid_tls_security.service_ports(role)),
            selector: Some(role_selector_labels(druid, APP_NAME, &role_name)),
            type_: Some("NodePort".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

#[allow(clippy::too_many_arguments)]
/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    druid: &DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_rolegroup_config: &CommonRoleGroupConfig,
    zk_connstr: &str,
    opa_connstr: Option<&str>,
    s3_conn: Option<&S3ConnectionSpec>,
    deep_storage_bucket_name: Option<&str>,
    druid_tls_security: &DruidTlsSecurity,
    druid_ldap_settings: &Option<DruidLdapSettings>,
) -> Result<ConfigMap> {
    let role = DruidRole::from_str(&rolegroup.role).unwrap();
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
                    ))),
                );

                if let Some(opa_str) = opa_connstr {
                    conf.insert(
                        AUTH_AUTHORIZER_OPA_URI.to_string(),
                        Some(opa_str.to_string()),
                    );
                };

                if let Some(conn) = s3_conn {
                    if let Some(endpoint) = conn.endpoint() {
                        conf.insert(S3_ENDPOINT_URL.to_string(), Some(endpoint));
                    }

                    // We did choose a match statement here to detect new access styles in the future
                    let path_style_access = match conn.access_style.clone().unwrap_or_default() {
                        S3AccessStyle::Path => true,
                        S3AccessStyle::VirtualHosted => false,
                    };
                    conf.insert(
                        S3_PATH_STYLE_ACCESS.to_string(),
                        Some(path_style_access.to_string()),
                    );
                }
                conf.insert(
                    DS_BUCKET.to_string(),
                    deep_storage_bucket_name.map(str::to_string),
                );

                // add tls encryption / auth properties
                druid_tls_security.add_tls_config_properties(&mut conf, &role);

                if let Some(ldap_settings) = druid_ldap_settings {
                    conf.extend(ldap_settings.generate_runtime_properties_config());
                };

                let transformed_config: BTreeMap<String, Option<String>> = config
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect();
                // extend the config to respect overrides
                conf.extend(transformed_config);

                let runtime_properties =
                    stackable_operator::product_config::writer::to_java_properties_string(
                        conf.iter(),
                    )
                    .context(PropertiesWriteSnafu)?;
                cm_conf_data.insert(RUNTIME_PROPS.to_string(), runtime_properties);
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let (heap, direct) = merged_rolegroup_config
                    .resources
                    .get_memory_sizes(&role)
                    .context(DeriveMemorySettingsSnafu)?;
                let jvm_config = get_jvm_config(&role, heap, direct).context(GetJvmConfigSnafu)?;
                // the user can set overrides in the config, but currently they have no effect
                // if this is changed in the future, make sure to respect overrides!
                cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config);
            }
            PropertyNameKind::File(file_name) if file_name == LOG4J2_CONFIG => {
                let log_config = get_log4j_config(&role);
                // the user can set overrides in the config, but currently they have no effect
                // if this is changed in the future, make sure to respect overrides!
                cm_conf_data.insert(LOG4J2_CONFIG.to_string(), log_config);
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
                CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .build(),
    );
    for (filename, file_content) in cm_conf_data.iter() {
        config_map_builder.add_data(filename, file_content);
    }
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
    druid: &DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<DruidCluster>,
    druid_tls_security: &DruidTlsSecurity,
) -> Result<Service> {
    let role = DruidRole::from_str(&rolegroup.role).unwrap();

    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(druid_tls_security.service_ports(&role)),
            selector: Some(role_group_selector_labels(
                druid,
                APP_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )),
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
    druid: &DruidCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_rolegroup_config: &CommonRoleGroupConfig,
    s3_conn: Option<&S3ConnectionSpec>,
    druid_tls_security: &DruidTlsSecurity,
    ldap_settings: &Option<DruidLdapSettings>,
) -> Result<StatefulSet> {
    let role = DruidRole::from_str(&rolegroup_ref.role).context(UnidentifiedDruidRoleSnafu {
        role: rolegroup_ref.role.to_string(),
    })?;

    // init container builder
    let mut cb_prepare = ContainerBuilder::new("prepare")
        .context(FailedContainerBuilderCreationSnafu { name: "prepare" })?;
    // druid container builder
    let mut cb_druid = ContainerBuilder::new(APP_NAME)
        .context(FailedContainerBuilderCreationSnafu { name: APP_NAME })?;
    // init pod builder
    let mut pb = PodBuilder::new();
    pb.affinity(&merged_rolegroup_config.affinity);

    if let Some(ldap_settings) = ldap_settings {
        // TODO: Connecting to an LDAP server without bind credentials does not seem to be configurable in Druid at the moment
        // see https://github.com/stackabletech/druid-operator/issues/383 for future work.
        // Expect bind credentials to be provided for now, and throw return a useful error if there are none.
        if ldap_settings.ldap.bind_credentials.is_none() {
            return LdapBindCredentialsAreRequiredSnafu.fail();
        }

        ldap_settings
            .ldap
            .add_volumes_and_mounts(&mut pb, vec![&mut cb_druid]);
    }
    let ldap_auth_cmd = get_ldap_secret_placeholder_replacement_commands(ldap_settings)?;

    // volume and volume mounts
    druid_tls_security
        .add_tls_volume_and_volume_mounts(&mut cb_prepare, &mut cb_druid, &mut pb)
        .context(FailedToInitializeSecurityContextSnafu)?;
    add_s3_volume_and_volume_mounts(s3_conn, &mut cb_druid, &mut pb)?;
    add_config_volume_and_volume_mounts(rolegroup_ref, &mut cb_druid, &mut pb);
    add_hdfs_cm_volume_and_volume_mounts(
        &druid.spec.cluster_config.deep_storage,
        &mut cb_druid,
        &mut pb,
    );
    merged_rolegroup_config
        .resources
        .update_volumes_and_volume_mounts(&mut cb_druid, &mut pb);

    let prepare_container_command = druid_tls_security.build_tls_key_stores_cmd();

    cb_prepare
        .image_from_product_image(resolved_product_image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![prepare_container_command.join(" && ")])
        .build();

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

    let secret_name = build_shared_internal_secret_name(druid);
    rest_env.push(env_var_from_secret(&secret_name, None, ENV_INTERNAL_SECRET));

    cb_druid
        .image_from_product_image(resolved_product_image)
        .command(role.get_command(s3_conn, ldap_auth_cmd))
        .add_env_vars(rest_env)
        .add_container_ports(druid_tls_security.container_ports(&role))
        // 10s * 30 = 300s to come up
        .startup_probe(druid_tls_security.get_tcp_socket_probe(30, 10, 30, 3))
        // 10s * 1 = 10s to get removed from service
        .readiness_probe(druid_tls_security.get_tcp_socket_probe(10, 10, 1, 3))
        // 10s * 3 = 30s to be restarted
        .liveness_probe(druid_tls_security.get_tcp_socket_probe(10, 10, 3, 3))
        .resources(merged_rolegroup_config.resources.as_resource_requirements());

    pb.image_pull_secrets_from_product_image(resolved_product_image)
        .add_init_container(cb_prepare.build())
        .add_container(cb_druid.build())
        .metadata_builder(|m| {
            m.with_recommended_labels(build_recommended_labels(
                druid,
                CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
        })
        .security_context(
            PodSecurityContextBuilder::new()
                .run_as_user(1000)
                .run_as_group(1000)
                .fs_group(1000)
                .build(),
        );

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: if druid.spec.stopped.unwrap_or(false) {
                Some(0)
            } else {
                merged_rolegroup_config.replicas.map(i32::from)
            },
            selector: LabelSelector {
                match_labels: Some(role_group_selector_labels(
                    druid,
                    APP_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )),
                ..LabelSelector::default()
            },
            service_name: rolegroup_ref.object_name(),
            template: pb.build_template(),
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
    if let DeepStorageSpec::HDFS(hdfs) = deep_storage_spec {
        cb_druid.add_volume_mount("hdfs", HDFS_CONFIG_DIRECTORY);
        pb.add_volume(
            VolumeBuilder::new("hdfs")
                .with_config_map(&hdfs.config_map_name)
                .build(),
        );
    }
}

fn get_ldap_secret_placeholder_replacement_commands(
    ldap_settings: &Option<DruidLdapSettings>,
) -> Result<Vec<String>, Error> {
    let mut commands = Vec::new();

    if let Some(ldap_settings) = ldap_settings {
        let runtime_properties_file: String = format!("{RW_CONFIG_DIRECTORY}/{RUNTIME_PROPS}");

        let internal_client_password = format!("$(echo ${ENV_INTERNAL_SECRET})");

        commands
                .push(r#"echo "Replacing LDAP placeholders with their proper values in {RUNTIME_PROPERTIES_FILE}""#.to_string());
        commands.push(format!(
            r#"sed "s|{PLACEHOLDER_INTERNAL_CLIENT_PASSWORD}|{internal_client_password}|g" -i {runtime_properties_file}"# // using another delimeter (|) here because of base64 string
        ));

        if let Some((ldap_bind_user_path, ldap_bind_password_path)) =
            ldap_settings.ldap.bind_credentials_mount_paths()
        {
            let ldap_bind_user = format!("$(cat {ldap_bind_user_path})");
            let ldap_bind_password = format!("$(cat {ldap_bind_password_path})");

            commands.push(format!(
                    r#"sed "s/{PLACEHOLDER_LDAP_BIND_USER}/{ldap_bind_user}/g" -i {runtime_properties_file}"#
                ));
            commands.push(format!(
                    r#"sed "s/{PLACEHOLDER_LDAP_BIND_PASSWORD}/{ldap_bind_password}/g" -i {runtime_properties_file}"#
                ));
        }
    }
    Ok(commands)
}

fn add_config_volume_and_volume_mounts(
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    cb_druid.add_volume_mount("config", DRUID_CONFIG_DIRECTORY);
    pb.add_volume(
        VolumeBuilder::new("config")
            .with_config_map(rolegroup_ref.object_name())
            .build(),
    );
    cb_druid.add_volume_mount("rwconfig", RW_CONFIG_DIRECTORY);
    pb.add_volume(
        VolumeBuilder::new("rwconfig")
            .with_empty_dir(Some(""), None)
            .build(),
    );
}

fn add_s3_volume_and_volume_mounts(
    s3_conn: Option<&S3ConnectionSpec>,
    cb_druid: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    if let Some(s3_conn) = s3_conn {
        if let Some(credentials) = &s3_conn.credentials {
            pb.add_volume(credentials.to_volume("s3-credentials"));
            cb_druid.add_volume_mount("s3-credentials", S3_SECRET_DIR_NAME);
        }

        if let Some(tls) = &s3_conn.tls {
            match &tls.verification {
                TlsVerification::None {} => return S3TlsNoVerificationNotSupportedSnafu.fail(),
                TlsVerification::Server(server_verification) => {
                    match &server_verification.ca_cert {
                        CaCert::WebPki {} => {}
                        CaCert::SecretClass(secret_class) => {
                            let volume_name = format!("{secret_class}-tls-certificate");

                            let volume = VolumeBuilder::new(&volume_name)
                                .ephemeral(
                                    SecretOperatorVolumeSourceBuilder::new(secret_class).build(),
                                )
                                .build();
                            pb.add_volume(volume);
                            cb_druid.add_volume_mount(
                                &volume_name,
                                format!("{CERTS_DIR}/{volume_name}"),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn error_policy(_obj: Arc<DruidCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;
    use stackable_druid_crd::{
        authentication::ResolvedAuthenticationClasses, PROP_SEGMENT_CACHE_LOCATIONS,
    };
    use stackable_operator::product_config::{writer, ProductConfigManager};

    #[derive(Snafu, Debug, EnumDiscriminants)]
    #[strum_discriminants(derive(IntoStaticStr))]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        #[snafu(display("controller error"))]
        Controller { source: super::Error },
        #[snafu(display("product config error"))]
        ProductConfig {
            source: stackable_operator::product_config::error::Error,
        },
        #[snafu(display("product config utils error"))]
        ProductConfigUtils {
            source: stackable_operator::product_config_utils::ConfigError,
        },
        #[snafu(display("operator framework error"))]
        OperatorFramework {
            source: stackable_operator::error::Error,
        },
        #[snafu(display("failed to resolve and merge config for role and role group"))]
        FailedToResolveConfig { source: stackable_druid_crd::Error },
        #[snafu(display("invalid configuration"))]
        InvalidConfiguration { source: stackable_druid_crd::Error },
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
    ) -> Result<(), Error> {
        let cluster_cr =
            std::fs::File::open(format!("test/resources/druid_controller/{druid_manifest}"))
                .unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let resolved_product_image: ResolvedProductImage =
            druid.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);
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
            ResolvedAuthenticationClasses::new(vec![]),
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
                        .common_config(DruidRole::Historical, rolegroup_name)
                        .context(InvalidConfigurationSnafu)?;

                    let ldap_settings: Option<DruidLdapSettings> = None;

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
                        &druid_tls_security,
                        &ldap_settings,
                    )
                    .context(ControllerSnafu)?;

                    druid_segment_cache_property = rg_configmap
                        .data
                        .unwrap()
                        .get(&RUNTIME_PROPS.to_string())
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
