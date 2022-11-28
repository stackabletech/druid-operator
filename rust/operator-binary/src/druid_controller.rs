//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::{get_jvm_config, get_log4j_config},
    discovery::{self, build_discovery_configmaps},
};

use crate::OPERATOR_NAME;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    authentication, authentication::DruidAuthentication, tls, DeepStorageSpec, DruidAuthorization,
    DruidCluster, DruidRole, APP_NAME, AUTH_AUTHORIZER_OPA_URI, CERTS_DIR,
    CREDENTIALS_SECRET_PROPERTY, DRUID_CONFIG_DIRECTORY, DS_BUCKET, HDFS_CONFIG_DIRECTORY,
    JVM_CONFIG, LOG4J2_CONFIG, RUNTIME_PROPS, RW_CONFIG_DIRECTORY, S3_ENDPOINT_URL,
    S3_PATH_STYLE_ACCESS, S3_SECRET_DIR_NAME, ZOOKEEPER_CONNECTION_STRING,
};
use stackable_druid_crd::{
    build_recommended_labels,
    resource::{self, RoleResource},
    tls::DruidTlsSettings,
};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, SecurityContextBuilder,
        VolumeBuilder,
    },
    cluster_resources::ClusterResources,
    commons::{
        authentication::AuthenticationClassProvider,
        opa::OpaApiVersion,
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
    memory::{to_java_heap_value, BinaryMultiple},
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

const JVM_HEAP_FACTOR: f32 = 0.8;
pub const CONTROLLER_NAME: &str = "druidcluster";

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
        "Failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display(
        "Failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display("Failed to get valid S3 connection"))]
    GetS3Connection { source: stackable_druid_crd::Error },
    #[snafu(display("Failed to get deep storage bucket"))]
    GetDeepStorageBucket {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "Failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },
    #[snafu(display("Failed to get OPA discovery config map for cluster: {}", cm_name))]
    GetOpaConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display("Failed to get OPA connection string from config map {}", cm_name))]
    MissingOpaConnString { cm_name: String },
    #[snafu(display("Failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("Failed to format runtime properties"))]
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
    #[snafu(display("failed to resolve and merge resource config for role and role group"))]
    FailedToResolveResourceConfig {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("invalid java heap config - missing default or value in crd?"))]
    InvalidJavaHeapConfig,
    #[snafu(display("failed to convert java heap config to unit [{unit}]"))]
    FailedToConvertJavaHeap {
        source: stackable_operator::error::Error,
        unit: String,
    },
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
    #[snafu(display("no quantity unit (k, m, g, etc.) given for [{value}]"))]
    NoQuantityUnit { value: String },
    #[snafu(display("invalid quantity value"))]
    InvalidQuantityValue { source: std::num::ParseIntError },
    #[snafu(display("segment cache location is required but missing"))]
    NoSegmentCacheLocation,
    #[snafu(display("role group and resource type mismatch. this is a programming error."))]
    RoleResourceMismatch,
    #[snafu(display("invalid authentication configuration"))]
    InvalidAuthenticationConfig { source: authentication::Error },
    #[snafu(display("invalid tls configuration"))]
    InvalidTlsConfig { source: tls::Error },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
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

    // Get possible authentication methods
    let resolved_authentication_config = DruidAuthentication::resolve(client, &druid)
        .await
        .context(InvalidAuthenticationConfigSnafu)?;

    // TODO: this is fishy! why ignore the spec.cluster_config.tls ?
    let mut tls_authentication_config = None;
    for auth_conf in resolved_authentication_config.into_iter() {
        if let AuthenticationClassProvider::Tls(_) = auth_conf {
            tls_authentication_config = Some(auth_conf);
        }
    }

    // Extract TLS encryption and TLS auth provider if available
    let druid_tls_settings = DruidTlsSettings {
        encryption: druid.spec.cluster_config.tls.clone(),
        // There can currently only be one TLS authentication config, so if we find it we can just
        // take ownership.
        authentication: tls_authentication_config,
    };

    // False positive, auto-deref breaks type inference
    #[allow(clippy::explicit_auto_deref)]
    let role_config = transform_all_roles_to_config(&*druid, druid.build_role_properties());
    let validated_role_config = validate_all_roles_and_groups_config(
        druid.version(),
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

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(&druid, &druid_role, &druid_tls_settings)?;
        cluster_resources
            .add(client, &role_service)
            .await
            .context(ApplyRoleServiceSnafu)?;
        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let resources = resource::resources(&druid, &druid_role, &rolegroup)
                .context(FailedToResolveResourceConfigSnafu)?;

            let rg_service = build_rolegroup_services(&druid, &rolegroup, &druid_tls_settings)?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &rolegroup,
                rolegroup_config,
                &zk_connstr,
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
                &resources,
                &druid_tls_settings,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &rolegroup,
                rolegroup_config,
                s3_conn.as_ref(),
                &resources,
                &druid_tls_settings,
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
    for discovery_cm in build_discovery_configmaps(&druid, &*druid)
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
    role: &DruidRole,
    tls_settings: &DruidTlsSettings,
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
                druid.version(),
                &role_name,
                "global",
            ))
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(tls_settings.service_ports(role)),
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
    rolegroup: &RoleGroupRef<DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    zk_connstr: &str,
    opa_connstr: Option<&str>,
    s3_conn: Option<&S3ConnectionSpec>,
    deep_storage_bucket_name: Option<&str>,
    resources: &RoleResource,
    tls_settings: &DruidTlsSettings,
) -> Result<ConfigMap> {
    let role = DruidRole::from_str(&rolegroup.role).unwrap();
    let mut cm_conf_data = BTreeMap::new(); // filename -> filecontent

    for (property_name_kind, config) in rolegroup_config {
        let mut transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == RUNTIME_PROPS => {
                // Add any properties derived from storage manifests, such as segment cache locations.
                // This has to be done here since there is no other suitable place for it.
                // Previously such properties were added in the compute_files() function,
                // but that code path is now incompatible with the design of fragment merging.
                resources.update_druid_config_file(file_name.as_str(), &mut transformed_config);
                // NOTE: druid.host can be set manually - if it isn't, the canonical host name of
                // the local host is used.  This should work with the agent and k8s host networking
                // but might need to be revisited in the future
                transformed_config.insert(
                    ZOOKEEPER_CONNECTION_STRING.to_string(),
                    Some(zk_connstr.to_string()),
                );
                if let Some(opa_str) = opa_connstr {
                    transformed_config.insert(
                        AUTH_AUTHORIZER_OPA_URI.to_string(),
                        Some(opa_str.to_string()),
                    );
                };
                if let Some(conn) = s3_conn {
                    if let Some(endpoint) = conn.endpoint() {
                        transformed_config.insert(S3_ENDPOINT_URL.to_string(), Some(endpoint));
                    }

                    // We did choose a match statement here to detect new access styles in the future
                    let path_style_access = match conn.access_style.clone().unwrap_or_default() {
                        S3AccessStyle::Path => true,
                        S3AccessStyle::VirtualHosted => false,
                    };
                    transformed_config.insert(
                        S3_PATH_STYLE_ACCESS.to_string(),
                        Some(path_style_access.to_string()),
                    );
                }
                transformed_config.insert(
                    DS_BUCKET.to_string(),
                    deep_storage_bucket_name.map(str::to_string),
                );

                // add tls encryption / auth properties
                tls_settings.add_tls_config_properties(&mut transformed_config, &role);

                let runtime_properties =
                    stackable_operator::product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )
                    .context(PropertiesWriteSnafu)?;
                cm_conf_data.insert(RUNTIME_PROPS.to_string(), runtime_properties);
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let heap_in_mebi = to_java_heap_value(
                    resources
                        .as_memory_limits()
                        .limit
                        .as_ref()
                        .context(InvalidJavaHeapConfigSnafu)?,
                    JVM_HEAP_FACTOR,
                    BinaryMultiple::Mebi,
                )
                .context(FailedToConvertJavaHeapSnafu {
                    unit: BinaryMultiple::Mebi.to_java_memory_unit(),
                })?;

                let jvm_config = get_jvm_config(&role, heap_in_mebi);
                cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config);
            }
            PropertyNameKind::File(file_name) if file_name == LOG4J2_CONFIG => {
                let log_config = get_log4j_config(&role);
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
                druid.version(),
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
    rolegroup: &RoleGroupRef<DruidCluster>,
    tls_settings: &DruidTlsSettings,
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
                druid.version(),
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(tls_settings.service_ports(&role)),
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

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_services`]).
fn build_rolegroup_statefulset(
    druid: &DruidCluster,
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    s3_conn: Option<&S3ConnectionSpec>,
    resources: &RoleResource,
    tls_settings: &DruidTlsSettings,
) -> Result<StatefulSet> {
    let role = DruidRole::from_str(&rolegroup_ref.role).context(UnidentifiedDruidRoleSnafu {
        role: rolegroup_ref.role.to_string(),
    })?;
    let druid_version = druid.version();

    // init container builder
    let mut cb_prepare = ContainerBuilder::new("prepare")
        .context(FailedContainerBuilderCreationSnafu { name: "prepare" })?;
    // druid container builder
    let mut cb_druid = ContainerBuilder::new(APP_NAME)
        .context(FailedContainerBuilderCreationSnafu { name: APP_NAME })?;
    // init pod builder
    let mut pb = PodBuilder::new();

    // volume and volume mounts
    tls_settings
        .add_tls_volume_and_volume_mounts(&mut cb_prepare, &mut cb_druid, &mut pb)
        .context(InvalidTlsConfigSnafu)?;
    add_s3_volume_and_volume_mounts(s3_conn, &mut cb_druid, &mut pb)?;
    add_config_volume_and_volume_mounts(rolegroup_ref, &mut cb_druid, &mut pb);
    add_hdfs_cm_volume_and_volume_mounts(
        &druid.spec.cluster_config.deep_storage,
        &mut cb_druid,
        &mut pb,
    );
    resources.update_volumes_and_volume_mounts(&mut cb_druid, &mut pb);

    let prepare_container_command = tls_settings.build_tls_key_stores_cmd();

    cb_prepare
        .image("docker.stackable.tech/stackable/tools:0.2.0-stackable0")
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![prepare_container_command.join(" && ")])
        .image_pull_policy("IfNotPresent")
        .security_context(SecurityContextBuilder::run_as_root())
        .build();

    // rest of env
    let rest_env = rolegroup_config
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

    cb_druid.image(container_image(druid_version));
    cb_druid.command(role.get_command(s3_conn));
    cb_druid.image_pull_policy("IfNotPresent");
    cb_druid.add_env_vars(rest_env);
    cb_druid.add_container_ports(tls_settings.container_ports(&role));
    // 10s * 30 = 300s to come up
    cb_druid.startup_probe(tls_settings.get_tcp_socket_probe(30, 10, 30, 3));
    // 10s * 1 = 10s to get removed from service
    cb_druid.readiness_probe(tls_settings.get_tcp_socket_probe(10, 10, 1, 3));
    // 10s * 3 = 30s to be restarted
    cb_druid.liveness_probe(tls_settings.get_tcp_socket_probe(10, 10, 3, 3));
    cb_druid.resources(resources.as_resource_requirements());

    pb.add_init_container(cb_prepare.build());
    pb.add_container(cb_druid.build());
    pb.metadata_builder(|m| {
        m.with_recommended_labels(build_recommended_labels(
            druid,
            CONTROLLER_NAME,
            druid_version,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        ))
    });
    pb.security_context(PodSecurityContextBuilder::new().fs_group(1000).build()); // Needed for secret-operator

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                druid,
                CONTROLLER_NAME,
                druid_version,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: if druid.spec.stopped.unwrap_or(false) {
                Some(0)
            } else {
                druid.replicas(rolegroup_ref)
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

fn container_image(version: &str) -> String {
    format!("docker.stackable.tech/stackable/druid:{}", version)
}

pub fn error_policy(_obj: Arc<DruidCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::*;
    use stackable_druid_crd::PROP_SEGMENT_CACHE_LOCATIONS;
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
        #[snafu(display("resource error"))]
        Resource {
            source: stackable_druid_crd::resource::Error,
        },
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

        let role_config = transform_all_roles_to_config(&druid, druid.build_role_properties());

        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/resources/druid_controller/properties.yaml")
                .context(ProductConfigSnafu)?;

        let validated_role_config = validate_all_roles_and_groups_config(
            druid.version(),
            &role_config.context(ProductConfigUtilsSnafu)?,
            &product_config_manager,
            false,
            false,
        )
        .context(OperatorFrameworkSnafu)?;

        let druid_tls_settings = DruidTlsSettings {
            encryption: druid.spec.cluster_config.tls.clone(),
            authentication: None,
        };

        let mut druid_segment_cache_property = "invalid".to_string();

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

                    let resources =
                        resource::resources(&druid, &DruidRole::Historical, &rolegroup_ref)
                            .context(ResourceSnafu)?;

                    let rg_configmap = build_rolegroup_config_map(
                        &druid,
                        &rolegroup_ref,
                        rolegroup_config,
                        "zookeeper-connection-string",
                        None,
                        None,
                        None,
                        &resources,
                        &druid_tls_settings,
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

        //assert!(druid_segment_cache_property.contains(expected_druid_segment_cache_property), "role group {}", tested_rolegroup_name);
        assert!(
            druid_segment_cache_property.contains(&escaped_segment_cache_property),
            "role group {}",
            tested_rolegroup_name
        );

        Ok(())
    }
}
