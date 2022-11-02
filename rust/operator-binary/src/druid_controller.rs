//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::{get_jvm_config, get_log4j_config},
    discovery::{self, build_discovery_configmaps},
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    authentication,
    authentication::{DruidAuthentication, DruidAuthenticationConfig},
    tls::DruidTls,
    DeepStorageSpec, DruidAuthorization, DruidCluster, DruidRole, DruidStorageConfig, APP_NAME,
    AUTH_AUTHORIZER_OPA_URI, CERTS_DIR, CONTROLLER_NAME, CREDENTIALS_SECRET_PROPERTY,
    DRUID_CONFIG_DIRECTORY, DS_BUCKET, HDFS_CONFIG_DIRECTORY, JVM_CONFIG, LOG4J2_CONFIG,
    RUNTIME_PROPS, RW_CONFIG_DIRECTORY, S3_ENDPOINT_URL, S3_PATH_STYLE_ACCESS, S3_SECRET_DIR_NAME,
    ZOOKEEPER_CONNECTION_STRING,
};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, SecurityContextBuilder,
        VolumeBuilder,
    },
    cluster_resources::ClusterResources,
    commons::{
        opa::OpaApiVersion,
        resources::{NoRuntimeLimits, Resources},
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
        Resource, ResourceExt,
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
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

const JVM_HEAP_FACTOR: f32 = 0.8;

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
    FailedToResolveResourceConfig,
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
    #[snafu(display("invalid authentication configuration"))]
    InvalidAuthenticationConfig { source: authentication::Error },
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

    let zk_confmap = druid.spec.common_config.zookeeper_config_map_name.clone();
    let zk_connstr = client
        .get::<ConfigMap>(&zk_confmap, druid.namespace().as_deref())
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
        &druid.spec.common_config.authorization
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

    let deep_storage_bucket_name = match &druid.spec.common_config.deep_storage {
        DeepStorageSpec::S3(s3_spec) => {
            s3_spec
                .bucket
                .resolve(client, druid.namespace().as_deref())
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name
        }
        _ => None,
    };

    // Get possible authentication methods
    let authentication_config = DruidAuthentication::resolve(client, &druid)
        .await
        .context(InvalidAuthenticationConfigSnafu)?;

    let mut roles = HashMap::new();

    let config_files = vec![
        PropertyNameKind::Env,
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG4J2_CONFIG.to_string()),
        PropertyNameKind::File(RUNTIME_PROPS.to_string()),
    ];

    for role in DruidRole::iter() {
        roles.insert(
            role.to_string(),
            (config_files.clone(), druid.get_role(&role).clone()),
        );
    }

    let role_config = transform_all_roles_to_config(&*druid, roles);
    let validated_role_config = validate_all_roles_and_groups_config(
        druid.version(),
        &role_config.context(ProductConfigTransformSnafu)?,
        &ctx.product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    let mut cluster_resources =
        ClusterResources::new(APP_NAME, CONTROLLER_NAME, &druid.object_ref(&()))
            .context(CreateClusterResourcesSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(&druid, &druid_role)?;
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

            let resources = druid
                .resolve_resource_config_for_role_and_rolegroup(&druid_role, &rolegroup)
                .context(FailedToResolveResourceConfigSnafu)?;

            let rg_service = build_rolegroup_services(&druid, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &rolegroup,
                rolegroup_config,
                &zk_connstr,
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
                &resources,
                &authentication_config,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &rolegroup,
                rolegroup_config,
                s3_conn.as_ref(),
                &resources,
                &authentication_config,
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
    for discovery_cm in build_discovery_configmaps(&*druid, &*druid)
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
pub fn build_role_service(druid: &DruidCluster, role: &DruidRole) -> Result<Service> {
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
            .with_recommended_labels(
                druid,
                APP_NAME,
                druid.version(),
                CONTROLLER_NAME,
                &role_name,
                "global",
            )
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(druid.spec.common_config.tls.service_ports(role)),
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
    resources: &Resources<DruidStorageConfig, NoRuntimeLimits>,
    authentication: &Vec<DruidAuthenticationConfig>,
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
                for auth in authentication {
                    auth.add_common_config_properties(&mut transformed_config);
                }

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
                        .memory
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
            .with_recommended_labels(
                druid,
                APP_NAME,
                druid.version(),
                CONTROLLER_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )
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
) -> Result<Service> {
    let role = DruidRole::from_str(&rolegroup.role).unwrap();

    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                druid,
                APP_NAME,
                druid.version(),
                CONTROLLER_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(druid.spec.common_config.tls.service_ports(&role)),
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
    resources: &Resources<DruidStorageConfig, NoRuntimeLimits>,
    authentication: &Vec<DruidAuthenticationConfig>,
) -> Result<StatefulSet> {
    let role = DruidRole::from_str(&rolegroup_ref.role).context(UnidentifiedDruidRoleSnafu {
        role: rolegroup_ref.role.to_string(),
    })?;
    let druid_version = druid.version();
    let rolegroup = druid
        .get_role(&role)
        .role_groups
        .get(&rolegroup_ref.role_group);

    // init container builder
    let mut cb_prepare = ContainerBuilder::new("prepare")
        .context(FailedContainerBuilderCreationSnafu { name: "prepare" })?;
    // druid container builder
    let mut cb_druid = ContainerBuilder::new(APP_NAME)
        .context(FailedContainerBuilderCreationSnafu { name: APP_NAME })?;
    // init pod builder
    let mut pb = PodBuilder::new();

    let tls_config: &DruidTls = &druid.spec.common_config.tls;
    // volume and volume mounts
    tls_config.add_tls_volume_and_volume_mounts(&mut cb_prepare, &mut cb_druid, &mut pb);
    add_s3_volume_and_volume_mounts(s3_conn, &mut cb_druid, &mut pb)?;
    add_config_volume_and_volume_mounts(rolegroup_ref, &mut cb_druid, &mut pb);
    add_hdfs_cm_volume_and_volume_mounts(
        &druid.spec.common_config.deep_storage,
        &mut cb_druid,
        &mut pb,
    );

    // tls
    let mut init_command: Vec<String> = tls_config.build_tls_stores_cmd();
    // possible client auth
    for auth_method in authentication {
        auth_method.add_authentication_volume_and_volume_mounts(
            &mut cb_prepare,
            &mut cb_druid,
            &mut pb,
        );
        init_command.extend(auth_method.build_authentication_cmd());
    }

    cb_prepare
        .image("docker.stackable.tech/stackable/tools:0.2.0-stackable0")
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![init_command.join(" && ")])
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
    cb_druid.add_env_vars(rest_env);
    cb_druid.add_container_ports(tls_config.container_ports(&role));
    cb_druid.readiness_probe(tls_config.get_probe());
    cb_druid.liveness_probe(tls_config.get_probe());
    cb_druid.resources(resources.clone().into());

    pb.add_init_container(cb_prepare.build());
    pb.add_container(cb_druid.build());
    pb.metadata_builder(|m| {
        m.with_recommended_labels(
            druid,
            APP_NAME,
            druid_version,
            CONTROLLER_NAME,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        )
    });
    pb.security_context(PodSecurityContextBuilder::new().fs_group(1000).build()); // Needed for secret-operator

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                druid,
                APP_NAME,
                druid_version,
                CONTROLLER_NAME,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            )
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: if druid.spec.stopped.unwrap_or(false) {
                Some(0)
            } else {
                rolegroup.and_then(|rg| rg.replicas).map(i32::from)
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
                                format!("{CERTS_DIR}{volume_name}"),
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

pub fn error_policy(_error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
