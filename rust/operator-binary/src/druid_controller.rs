//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::{get_jvm_config, get_log4j_config},
    discovery::{self, build_discovery_configmaps},
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    DeepStorageSpec, DruidCluster, DruidRole, APP_NAME, AUTH_AUTHORIZER_OPA_URI,
    CONTAINER_HTTP_PORT, CONTAINER_METRICS_PORT, CREDENTIALS_SECRET_PROPERTY, DRUID_METRICS_PORT,
    DS_BUCKET, JVM_CONFIG, LOG4J2_CONFIG, RUNTIME_PROPS, S3_ENDPOINT_URL, S3_SECRET_DIR_NAME,
    ZOOKEEPER_CONNECTION_STRING,
};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder, VolumeBuilder},
    commons::{opa::OpaApiVersion, s3::S3ConnectionSpec},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, EnvVar, Probe, Service, ServicePort, ServiceSpec, TCPSocketAction,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::{
        runtime::{
            controller::{Action, Context},
            reflector::ObjectRef,
        },
        ResourceExt,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::RoleGroupRef,
};
use std::ops::Deref;
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

const FIELD_MANAGER_SCOPE: &str = "druidcluster";

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
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(druid: Arc<DruidCluster>, ctx: Context<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");
    let client = &ctx.get_ref().client;

    let zk_confmap = druid.spec.zookeeper_config_map_name.clone();
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
    let opa_connstr = if let Some(opa_spec) = &druid.spec.opa {
        Some(
            opa_spec
                .full_document_url_from_config_map(
                    client,
                    druid.deref(),
                    Some("allow"),
                    OpaApiVersion::V1,
                )
                .await
                .context(GetOpaConnStringSnafu {
                    cm_name: opa_spec.config_map_name.clone(),
                })?,
        )
    } else {
        None
    };

    // Get the s3 connection if one is defined
    let s3_conn: Option<S3ConnectionSpec> = druid
        .get_s3_connection(client)
        .await
        .context(GetS3ConnectionSnafu)?;

    let deep_storage_bucket_name = match &druid.spec.deep_storage {
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
        druid_version(&druid)?,
        &role_config.context(ProductConfigTransformSnafu)?,
        &ctx.get_ref().product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let role_service = build_role_service(role_name, &druid)?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &role_service, &role_service)
            .await
            .context(ApplyRoleServiceSnafu)?;
        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let rg_service = build_rolegroup_services(&rolegroup, &druid, rolegroup_config)?;
            let rg_configmap = build_rolegroup_config_map(
                &rolegroup,
                &druid,
                rolegroup_config,
                &zk_connstr,
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &rolegroup,
                &druid,
                rolegroup_config,
                s3_conn.as_ref(),
            )?;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_configmap, &rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_statefulset, &rg_statefulset)
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
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &discovery_cm, &discovery_cm)
            .await
            .context(ApplyDiscoveryConfigSnafu)?;
    }

    Ok(Action::await_change())
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
pub fn build_role_service(role_name: &str, druid: &DruidCluster) -> Result<Service> {
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
            .with_recommended_labels(druid, APP_NAME, druid_version(druid)?, role_name, "global")
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                name: Some(CONTAINER_HTTP_PORT.to_string()),
                port: DruidRole::from_str(role_name)
                    .unwrap()
                    .get_http_port()
                    .into(),
                target_port: Some(IntOrString::String(CONTAINER_HTTP_PORT.to_string())),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
            selector: Some(role_selector_labels(druid, APP_NAME, role_name)),
            type_: Some("NodePort".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    rolegroup: &RoleGroupRef<DruidCluster>,
    druid: &DruidCluster,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    zk_connstr: &str,
    opa_connstr: Option<&str>,
    s3_conn: Option<&S3ConnectionSpec>,
    deep_storage_bucket_name: Option<&str>,
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
                    } // TODO make code nicer
                }
                transformed_config.insert(
                    DS_BUCKET.to_string(),
                    deep_storage_bucket_name.map(str::to_string),
                );
                let runtime_properties =
                    stackable_operator::product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )
                    .context(PropertiesWriteSnafu)?;
                cm_conf_data.insert(RUNTIME_PROPS.to_string(), runtime_properties);
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let jvm_config = get_jvm_config(&role);
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
                druid_version(druid)?,
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
    rolegroup: &RoleGroupRef<DruidCluster>,
    druid: &DruidCluster,
    _rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
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
                druid_version(druid)?,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(vec![
                ServicePort {
                    name: Some(CONTAINER_HTTP_PORT.to_string()),
                    port: role.get_http_port().into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(CONTAINER_METRICS_PORT.to_string()),
                    port: DRUID_METRICS_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
            ]),
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
    rolegroup_ref: &RoleGroupRef<DruidCluster>,
    druid: &DruidCluster,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    s3_conn: Option<&S3ConnectionSpec>,
) -> Result<StatefulSet> {
    // setup
    let role = DruidRole::from_str(&rolegroup_ref.role).unwrap();
    let druid_version = druid_version(druid)?;
    let rolegroup = druid
        .get_role(&DruidRole::from_str(&rolegroup_ref.role).unwrap())
        .role_groups
        .get(&rolegroup_ref.role_group);

    // init container builder
    let mut cb = ContainerBuilder::new(APP_NAME);
    // init pod builder
    let mut pb = PodBuilder::new();
    pb.metadata_builder(|m| {
        m.with_recommended_labels(
            druid,
            APP_NAME,
            druid_version,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        )
    });

    // add image
    cb.image(container_image(druid_version));

    let mut load_s3_credentials = false;
    // Add s3 credentials secret volume
    if let Some(S3ConnectionSpec {
        credentials: Some(credentials),
        ..
    }) = s3_conn
    {
        load_s3_credentials = true;
        pb.add_volume(credentials.to_volume("s3-credentials"));
        cb.add_volume_mount("s3-credentials", S3_SECRET_DIR_NAME);
    }

    // add command
    cb.command(role.get_command(load_s3_credentials));

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
    cb.add_env_vars(rest_env);

    // add ports
    cb.add_container_port(CONTAINER_HTTP_PORT, role.get_http_port().into());
    cb.add_container_port(CONTAINER_METRICS_PORT, DRUID_METRICS_PORT.into());

    // config mount
    cb.add_volume_mount("config", "/stackable/conf");
    pb.add_volume(
        VolumeBuilder::new("config")
            .with_config_map(rolegroup_ref.object_name())
            .build(),
    );

    // readiness probe
    let probe = Probe {
        tcp_socket: Some(TCPSocketAction {
            port: IntOrString::Int(role.get_http_port().into()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(30),
        period_seconds: Some(5),
        ..Default::default()
    };
    cb.readiness_probe(probe);

    let mut container = cb.build();
    container.image_pull_policy = Some("IfNotPresent".to_string());
    pb.add_container(container);

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

fn container_image(version: &str) -> String {
    format!("docker.stackable.tech/stackable/druid:{}", version)
}

pub fn druid_version(druid: &DruidCluster) -> Result<&str> {
    Ok(&druid.spec.version)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
