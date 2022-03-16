//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]
use crate::{
    config::{get_jvm_config, get_log4j_config},
    discovery::{self, build_discovery_configmaps},
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{DruidCluster, DruidRole, APP_NAME, CONTAINER_HTTP_PORT, CONTAINER_METRICS_PORT, CREDENTIALS_SECRET_PROPERTY, DRUID_METRICS_PORT, JVM_CONFIG, LOG4J2_CONFIG, RUNTIME_PROPS, ZOOKEEPER_CONNECTION_STRING, AUTH_AUTHORIZER_OPA_URI};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder, VolumeBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, EnvVar, EnvVarSource, SecretKeySelector, Service, ServicePort,
                ServiceSpec,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::{
        runtime::{
            controller::{Context, ReconcilerAction},
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
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use std::ops::Deref;
use strum::{EnumDiscriminants, IntoEnumIterator, IntoStaticStr};

const FIELD_MANAGER_SCOPE: &str = "druidcluster";
const DEFAULT_IMAGE_VERSION: &str = "0";

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

pub async fn reconcile_druid(
    druid: Arc<DruidCluster>,
    ctx: Context<Ctx>,
) -> Result<ReconcilerAction> {
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
        Some(opa_spec.full_package_url_from_config_map(&client, druid.deref()).await.context(GetOpaConnStringSnafu {
            cm_name: opa_spec.config_map_name.clone(),
        })?)
    } else {
        None
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
                zk_connstr.clone(),
                opa_connstr.clone(),
            )?;
            let rg_statefulset = build_rolegroup_statefulset(&rolegroup, &druid, rolegroup_config)?;
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

    Ok(ReconcilerAction {
        requeue_after: None,
    })
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
    zk_connstr: String,
    opa_connstr: Option<String>,  // TODO make use of this again
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
                    Some(zk_connstr.clone()),
                );
                if let Some(opa_str) = opa_connstr.clone() {
                    transformed_config.insert(
                        AUTH_AUTHORIZER_OPA_URI.to_string(),
                        Some(opa_str),
                    );
                };
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

    // add command
    cb.command(role.get_command(druid_version));

    // add env
    let secret = rolegroup_config
        .get(&PropertyNameKind::Env)
        .and_then(|m| m.get(CREDENTIALS_SECRET_PROPERTY));
    let secret_env = secret.map(|s| {
        vec![
            env_var_from_secret("AWS_ACCESS_KEY_ID", s, "accessKeyId"),
            env_var_from_secret("AWS_SECRET_ACCESS_KEY", s, "secretAccessKey"),
        ]
    });
    if let Some(e) = secret_env {
        cb.add_env_vars(e);
    }
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

fn env_var_from_secret(var_name: &str, secret: &str, secret_key: &str) -> EnvVar {
    EnvVar {
        name: String::from(var_name),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: Some(String::from(secret)),
                key: String::from(secret_key),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn container_image(version: &str) -> String {
    format!(
        // For now we hardcode the stackable image version via DEFAULT_IMAGE_VERSION
        // which represents the major image version and will fallback to the newest
        // available image e.g. if DEFAULT_IMAGE_VERSION = 0 and versions 0.0.1 and
        // 0.0.2 are available, the latter one will be selected. This may change the
        // image during restarts depending on the imagePullPolicy.
        // TODO: should be made configurable
        "docker.stackable.tech/stackable/druid:{}-stackable{}",
        version, DEFAULT_IMAGE_VERSION
    )
}

pub fn druid_version(druid: &DruidCluster) -> Result<&str> {
    Ok(&druid.spec.version)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
