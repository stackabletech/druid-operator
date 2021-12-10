//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hasher,
    str::FromStr,
    time::Duration,
};

use crate::{
    config::{get_jvm_config, get_log4j_config, get_runtime_properties},
    utils::{apply_owned, apply_status},
    APP_PORT,
};
use fnv::FnvHasher;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    DeepStorageType, DruidCluster, DruidClusterSpec, DruidClusterStatus, DruidRole, DruidVersion,
    RoleGroupRef, APP_NAME, CONTAINER_METRICS_PORT, CONTAINER_PLAINTEXT_PORT,
    CREDENTIALS_SECRET_PROPERTY, DRUID_METRICS_PORT, DRUID_PLAINTEXTPORT, JVM_CONFIG,
    LOG4J2_CONFIG, RUNTIME_PROPS, ZOOKEEPER_CONNECTION_STRING,
};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, VolumeBuilder,
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, EnvVar, EnvVarSource, ExecAction,
                ObjectFieldSelector, PersistentVolumeClaim, PersistentVolumeClaimSpec, Probe,
                ResourceRequirements, SecretKeySelector, Service, ServicePort, ServiceSpec, Volume,
            },
        },
        apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    },
    kube::{
        self,
        api::ObjectMeta,
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
        },
    },
    labels::{role_group_selector_labels, role_selector_labels},
    product_config::{
        types::PropertyNameKind, writer::to_java_properties_string, ProductConfigManager,
    },
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
};

const FIELD_MANAGER_SCOPE: &str = "druidcluster";
const DEFAULT_IMAGE_VERSION: &str = "0";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object {} has no namespace", obj_ref))]
    ObjectHasNoNamespace { obj_ref: ObjectRef<DruidCluster> },
    #[snafu(display("object {} defines no version", obj_ref))]
    ObjectHasNoVersion { obj_ref: ObjectRef<DruidCluster> },
    #[snafu(display("{} has no server role", obj_ref))]
    NoServerRole { obj_ref: ObjectRef<DruidCluster> },
    #[snafu(display("failed to calculate global service name for {}", obj_ref))]
    GlobalServiceNameNotFound { obj_ref: ObjectRef<DruidCluster> },
    #[snafu(display("failed to calculate service name for role {}", rolegroup))]
    RoleGroupServiceNameNotFound { rolegroup: RoleGroupRef },
    #[snafu(display("failed to apply global Service for {}", druid))]
    ApplyRoleService {
        source: kube::Error,
        druid: ObjectRef<DruidCluster>,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("invalid product config for {}", druid))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
        druid: ObjectRef<DruidCluster>,
    },
    #[snafu(display("failed to serialize zoo.cfg for {}", rolegroup))]
    SerializeZooCfg {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("object {} is missing metadata to build owner reference", druid))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
        druid: ObjectRef<DruidCluster>,
    },
    #[snafu(display("failed to update status of {}", druid))]
    ApplyStatus {
        source: kube::Error,
        druid: ObjectRef<DruidCluster>,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

const PROPERTIES_FILE: &str = "zoo.cfg";

pub async fn reconcile_druid(druid: DruidCluster, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");
    let druid_ref = ObjectRef::from_obj(&druid);
    let client = &ctx.get_ref().client;

    let zk_connstr = client
        .get::<ConfigMap>("simple", Some("default"))
        .await
        .unwrap_or_default()
        .data
        .unwrap_or_default()
        .remove("ZOOKEEPER")
        .unwrap();

    let druid_version = druid.spec.version.to_string(); // TODO

    let mut roles = HashMap::new();

    let config_files = vec![
        PropertyNameKind::Env,
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG4J2_CONFIG.to_string()),
        PropertyNameKind::File(RUNTIME_PROPS.to_string()),
    ];

    roles.insert(
        DruidRole::Broker.to_string(),
        (config_files.clone(), druid.spec.brokers.clone().into()),
    );

    roles.insert(
        DruidRole::Coordinator.to_string(),
        (config_files.clone(), druid.spec.coordinators.clone().into()),
    );

    roles.insert(
        DruidRole::Historical.to_string(),
        (config_files.clone(), druid.spec.historicals.clone().into()),
    );

    roles.insert(
        DruidRole::MiddleManager.to_string(),
        (
            config_files.clone(),
            druid.spec.middle_managers.clone().into(),
        ),
    );

    roles.insert(
        DruidRole::Router.to_string(),
        (config_files, druid.spec.routers.clone().into()),
    );

    let role_config = transform_all_roles_to_config(&druid, roles);
    let validated_role_config = validate_all_roles_and_groups_config(
        &druid.spec.version.to_string(),
        &role_config,
        &ctx.get_ref().product_config,
        false,
        false,
    )
    .with_context(|| InvalidProductConfig {
        druid: druid_ref.clone(),
    })?;

    for (role_name, role_config) in validated_role_config.iter() {
        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let rg_service = build_rolegroup_services(&rolegroup, &druid, rolegroup_config)?;
            let rg_configmap = build_rolegroup_config_map(
                &rolegroup,
                &druid,
                rolegroup_config,
                zk_connstr.clone(),
            )?;
            let rg_statefulset = build_rolegroup_statefulset(&rolegroup, &druid, rolegroup_config)?;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
                .await;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_configmap, &rg_configmap)
                .await;
            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_statefulset, &rg_statefulset)
                .await;
        }
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    rolegroup: &RoleGroupRef,
    druid: &DruidCluster,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    zk_connstr: String,
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
                /*
                                if let Some(zk_info) = &druid.spec.zookeeper_info {
                                    transformed_config.insert(
                                        ZOOKEEPER_CONNECTION_STRING.to_string(),
                                        Some(zk_info.connection_string.clone()),
                                    );
                                } else {
                                    return Err(error::Error::ZookeeperConnectionInformationError);
                                }
                */
                let runtime_properties = get_runtime_properties(&role, &transformed_config);
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
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                druid: ObjectRef::from_obj(druid),
            })?
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
        .with_context(|| BuildRoleGroupConfig {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_rolegroup_services(
    rolegroup: &RoleGroupRef,
    druid: &DruidCluster,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<Service> {
    let mut ports = vec![];
    if let Some(plaintext_port) = rolegroup_config
        .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
        .and_then(|props| props.get(DRUID_PLAINTEXTPORT))
        .map(|port| port.parse::<i32>().unwrap())
    {
        ports.push(ServicePort {
            name: Some(CONTAINER_PLAINTEXT_PORT.to_string()),
            port: plaintext_port,
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        });
    }
    if let Some(metrics_port) = rolegroup_config
        .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
        .and_then(|props| props.get(DRUID_METRICS_PORT))
        .map(|port| port.parse::<i32>().unwrap())
    {
        ports.push(ServicePort {
            name: Some(CONTAINER_METRICS_PORT.to_string()),
            port: metrics_port,
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        });
    }
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                druid: ObjectRef::from_obj(druid),
            })?
            .with_recommended_labels(
                druid,
                APP_NAME,
                druid_version(druid)?,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
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
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_service`]).
fn build_rolegroup_statefulset(
    rolegroup_ref: &RoleGroupRef,
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

    // add ports
    if let Some(plaintext_port) = rolegroup_config
        .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
        .and_then(|props| props.get(DRUID_PLAINTEXTPORT))
        .map(|port| port.parse::<i32>().unwrap())
    {
        cb.add_container_port(CONTAINER_PLAINTEXT_PORT, plaintext_port);
    }
    if let Some(metrics_port) = rolegroup_config
        .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
        .and_then(|props| props.get(DRUID_METRICS_PORT))
        .map(|port| port.parse::<i32>().unwrap())
    {
        cb.add_container_port(CONTAINER_METRICS_PORT, metrics_port);
    }

    // config mount
    cb.add_volume_mount("config", "/stackable/conf");
    pb.add_volume(
        VolumeBuilder::new("config")
            .with_config_map(rolegroup_ref.object_name())
            .build(),
    );

    // add local deep storage setup
    let mut pvcs = vec![];
    if druid.spec.deep_storage.storage_type == DeepStorageType::Local {
        let data_dir = String::from("/data");
        let dir = druid
            .spec
            .deep_storage
            .storage_directory
            .as_ref()
            .unwrap_or(&data_dir);
        cb.add_volume_mount("data", "/data");
        pb.add_volume(
            VolumeBuilder::new("data")
                .with_host_path(dir, Some("DirectoryOrCreate".to_string()))
                .build(),
        );
        pvcs.push(PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("data".to_string()),
                ..ObjectMeta::default()
            },
            spec: Some(PersistentVolumeClaimSpec {
                access_modes: Some(vec!["ReadWriteOnce".to_string()]),
                resources: Some(ResourceRequirements {
                    requests: Some({
                        let mut map = BTreeMap::new();
                        map.insert("storage".to_string(), Quantity("1Gi".to_string()));
                        map
                    }),
                    ..ResourceRequirements::default()
                }),
                ..PersistentVolumeClaimSpec::default()
            }),
            ..PersistentVolumeClaim::default()
        });
        pb.security_context(
            PodSecurityContextBuilder::new()
                .run_as_user(0)
                .fs_group(0)
                .run_as_group(0)
                .build(),
        );
    }

    let mut container = cb.build();
    container.image_pull_policy = Some("IfNotPresent".to_string());
    pb.add_container(container);

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(druid, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                druid: ObjectRef::from_obj(druid),
            })?
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
            volume_claim_templates: Some(pvcs),
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
        version.to_string(),
        DEFAULT_IMAGE_VERSION
    )
}

pub fn druid_version(druid: &DruidCluster) -> Result<&str> {
    Ok("0.22.0")
    //Ok(&druid.spec.version.to_string()) // TODO
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
