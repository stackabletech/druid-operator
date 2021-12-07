//! Ensures that `Pod`s are configured and running for each [`DruidCluster`]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hasher,
    time::Duration,
};

use crate::{
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
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, EnvVar, EnvVarSource, ExecAction,
                ObjectFieldSelector, PersistentVolumeClaim, PersistentVolumeClaimSpec, Probe,
                ResourceRequirements, Service, ServicePort, ServiceSpec, Volume,
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

const FIELD_MANAGER: &str = "druid.stackable.tech/druidcluster";

pub struct Ctx {
    pub kube: kube::Client,
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
    let kube = ctx.get_ref().kube.clone();

    let druid_version = druid
        .spec
        .version
        .as_deref()
        .with_context(|| ObjectHasNoVersion {
            obj_ref: druid_ref.clone(),
        })?;

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
                cluster: ObjectRef::from_obj(druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            apply_owned(
                &kube,
                FIELD_MANAGER,
                &build_rolegroup_config_map(&rolegroup, &druid, rolegroup_config)?,
            )
            .await
            .with_context(|| ApplyRoleGroupConfig {
                rolegroup: rolegroup.clone(),
            })?;
            apply_owned(
                &kube,
                FIELD_MANAGER,
                &build_rolegroup_statefulset(&rolegroup, &druid, rolegroup_config)?,
            )
            .await
            .with_context(|| ApplyRoleGroupStatefulSet {
                rolegroup: rolegroup.clone(),
            })?;
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
) -> Result<ConfigMap> {
    let mut config_maps = HashMap::new();
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

                if let Some(zk_info) = &druid.zookeeper_info {
                    transformed_config.insert(
                        ZOOKEEPER_CONNECTION_STRING.to_string(),
                        Some(zk_info.connection_string.clone()),
                    );
                } else {
                    return Err(error::Error::ZookeeperConnectionInformationError);
                }

                let runtime_properties = get_runtime_properties(role, &transformed_config);
                cm_conf_data.insert(RUNTIME_PROPS.to_string(), runtime_properties);
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let jvm_config = get_jvm_config(role);
                cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config);
            }
            PropertyNameKind::File(file_name) if file_name == LOG4J2_CONFIG => {
                let log_config = get_log4j_config(role);
                cm_conf_data.insert(LOG4J2_CONFIG.to_string(), log_config);
            }
            _ => {}
        }
    }

    let mut config_map_builder = ConfigMapBuilder::new().metadata(
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
        config_map_builder = config_map_builder.add_data(filename, file_content);
    }
    config_map_builder
        .build()
        .with_context(|| BuildRoleGroupConfig {
            rolegroup: rolegroup.clone(),
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
    let druid_version = druid_version(druid)?;
    let image = format!(
        "docker.stackable.tech/stackable/zookeeper:{}-stackable0",
        druid_version
    );

    let rolegroup = druid
        .spec
        .get_role(&DruidRole::from_str(&rolegroup_ref.role).unwrap())
        .as_ref()
        .with_context(|| NoServerRole {
            obj_ref: ObjectRef::from_obj(druid),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    let env = server_config
        .get(&PropertyNameKind::Env)
        .iter()
        .flat_map(|env_vars| env_vars.iter())
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..EnvVar::default()
        })
        .collect::<Vec<_>>();
    let container_decide_myid = ContainerBuilder::new("decide-myid")
        .image(&image)
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            "expr $MYID_OFFSET + $(echo $POD_NAME | sed 's/.*-//') > /stackable/data/myid"
                .to_string(),
        ])
        .add_env_vars(env.clone())
        .add_env_vars(vec![EnvVar {
            name: "POD_NAME".to_string(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    api_version: Some("v1".to_string()),
                    field_path: "metadata.name".to_string(),
                }),
                ..EnvVarSource::default()
            }),
            ..EnvVar::default()
        }])
        .add_volume_mount("data", "/stackable/data")
        .build();
    let container_druid = ContainerBuilder::new("zookeeper")
        .image(image)
        .args(vec![
            "bin/druidServer.sh".to_string(),
            "start-foreground".to_string(),
            "/stackable/config/zoo.cfg".to_string(),
        ])
        .add_env_vars(env)
        // Only allow the global load balancing service to send traffic to pods that are members of the quorum
        // This also acts as a hint to the StatefulSet controller to wait for each pod to enter quorum before taking down the next
        .readiness_probe(Probe {
            exec: Some(ExecAction {
                command: Some(vec![
                    "bash".to_string(),
                    "-c".to_string(),
                    // We don't have telnet or netcat in the container images, but
                    // we can use Bash's virtual /dev/tcp filesystem to accomplish the same thing
                    format!(
                        "exec 3<>/dev/tcp/localhost/{} && echo srvr >&3 && grep '^Mode: ' <&3",
                        APP_PORT
                    ),
                ]),
            }),
            period_seconds: Some(1),
            ..Probe::default()
        })
        .add_container_port("druid", APP_PORT.into())
        .add_container_port("druid-leader", 2888)
        .add_container_port("druid-election", 3888)
        .add_container_port("metrics", 9505)
        .add_volume_mount("data", "/stackable/data")
        .add_volume_mount("config", "/stackable/config")
        .build();
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
            template: PodBuilder::new()
                .metadata_builder(|m| {
                    m.with_recommended_labels(
                        druid,
                        APP_NAME,
                        druid_version,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                })
                .add_init_container(container_decide_myid)
                .add_container(container_druid)
                .add_volume(Volume {
                    name: "config".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: Some(rolegroup_ref.object_name()),
                        ..ConfigMapVolumeSource::default()
                    }),
                    ..Volume::default()
                })
                .build_template(),
            volume_claim_templates: Some(vec![PersistentVolumeClaim {
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
            }]),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

pub fn druid_version(druid: &DruidCluster) -> Result<&str> {
    druid
        .spec
        .version
        .as_deref()
        .with_context(|| Error::ObjectHasNoVersion {
            obj_ref: ObjectRef::from_obj(druid),
        })
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
