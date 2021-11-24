mod config;
mod error;

use crate::config::{get_jvm_config, get_log4j_config, get_runtime_properties};
use crate::error::Error;
use stackable_druid_crd::commands::{Restart, Start, Stop};

use async_trait::async_trait;
use serde::Serialize;
use stackable_druid_crd::{
    DeepStorageType, DruidCluster, DruidClusterSpec, DruidRole, DruidVersion, APP_NAME,
    CONTAINER_METRICS_PORT, CONTAINER_PLAINTEXT_PORT, CREDENTIALS_SECRET_PROPERTY,
    DRUID_METRICS_PORT, DRUID_PLAINTEXTPORT, JVM_CONFIG, LOG4J2_CONFIG, RUNTIME_PROPS,
    ZOOKEEPER_CONNECTION_STRING,
};
use stackable_operator::builder::{
    ContainerBuilder, ObjectMetaBuilder, PodBuilder, PodSecurityContextBuilder, VolumeBuilder,
};
use stackable_operator::client::Client;
use stackable_operator::command::materialize_command;
use stackable_operator::configmap;
use stackable_operator::controller::Controller;
use stackable_operator::controller::{ControllerStrategy, ReconciliationState};
use stackable_operator::error::OperatorResult;
use stackable_operator::identity::{LabeledPodIdentityFactory, PodIdentity, PodToNodeMapping};
use stackable_operator::k8s_openapi::api::core::v1::{
    ConfigMap, EnvVar, EnvVarSource, Pod, SecretKeySelector,
};
use stackable_operator::kube::api::{ListParams, ResourceExt};
use stackable_operator::kube::Api;
use stackable_operator::kube::CustomResourceExt;
use stackable_operator::labels;
use stackable_operator::labels::{
    build_common_labels_for_all_managed_resources, get_recommended_labels,
};
use stackable_operator::name_utils;
use stackable_operator::product_config::types::PropertyNameKind;
use stackable_operator::product_config::ProductConfigManager;
use stackable_operator::product_config_utils::{
    config_for_role_and_group, transform_all_roles_to_config, validate_all_roles_and_groups_config,
    ValidatedRoleConfigByPropertyKind,
};
use stackable_operator::reconcile::{
    ContinuationStrategy, ReconcileFunctionAction, ReconcileResult, ReconciliationContext,
};
use stackable_operator::role_utils::{
    get_role_and_group_labels, list_eligible_nodes_for_role_and_group, EligibleNodesAndReplicas,
    EligibleNodesForRoleAndGroup, Role,
};
use stackable_operator::scheduler::{
    K8SUnboundedHistory, RoleGroupEligibleNodes, ScheduleStrategy, Scheduler, StickyScheduler,
};
use stackable_operator::status::HasClusterExecutionStatus;
use stackable_operator::status::{init_status, ClusterExecutionStatus};
use stackable_operator::versioning::{finalize_versioning, init_versioning};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;
use tracing::error;
use tracing::{debug, info, trace};

use stackable_zookeeper_crd::discovery::ZookeeperConnectionInformation;

const FINALIZER_NAME: &str = "druid.stackable.tech/cleanup";
const ID_LABEL: &str = "druid.stackable.tech/id";
const DEFAULT_IMAGE_VERSION: &str = "0";

const CONFIG_MAP_TYPE_CONF: &str = "config";

type DruidReconcileResult = ReconcileResult<error::Error>;

struct DruidState {
    context: ReconciliationContext<DruidCluster>,
    existing_pods: Vec<Pod>,
    eligible_nodes: EligibleNodesForRoleAndGroup,
    validated_role_config: ValidatedRoleConfigByPropertyKind,
    zookeeper_info: Option<ZookeeperConnectionInformation>,
}

impl DruidState {
    /// Required labels for pods. Pods without any of these will deleted and/or replaced.
    pub fn get_required_labels(&self) -> BTreeMap<String, Option<Vec<String>>> {
        let roles = DruidRole::iter()
            .map(|role| role.to_string())
            .collect::<Vec<_>>();
        let mut mandatory_labels = BTreeMap::new();

        mandatory_labels.insert(labels::APP_COMPONENT_LABEL.to_string(), Some(roles));
        mandatory_labels.insert(
            labels::APP_INSTANCE_LABEL.to_string(),
            Some(vec![self.context.name()]),
        );
        mandatory_labels.insert(
            labels::APP_VERSION_LABEL.to_string(),
            Some(vec![self.context.resource.spec.version.to_string()]),
        );
        mandatory_labels.insert(ID_LABEL.to_string(), None);

        mandatory_labels
    }

    async fn get_zookeeper_connection_information(&mut self) -> DruidReconcileResult {
        let zk_ref: &stackable_zookeeper_crd::discovery::ZookeeperReference =
            &self.context.resource.spec.zookeeper_reference;

        if let Some(chroot) = zk_ref.chroot.as_deref() {
            stackable_zookeeper_crd::discovery::is_valid_zookeeper_path(chroot)?;
        }

        let zookeeper_info = stackable_zookeeper_crd::discovery::get_zk_connection_info(
            &self.context.client,
            zk_ref,
        )
        .await?;

        debug!(
            "Received ZooKeeper connection information: [{}]",
            &zookeeper_info.connection_string
        );

        self.zookeeper_info = Some(zookeeper_info);

        Ok(ReconcileFunctionAction::Continue)
    }

    /// Will initialize the status object if it's never been set.
    async fn init_status(&mut self) -> DruidReconcileResult {
        // init status with default values if not available yet.
        self.context.resource = init_status(&self.context.client, &self.context.resource).await?;

        let spec_version = self.context.resource.spec.version.clone();

        self.context.resource =
            init_versioning(&self.context.client, &self.context.resource, spec_version).await?;

        // set the cluster status to running
        if self.context.resource.cluster_execution_status().is_none() {
            self.context
                .client
                .merge_patch_status(
                    &self.context.resource,
                    &self
                        .context
                        .resource
                        .cluster_execution_status_patch(&ClusterExecutionStatus::Running),
                )
                .await?;
        }

        Ok(ReconcileFunctionAction::Continue)
    }

    pub async fn create_missing_pods(&mut self) -> DruidReconcileResult {
        trace!(target: "create_missing_pods","Starting `create_missing_pods`");

        // The iteration happens in two stages here, to accommodate the way our operators think
        // about roles and role groups.
        // The hierarchy is:
        // - Roles (Master, Worker, History-Server)
        //   - Role groups (user defined)
        for role in DruidRole::iter() {
            let role_str = &role.to_string();
            trace!(target: "create_missing_pods", "Checking role '{}'", role_str);
            if let Some(nodes_for_role) = self.eligible_nodes.get(role_str) {
                for (role_group, eligible_nodes) in nodes_for_role {
                    debug!( target: "create_missing_pods",
                        "Identify missing pods for [{}] role and group [{}]",
                        role_str, role_group
                    );
                    trace!( target: "create_missing_pods",
                        "candidate_nodes[{}]: [{:?}]",
                        eligible_nodes.nodes.len(),
                        eligible_nodes
                            .nodes
                            .iter()
                            .map(|node| node.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "existing_pods[{}]: [{:?}]",
                        &self.existing_pods.len(),
                        &self
                            .existing_pods
                            .iter()
                            .map(|pod| pod.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "labels: [{:?}]",
                        get_role_and_group_labels(role_str, role_group)
                    );
                    let mut history = match self
                        .context
                        .resource
                        .status
                        .as_ref()
                        .and_then(|status| status.history.as_ref())
                    {
                        Some(simple_history) => {
                            // we clone here because we cannot access mut self because we need it later
                            // to create config maps and pods. The `status` history will be out of sync
                            // with the cloned `simple_history` until the next reconcile.
                            // The `status` history should not be used after this method to avoid side
                            // effects.
                            K8SUnboundedHistory::new(&self.context.client, simple_history.clone())
                        }
                        None => K8SUnboundedHistory::new(
                            &self.context.client,
                            PodToNodeMapping::default(),
                        ),
                    };

                    let mut sticky_scheduler =
                        StickyScheduler::new(&mut history, ScheduleStrategy::GroupAntiAffinity);

                    let pod_id_factory = LabeledPodIdentityFactory::new(
                        APP_NAME,
                        &self.context.name(),
                        &self.eligible_nodes,
                        ID_LABEL,
                        1,
                    );

                    trace!("pod_id_factory: {:?}", pod_id_factory.as_ref());

                    let state = sticky_scheduler.schedule(
                        &pod_id_factory,
                        &RoleGroupEligibleNodes::from(&self.eligible_nodes),
                        &self.existing_pods,
                    )?;

                    let mapping = state.remaining_mapping().filter(
                        APP_NAME,
                        &self.context.name(),
                        role_str,
                        role_group,
                    );

                    if let Some((pod_id, node_id)) = mapping.iter().next() {
                        // now we have a node that needs a pod -> get validated config
                        let validated_config = config_for_role_and_group(
                            pod_id.role(),
                            pod_id.group(),
                            &self.validated_role_config,
                        )?;

                        let config_maps = self
                            .create_config_maps(pod_id, &role, validated_config)
                            .await?;

                        self.create_pod(
                            pod_id,
                            &role,
                            &node_id.name,
                            &config_maps,
                            validated_config,
                        )
                        .await?;

                        history.save(&self.context.resource).await?;

                        return Ok(ReconcileFunctionAction::Requeue(Duration::from_secs(10)));
                    }
                }
            }
        }

        // If we reach here it means all pods must be running on target_version.
        // We can now set current_version to target_version (if target_version was set) and
        // target_version to None
        finalize_versioning(&self.context.client, &self.context.resource).await?;

        Ok(ReconcileFunctionAction::Continue)
    }

    /// Creates the config maps required for a druid instance (or role, role_group combination):
    /// * The 'zoo.cfg' properties file
    /// * The 'myid' file
    ///
    /// The 'zoo.cfg' properties are read from the product_config and/or merged with the cluster
    /// custom resource.
    ///
    /// Labels are automatically adapted from the `recommended_labels` with a type (data for
    /// 'zoo.cfg' and id for 'myid'). Names are generated via `name_utils::build_resource_name`.
    ///
    /// Returns a map with a 'type' identifier (e.g. data, id) as key and the corresponding
    /// ConfigMap as value. This is required to set the volume mounts in the pod later on.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `validated_config` - The validated product config.
    /// - `id_mapping` - All id to node mappings required to create config maps
    ///
    async fn create_config_maps(
        &self,
        pod_id: &PodIdentity,
        role: &DruidRole,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<HashMap<&'static str, ConfigMap>, Error> {
        let mut config_maps = HashMap::new();
        let mut cm_conf_data = BTreeMap::new();

        for (property_name_kind, config) in validated_config {
            let mut transformed_config: BTreeMap<String, Option<String>> = config
                .iter()
                .map(|(k, v)| (k.clone(), Some(v.clone())))
                .collect();

            match property_name_kind {
                PropertyNameKind::File(file_name) if file_name == RUNTIME_PROPS => {
                    // NOTE: druid.host can be set manually - if it isn't, the canonical host name of
                    // the local host is used.  This should work with the agent and k8s host networking
                    // but might need to be revisited in the future

                    if let Some(zk_info) = &self.zookeeper_info {
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

        // druid config map
        let mut cm_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &self.context.resource.spec.version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );

        cm_labels.insert(
            configmap::CONFIGMAP_TYPE_LABEL.to_string(),
            CONFIG_MAP_TYPE_CONF.to_string(),
        );

        let cm_conf_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            None,
            Some(CONFIG_MAP_TYPE_CONF),
        )?;

        let cm_config = configmap::build_config_map(
            &self.context.resource,
            &cm_conf_name,
            &self.context.namespace(),
            cm_labels.clone(),
            cm_conf_data,
        )?;

        config_maps.insert(
            CONFIG_MAP_TYPE_CONF,
            configmap::create_config_map(&self.context.client, cm_config).await?,
        );

        Ok(config_maps)
    }

    /// Creates the pod required for the druid instance.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `node_name` - The node_name for this pod.
    /// - `config_maps` - The config maps and respective types required for this pod.
    /// - `validated_config` - The validated product config.
    ///
    async fn create_pod(
        &self,
        pod_id: &PodIdentity,
        role: &DruidRole,
        node_name: &str,
        config_maps: &HashMap<&'static str, ConfigMap>,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<Pod, Error> {
        let version = &self.context.resource.spec.version;

        let pod_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            Some(node_name),
            None,
        )?;

        let mut recommended_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );
        recommended_labels.insert(ID_LABEL.to_string(), pod_id.id().to_string());

        let mut pod_builder = PodBuilder::new();

        let secret = validated_config
            .get(&PropertyNameKind::Env)
            .and_then(|m| m.get(CREDENTIALS_SECRET_PROPERTY));

        let env = secret.map(|s| {
            vec![
                env_var_from_secret("AWS_ACCESS_KEY_ID", s, "accessKeyId"),
                env_var_from_secret("AWS_SECRET_ACCESS_KEY", s, "secretAccessKey"),
            ]
        });

        let mut cb = ContainerBuilder::new(APP_NAME);
        cb.image(container_image(version));
        cb.command(role.get_command(version));

        // One mount for the config directory
        if let Some(config_map_data) = config_maps.get(CONFIG_MAP_TYPE_CONF) {
            if let Some(name) = config_map_data.metadata.name.as_ref() {
                cb.add_volume_mount("config", "/stackable/conf");
                pod_builder.add_volume(VolumeBuilder::new("config").with_config_map(name).build());
            } else {
                return Err(error::Error::MissingConfigMapNameError {
                    cm_type: CONFIG_MAP_TYPE_CONF,
                });
            }
        } else {
            return Err(error::Error::MissingConfigMapError {
                cm_type: CONFIG_MAP_TYPE_CONF,
                pod_name,
            });
        }

        match &self.context.resource.spec.deep_storage.storage_type {
            DeepStorageType::Local => {
                let data_dir = String::from("/data");
                let dir = self
                    .context
                    .resource
                    .spec
                    .deep_storage
                    .storage_directory
                    .as_ref()
                    .unwrap_or(&data_dir);
                cb.add_volume_mount("data", "/data");
                pod_builder.add_volume(
                    VolumeBuilder::new("data")
                        .with_host_path(dir, Some("DirectoryOrCreate".to_string()))
                        .build(),
                );
                pod_builder.security_context(
                    PodSecurityContextBuilder::new()
                        .run_as_user(0)
                        .fs_group(0)
                        .run_as_group(0)
                        .build(),
                );
            }
            DeepStorageType::S3 => {}
            _ => {
                unimplemented!("Only local storage supported!")
            }
        }

        let annotations = BTreeMap::new();

        if let Some(plaintext_port) = validated_config
            .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
            .and_then(|props| props.get(DRUID_PLAINTEXTPORT))
            .map(|port| port.parse::<i32>().unwrap())
        {
            cb.add_container_port(CONTAINER_PLAINTEXT_PORT, plaintext_port);
        }

        if let Some(metrics_port) = validated_config
            .get(&PropertyNameKind::File(RUNTIME_PROPS.to_string()))
            .and_then(|props| props.get(DRUID_METRICS_PORT))
            .map(|port| port.parse::<i32>().unwrap())
        {
            cb.add_container_port(CONTAINER_METRICS_PORT, metrics_port);
        }

        let mut container = cb.build();
        container.image_pull_policy = Some("IfNotPresent".to_string());
        container.env = env;

        let pod = pod_builder
            .metadata(
                ObjectMetaBuilder::new()
                    .generate_name(pod_name)
                    .namespace(&self.context.client.default_namespace)
                    .with_labels(recommended_labels)
                    .with_annotations(annotations)
                    .ownerreference_from_resource(&self.context.resource, Some(true), Some(true))?
                    .build()?,
            )
            .host_network(true)
            .add_container(container)
            .node_name(node_name)
            .build()?;

        trace!("create_pod: {:?}", pod_id);
        Ok(self.context.client.create(&pod).await?)
    }

    async fn delete_all_pods(&self) -> OperatorResult<ReconcileFunctionAction> {
        for pod in &self.existing_pods {
            self.context.client.delete(pod).await?;
        }
        Ok(ReconcileFunctionAction::Done)
    }

    pub async fn process_command(&mut self) -> DruidReconcileResult {
        match self.context.retrieve_current_command().await? {
            // if there is no new command and the execution status is stopped we stop the
            // reconcile loop here.
            None => match self.context.resource.cluster_execution_status() {
                Some(execution_status) if execution_status == ClusterExecutionStatus::Stopped => {
                    Ok(ReconcileFunctionAction::Done)
                }
                _ => Ok(ReconcileFunctionAction::Continue),
            },
            Some(command_ref) => match command_ref.kind.as_str() {
                "Restart" => {
                    info!("Restarting cluster [{:?}]", command_ref);
                    let mut restart_command: Restart =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_restart(&mut restart_command).await?)
                }
                "Start" => {
                    info!("Starting cluster [{:?}]", command_ref);
                    let mut start_command: Start =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_start(&mut start_command).await?)
                }
                "Stop" => {
                    info!("Stopping cluster [{:?}]", command_ref);
                    let mut stop_command: Stop =
                        materialize_command(&self.context.client, &command_ref).await?;

                    Ok(self.context.default_stop(&mut stop_command).await?)
                }
                _ => {
                    error!("Got unknown type of command: [{:?}]", command_ref);
                    Ok(ReconcileFunctionAction::Done)
                }
            },
        }
    }
}

fn container_image(version: &DruidVersion) -> String {
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

impl ReconciliationState for DruidState {
    type Error = error::Error;

    fn reconcile(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<ReconcileFunctionAction, Self::Error>> + Send + '_>>
    {
        info!("========================= Starting reconciliation =========================");

        Box::pin(async move {
            self.init_status()
                .await?
                .then(self.context.handle_deletion(
                    Box::pin(self.delete_all_pods()),
                    FINALIZER_NAME,
                    true,
                ))
                .await?
                .then(self.get_zookeeper_connection_information())
                .await?
                .then(self.context.delete_illegal_pods(
                    self.existing_pods.as_slice(),
                    &self.get_required_labels(),
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(
                    self.context
                        .wait_for_terminating_pods(self.existing_pods.as_slice()),
                )
                .await?
                .then(
                    self.context
                        .wait_for_running_and_ready_pods(&self.existing_pods),
                )
                .await?
                .then(self.process_command())
                .await?
                .then(self.context.delete_excess_pods(
                    list_eligible_nodes_for_role_and_group(&self.eligible_nodes).as_slice(),
                    &self.existing_pods,
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(self.create_missing_pods())
                .await
        })
    }
}

struct DruidStrategy {
    config: Arc<ProductConfigManager>,
}

impl DruidStrategy {
    pub fn new(config: ProductConfigManager) -> DruidStrategy {
        DruidStrategy {
            config: Arc::new(config),
        }
    }
}

/// Return a map where the key corresponds to the role_group (e.g. "default", "10core10Gb") and
/// a tuple of a vector of nodes that fit the role_groups selector description, and the role_groups
/// "replicas" field for scheduling missing pods or removing excess pods.
pub async fn find_nodes_that_fit_selectors<T>(
    client: &Client,
    namespace: Option<String>,
    role: &Role<T>,
    extra_match_labels: &Option<BTreeMap<String, String>>,
) -> OperatorResult<HashMap<String, EligibleNodesAndReplicas>>
where
    T: Serialize,
{
    let mut found_nodes = HashMap::new();
    for (group_name, role_group) in &role.role_groups {
        let mut selector = role_group.selector.to_owned().unwrap_or_default();
        // if extra match labels were provided, add them to the label selector
        if let Some(eml) = extra_match_labels {
            let mut match_labels = selector.match_labels.unwrap_or_default();
            match_labels.extend(eml.iter().map(|(k, v)| (k.clone(), v.clone())));
            selector.match_labels = Some(match_labels);
        }
        let nodes = client
            .list_with_label_selector(namespace.as_deref(), &selector)
            .await?;
        debug!(
            "Found [{}] nodes for role group [{}]: [{:?}]",
            nodes.len(),
            group_name,
            nodes
        );
        found_nodes.insert(
            group_name.clone(),
            EligibleNodesAndReplicas {
                nodes,
                replicas: role_group.replicas,
            },
        );
    }
    Ok(found_nodes)
}

#[async_trait]
impl ControllerStrategy for DruidStrategy {
    type Item = DruidCluster;
    type State = DruidState;
    type Error = Error;

    /// Init the Druid state. Store all available pods owned by this cluster for later processing.
    /// Retrieve nodes that fit selectors and store them for later processing:
    /// DruidRole (we only have 'server') -> role group -> list of nodes.
    async fn init_reconcile_state(
        &self,
        context: ReconciliationContext<Self::Item>,
    ) -> Result<Self::State, Self::Error> {
        let existing_pods = context
            .list_owned(build_common_labels_for_all_managed_resources(
                APP_NAME,
                &context.resource.name(),
            ))
            .await?;
        trace!(
            "{}: Found [{}] pods",
            context.log_name(),
            existing_pods.len()
        );

        let druid_spec: DruidClusterSpec = context.resource.spec.clone();

        let mut eligible_nodes = HashMap::new();

        let extra_labels = if druid_spec.deep_storage.storage_type == DeepStorageType::Local {
            druid_spec.deep_storage.data_node_selector
        } else {
            None
        };

        eligible_nodes.insert(
            DruidRole::Broker.to_string(),
            find_nodes_that_fit_selectors(&context.client, None, &druid_spec.brokers, &None)
                .await?,
        );
        eligible_nodes.insert(
            DruidRole::Coordinator.to_string(),
            find_nodes_that_fit_selectors(&context.client, None, &druid_spec.coordinators, &None)
                .await?,
        );
        eligible_nodes.insert(
            DruidRole::Historical.to_string(),
            find_nodes_that_fit_selectors(
                &context.client,
                None,
                &druid_spec.historicals,
                &extra_labels,
            )
            .await?,
        );
        eligible_nodes.insert(
            DruidRole::MiddleManager.to_string(),
            find_nodes_that_fit_selectors(
                &context.client,
                None,
                &druid_spec.middle_managers,
                &extra_labels,
            )
            .await?,
        );
        eligible_nodes.insert(
            DruidRole::Router.to_string(),
            find_nodes_that_fit_selectors(&context.client, None, &druid_spec.routers, &None)
                .await?,
        );

        let mut roles = HashMap::new();

        let config_files = vec![
            PropertyNameKind::Env,
            PropertyNameKind::File(JVM_CONFIG.to_string()),
            PropertyNameKind::File(LOG4J2_CONFIG.to_string()),
            PropertyNameKind::File(RUNTIME_PROPS.to_string()),
        ];

        roles.insert(
            DruidRole::Broker.to_string(),
            (
                config_files.clone(),
                context.resource.spec.brokers.clone().into(),
            ),
        );

        roles.insert(
            DruidRole::Coordinator.to_string(),
            (
                config_files.clone(),
                context.resource.spec.coordinators.clone().into(),
            ),
        );

        roles.insert(
            DruidRole::Historical.to_string(),
            (
                config_files.clone(),
                context.resource.spec.historicals.clone().into(),
            ),
        );

        roles.insert(
            DruidRole::MiddleManager.to_string(),
            (
                config_files.clone(),
                context.resource.spec.middle_managers.clone().into(),
            ),
        );

        roles.insert(
            DruidRole::Router.to_string(),
            (config_files, context.resource.spec.routers.clone().into()),
        );

        let role_config = transform_all_roles_to_config(&context.resource, roles);
        let validated_role_config = validate_all_roles_and_groups_config(
            &context.resource.spec.version.to_string(),
            &role_config,
            &self.config,
            false,
            false,
        )?;

        Ok(DruidState {
            context,
            existing_pods,
            eligible_nodes,
            validated_role_config,
            zookeeper_info: None,
        })
    }
}

/// This creates an instance of a [`Controller`] which waits for incoming events and reconciles them.
///
/// This is an async method and the returned future needs to be consumed to make progress.
pub async fn create_controller(client: Client, product_config_path: &str) -> OperatorResult<()> {
    if let Err(error) = stackable_operator::crd::wait_until_crds_present(
        &client,
        vec![
            DruidCluster::crd_name(),
            Restart::crd_name(),
            Start::crd_name(),
            Stop::crd_name(),
        ],
        None,
    )
    .await
    {
        error!("Required CRDs missing, aborting: {:?}", error);
        return Err(error);
    };

    let api: Api<DruidCluster> = client.get_all_api();
    let pods_api: Api<Pod> = client.get_all_api();
    let config_maps_api: Api<ConfigMap> = client.get_all_api();
    let cmd_restart_api: Api<Restart> = client.get_all_api();
    let cmd_start_api: Api<Start> = client.get_all_api();
    let cmd_stop_api: Api<Stop> = client.get_all_api();

    let controller = Controller::new(api)
        .owns(pods_api, ListParams::default())
        .owns(config_maps_api, ListParams::default())
        .owns(cmd_restart_api, ListParams::default())
        .owns(cmd_start_api, ListParams::default())
        .owns(cmd_stop_api, ListParams::default());

    let product_config = ProductConfigManager::from_yaml_file(product_config_path).unwrap();

    let strategy = DruidStrategy::new(product_config);

    controller
        .run(client, strategy, Duration::from_secs(10))
        .await;

    Ok(())
}
