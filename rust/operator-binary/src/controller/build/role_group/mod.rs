//! Building the Kubernetes resources of one role group.
//!
//! Two phases, so neither has to reach into the other. First each role's module gathers its
//! [`RoleGroupInputs`]: the values every role has, resolved from its typed role-group config, plus
//! the values only that role has (its group Listener, the Historical segment cache and
//! resource-derived `runtime.properties` entries, the MiddleManager indexer options and drain
//! hook, the Coordinator's Derby log argument). [`RoleGroupBuilder::new`] turns those into
//! finished containers, pod volumes and rendered `ConfigMap` entries. Then [`RoleGroupBuilder`]'s
//! `build_*` methods emit the Kubernetes objects, reading straight through fields that are already
//! resolved.
//!
//! Every Druid role runs the same containers (the `prepare` init container, the `druid` container
//! and the Vector sidecar), so the resolve and emit phases live here once. Everything that differs
//! between roles happens in the five role modules' `build` functions.

use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::affinity::StackableAffinity,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{
            ConfigMap, Container, LifecycleHandler, PersistentVolumeClaim, PodTemplateSpec,
            ResourceRequirements, Service, Volume, VolumeMount,
        },
    },
    memory::MemoryQuantity,
    shared::time::Duration,
    v2::{
        builder::pod::container::EnvVarSet,
        jvm_argument_overrides::JvmArgumentOverrides,
        types::{kubernetes::ListenerName, operator::RoleGroupName},
    },
};

use super::{container, resource};
use crate::{
    controller::validate::{ValidatedCluster, ValidatedLogging},
    crd::{DruidConfigOverrides, DruidRole},
};

pub(crate) mod broker;
pub(crate) mod coordinator;
pub(crate) mod historical;
pub(crate) mod middle_manager;
pub(crate) mod router;

/// Why building one role group failed. The caller adds which role and role group it was.
#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to derive the Druid memory settings from the resources"))]
    DeriveMemorySettings { source: crate::crd::memory::Error },

    #[snafu(display("failed to derive the heap size from the resources"))]
    HeapMemory { source: crate::crd::resource::Error },

    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("failed to render the config files"))]
    ConfigMapData { source: resource::config_map::Error },

    #[snafu(display("failed to build the containers and volumes"))]
    ContainersAndVolumes { source: container::Error },

    #[snafu(display("failed to build ConfigMap"))]
    ConfigMap { source: resource::config_map::Error },

    #[snafu(display("failed to build StatefulSet"))]
    StatefulSet {
        source: resource::statefulset::Error,
    },
}

/// What [`RoleGroupBuilder::new`] resolves, gathered by one role module from its typed
/// role-group config.
pub(crate) struct RoleGroupInputs<'a> {
    pub(crate) cluster: &'a ValidatedCluster,
    /// Read for the role group's object names and labels, and for the values that are functions
    /// of the role: its ports, its process name and its container commands.
    pub(crate) role: DruidRole,
    pub(crate) role_group_name: RoleGroupName,
    pub(crate) affinity: StackableAffinity,
    pub(crate) graceful_shutdown_timeout: Option<Duration>,
    pub(crate) requested_secret_lifetime: Duration,
    /// The `druid` container's resource requirements.
    pub(crate) resources: ResourceRequirements,
    /// The JVM heap size.
    pub(crate) heap: MemoryQuantity,
    /// The JVM direct memory size of the roles that use direct memory: Broker, Historical and
    /// Router.
    pub(crate) direct_memory: Option<MemoryQuantity>,
    pub(crate) logging: ValidatedLogging,
    /// The role's group Listener name; `Some` for Brokers, Coordinators and Routers. Drives the
    /// listener claim template, its mount on the `druid` container and the listener scope of the
    /// TLS volume.
    pub(crate) listener: Option<ListenerName>,
    /// Pod volumes only this role has (the Historical segment cache); empty for the other roles.
    pub(crate) role_pod_volumes: Vec<Volume>,
    /// The `druid` container's mounts of `role_pod_volumes`.
    pub(crate) role_druid_mounts: Vec<VolumeMount>,
    /// `runtime.properties` entries derived from the resources (the Historical segment cache
    /// location and processing settings), the lowest layer; empty for the other roles.
    pub(crate) resource_runtime_properties: BTreeMap<String, String>,
    /// The value of `druid.indexer.runner.javaOptsArray`, the JVM options of the tasks a
    /// MiddleManager spawns; `Some` for MiddleManagers only. Written to both runtime.properties
    /// and security.properties.
    pub(crate) indexer_java_opts: Option<String>,
    /// The role's static `runtime.properties` defaults, the layer right below the user's
    /// overrides.
    pub(crate) role_runtime_defaults: BTreeMap<String, String>,
    /// JVM arguments only this role has (the Coordinator's Derby log file), rendered after the
    /// arguments every role has; empty for the other roles.
    pub(crate) role_jvm_args: Vec<String>,
    /// The `druid` container's pre-stop hook; `Some` for MiddleManagers, which drain their tasks
    /// before they stop.
    pub(crate) druid_pre_stop: Option<LifecycleHandler>,
    /// Whether the role authenticates its users with OIDC when the cluster uses OIDC; false for
    /// MiddleManagers, which then run the system authenticator only.
    pub(crate) oidc_enabled: bool,
    pub(crate) replicas: Option<u16>,
    pub(crate) config_overrides: DruidConfigOverrides,
    pub(crate) env_overrides: EnvVarSet,
    pub(crate) pod_overrides: PodTemplateSpec,
    pub(crate) jvm_argument_overrides: JvmArgumentOverrides,
}

/// Everything one role group's Kubernetes objects are built from, already resolved.
///
/// These fields are outputs rather than configuration: the containers are built and the
/// `ConfigMap` entries rendered. The `build_*` methods therefore read straight through, and
/// nothing about which role this is reaches them beyond the role's name.
pub(crate) struct RoleGroupBuilder<'a> {
    pub(crate) cluster: &'a ValidatedCluster,
    /// Read for the role group's object names and labels.
    pub(crate) role: DruidRole,
    pub(crate) role_group_name: RoleGroupName,
    /// Read for the pod's affinity.
    pub(crate) affinity: StackableAffinity,
    /// Read for the pod's termination grace period.
    pub(crate) graceful_shutdown_timeout: Option<Duration>,
    /// The role group's replica count, passed to the StatefulSet as is; `None` makes Kubernetes
    /// run one pod.
    pub(crate) replicas: Option<u16>,
    pub(crate) pod_overrides: PodTemplateSpec,
    /// The listener claim template of a role with a Listener. `None` for the other roles, which
    /// keeps their StatefulSets without a `volumeClaimTemplates` field.
    pub(crate) volume_claim_templates: Option<Vec<PersistentVolumeClaim>>,
    /// The `prepare` init container.
    pub(crate) init_containers: Vec<Container>,
    /// The `druid` container, then the Vector sidecar when the Vector agent is enabled.
    pub(crate) containers: Vec<Container>,
    /// Every pod-level volume the containers mount, in the order the pod lists them.
    pub(crate) pod_volumes: Vec<Volume>,
    /// The rendered `ConfigMap` entries, keyed by file name.
    pub(crate) config_map_data: BTreeMap<String, String>,
}

impl<'a> RoleGroupBuilder<'a> {
    /// Resolves one role group: renders its config files, builds the containers every role runs
    /// and collects their pod volumes.
    pub(crate) fn new(inputs: RoleGroupInputs<'a>) -> Result<Self, Error> {
        let config_map_data =
            resource::config_map::config_map_data(&inputs).context(ConfigMapDataSnafu)?;
        let container::ContainersAndVolumes {
            init_containers,
            containers,
            pod_volumes,
            volume_claim_templates,
        } = container::containers_and_volumes(&inputs).context(ContainersAndVolumesSnafu)?;

        Ok(Self {
            cluster: inputs.cluster,
            role: inputs.role,
            role_group_name: inputs.role_group_name,
            affinity: inputs.affinity,
            graceful_shutdown_timeout: inputs.graceful_shutdown_timeout,
            replicas: inputs.replicas,
            pod_overrides: inputs.pod_overrides,
            volume_claim_templates,
            init_containers,
            containers,
            pod_volumes,
            config_map_data,
        })
    }

    /// The headless and metrics `Service`s.
    pub(crate) fn build_services(&self) -> Vec<Service> {
        vec![
            resource::service::build_rolegroup_headless_service(
                self.cluster,
                &self.role,
                &self.role_group_name,
            ),
            resource::service::build_rolegroup_metrics_service(
                self.cluster,
                &self.role,
                &self.role_group_name,
            ),
        ]
    }

    pub(crate) fn build_config_map(&self) -> Result<ConfigMap, Error> {
        resource::config_map::build_config_map(self).context(ConfigMapSnafu)
    }

    pub(crate) fn build_statefulset(&self) -> Result<StatefulSet, Error> {
        resource::statefulset::build_statefulset(self).context(StatefulSetSnafu)
    }
}
