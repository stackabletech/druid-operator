//! Build steps that turn a `ValidatedCluster` into Kubernetes resources.

use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Secret, Service},
    },
    kube::ResourceExt,
    kvp::Labels,
    v2::{
        builder::meta::ownerreference_from_resource,
        kvp::label,
        types::{
            kubernetes::SecretKey,
            operator::{RoleGroupName, RoleName},
        },
    },
};

use crate::{
    controller::{
        CONTROLLER_NAME, KubernetesResources, OPERATOR_NAME, PRODUCT_NAME, Prepared,
        build::{
            resource::{
                discovery::build_discovery_configmap,
                listener::{build_group_listener, group_listener_name},
                pdb::build_pdb,
                rbac::{build_role_binding, build_service_account},
            },
            role_group::{
                RoleGroupBuilder, broker, coordinator, historical, middle_manager, router,
            },
        },
        validate::ValidatedCluster,
    },
    crd::{
        COOKIE_PASSPHRASE_SECRET_KEY, DruidRole,
        security::INTERNAL_INITIAL_CLIENT_PASSWORD_SECRET_KEY,
    },
    internal_secret::build_shared_internal_secret_name,
};

pub mod authentication;
pub mod container;
pub mod jvm;
pub mod properties;
pub mod resource;
pub mod role_group;
pub mod security;

/// Returns an [`ObjectMetaBuilder`] pre-filled with the cluster's namespace, an owner
/// reference back to the cluster, the resource `name` and the given `recommended_labels`.
///
/// Consolidates the metadata chain repeated by the child-resource builders. Call sites that
/// need extra labels/annotations chain them onto the returned builder.
pub(crate) fn object_meta(
    cluster: &ValidatedCluster,
    name: impl Into<String>,
    recommended_labels: Labels,
) -> ObjectMetaBuilder {
    let mut builder = ObjectMetaBuilder::new();
    builder
        .name_and_namespace(cluster)
        .name(name)
        .ownerreference(ownerreference_from_resource(cluster, None, Some(true)))
        .with_labels(recommended_labels);
    builder
}

pub(crate) fn recommended_labels_for_cluster_resources(cluster: &ValidatedCluster) -> Labels {
    label::recommended_labels_for_cluster_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
    )
}

pub(crate) fn recommended_labels_for_role_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
) -> Labels {
    label::recommended_labels_for_role_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
    )
}

pub(crate) fn recommended_labels_for_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

pub(crate) fn recommended_labels_for_unversioned_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_unversioned_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

/// Selector labels matching the pods of a role group.
pub(crate) fn role_group_selector(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::role_group_selector(&cluster.name, &PRODUCT_NAME, role_name, role_group_name)
}

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build the resources of {role} role group {role_group}"))]
    RoleGroup {
        source: role_group::Error,
        role: DruidRole,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build the discovery ConfigMap"))]
    DiscoveryConfigMap { source: resource::discovery::Error },
}

/// Builds the Kubernetes resources for the given validated cluster.
///
/// Does not need a Kubernetes client: every reference to another Kubernetes resource is already
/// dereferenced and validated by this point.
/// The remaining errors are resource-assembly failures only.
pub fn build(cluster: &ValidatedCluster) -> Result<KubernetesResources<Prepared>, Error> {
    let mut listeners = vec![];
    let mut pod_disruption_budgets = vec![];
    let mut built = RoleGroupResources::default();

    // Role-level resources first, then each role group's, in `DruidRole` variant order.
    if let Some(pdb) = build_pdb(&cluster.coordinator_config.pdb, cluster, &coordinator::ROLE) {
        pod_disruption_budgets.push(pdb);
    }
    listeners.push(build_group_listener(
        cluster,
        &cluster.coordinator_config.listener_class,
        group_listener_name(&cluster.name, &coordinator::ROLE),
        &coordinator::ROLE,
    ));
    for (role_group_name, rg_config) in &cluster.coordinator_role_group_configs {
        coordinator::build(cluster, role_group_name, rg_config)
            .and_then(|builder| built.add(&builder))
            .with_context(|_| RoleGroupSnafu {
                role: coordinator::ROLE,
                role_group: role_group_name.clone(),
            })?;
    }

    if let Some(pdb) = build_pdb(&cluster.broker_config.pdb, cluster, &broker::ROLE) {
        pod_disruption_budgets.push(pdb);
    }
    listeners.push(build_group_listener(
        cluster,
        &cluster.broker_config.listener_class,
        group_listener_name(&cluster.name, &broker::ROLE),
        &broker::ROLE,
    ));
    for (role_group_name, rg_config) in &cluster.broker_role_group_configs {
        broker::build(cluster, role_group_name, rg_config)
            .and_then(|builder| built.add(&builder))
            .with_context(|_| RoleGroupSnafu {
                role: broker::ROLE,
                role_group: role_group_name.clone(),
            })?;
    }

    if let Some(pdb) = build_pdb(&cluster.historical_config.pdb, cluster, &historical::ROLE) {
        pod_disruption_budgets.push(pdb);
    }
    for (role_group_name, rg_config) in &cluster.historical_role_group_configs {
        historical::build(cluster, role_group_name, rg_config)
            .and_then(|builder| built.add(&builder))
            .with_context(|_| RoleGroupSnafu {
                role: historical::ROLE,
                role_group: role_group_name.clone(),
            })?;
    }

    if let Some(pdb) = build_pdb(
        &cluster.middle_manager_config.pdb,
        cluster,
        &middle_manager::ROLE,
    ) {
        pod_disruption_budgets.push(pdb);
    }
    for (role_group_name, rg_config) in &cluster.middle_manager_role_group_configs {
        middle_manager::build(cluster, role_group_name, rg_config)
            .and_then(|builder| built.add(&builder))
            .with_context(|_| RoleGroupSnafu {
                role: middle_manager::ROLE,
                role_group: role_group_name.clone(),
            })?;
    }

    if let Some(pdb) = build_pdb(&cluster.router_config.pdb, cluster, &router::ROLE) {
        pod_disruption_budgets.push(pdb);
    }
    listeners.push(build_group_listener(
        cluster,
        &cluster.router_config.listener_class,
        group_listener_name(&cluster.name, &router::ROLE),
        &router::ROLE,
    ));
    for (role_group_name, rg_config) in &cluster.router_role_group_configs {
        router::build(cluster, role_group_name, rg_config)
            .and_then(|builder| built.add(&builder))
            .with_context(|_| RoleGroupSnafu {
                role: router::ROLE,
                role_group: role_group_name.clone(),
            })?;
    }

    let RoleGroupResources {
        services,
        mut config_maps,
        stateful_sets,
    } = built;

    if let Some(discovery_config_map) =
        build_discovery_configmap(cluster).context(DiscoveryConfigMapSnafu)?
    {
        config_maps.push(discovery_config_map);
    }

    Ok(KubernetesResources {
        stateful_sets,
        services,
        listeners,
        config_maps,
        pod_disruption_budgets,
        service_accounts: vec![build_service_account(cluster)],
        role_bindings: vec![build_role_binding(cluster)],
        internal_secret: build_internal_secret(cluster),
        status: PhantomData,
    })
}

/// The resources of the role groups, in the order the role-group loops of [`build`] add them.
#[derive(Default)]
struct RoleGroupResources {
    services: Vec<Service>,
    config_maps: Vec<ConfigMap>,
    stateful_sets: Vec<StatefulSet>,
}

impl RoleGroupResources {
    /// Adds the headless and metrics Services, the ConfigMap and the StatefulSet of one role
    /// group.
    fn add(&mut self, builder: &RoleGroupBuilder) -> Result<(), role_group::Error> {
        self.services.extend(builder.build_services());
        self.config_maps.push(builder.build_config_map()?);
        self.stateful_sets.push(builder.build_statefulset()?);
        Ok(())
    }
}

/// The shared internal Secret, emitted on *every* run so the apply step can track it in
/// `ClusterResources` like every other resource (a tracked resource that is not re-added in a
/// run would be deleted as an orphan).
///
/// Its contents are randomly generated, so an identical Secret can never be *rebuilt*. Instead:
///
/// - absent: a fresh Secret with random values for all required keys is generated;
/// - missing a required key: likewise replaced with a fresh Secret (warned about, as the changed
///   values cause a short Druid downtime);
/// - complete: the fetched values are re-emitted unchanged via [`reemit_internal_secret`],
///   making the apply of this Secret a no-op.
fn build_internal_secret(cluster: &ValidatedCluster) -> Secret {
    match &cluster.internal_secret {
        None => {
            let secret = build_shared_internal_secret(cluster);
            tracing::info!(
                secret_name = secret.name_any(),
                "Did not find a shared internal secret with the necessary data, so one will be \
                 created"
            );
            secret
        }
        Some(existing) => {
            let current_keys: HashSet<_> = existing
                .data
                .clone()
                .unwrap_or_default()
                .into_keys()
                .collect();
            if let Some(missing_key) = internal_secret_keys()
                .into_iter()
                .find(|key| !current_keys.contains(key.as_ref()))
            {
                let secret = build_shared_internal_secret(cluster);
                tracing::warn!(
                    secret_name = secret.name_any(),
                    "Found shared internal secret, which is missing the key {missing_key}: this \
                    will be patched. This should only happen once and will change the contents of \
                    the Secret. This might cause a short downtime of Druid, as the changed \
                    internal Secrets need to propagate through all Druid nodes"
                );
                secret
            } else {
                reemit_internal_secret(cluster, existing)
            }
        }
    }
}

/// The keys the shared internal Secret must contain. Single source for both
/// [`build_shared_internal_secret`] and the missing-key check in [`build_internal_secret`].
fn internal_secret_keys() -> [&'static SecretKey; 2] {
    [
        &INTERNAL_INITIAL_CLIENT_PASSWORD_SECRET_KEY,
        &COOKIE_PASSPHRASE_SECRET_KEY,
    ]
}

fn build_shared_internal_secret(cluster: &ValidatedCluster) -> Secret {
    let internal_secret: BTreeMap<String, String> = internal_secret_keys()
        .iter()
        .map(|key| (key.to_string(), get_random_base64()))
        .collect();

    Secret {
        metadata: internal_secret_meta(cluster).build(),
        string_data: Some(internal_secret),
        ..Secret::default()
    }
}

/// Re-emits an existing complete internal Secret so that the apply step can track it in
/// `ClusterResources` like every other resource.
///
/// The fetched `data` is carried over unchanged: the values are randomly generated at creation
/// and cannot be rebuilt, so echoing them back is the only way to always emit a Secret without
/// rotating the credentials. Applying identical content via server-side apply changes nothing on
/// the server (a no-op: no watch event, no propagation into the Pods, no restart).
///
/// The metadata is built fresh instead of echoing the fetched metadata: a fetched object carries
/// server-populated fields (`resourceVersion`, `uid`, `managedFields`) that must not appear in an
/// apply patch, and the labels required by `ClusterResources::add` are added here.
fn reemit_internal_secret(cluster: &ValidatedCluster, existing: &Secret) -> Secret {
    Secret {
        metadata: internal_secret_meta(cluster).build(),
        data: existing.data.clone(),
        ..Secret::default()
    }
}

/// Shared metadata for both the freshly generated and the re-emitted internal Secret, so that
/// the two are identical apart from their contents.
fn internal_secret_meta(cluster: &ValidatedCluster) -> ObjectMetaBuilder {
    // The internal Secret is shared by the whole cluster rather than tied to a role or role
    // group, so it carries the cluster-resource labels (like the RBAC resources).
    object_meta(
        cluster,
        build_shared_internal_secret_name(&cluster.name).to_string(),
        recommended_labels_for_cluster_resources(cluster),
    )
}

fn get_random_base64() -> String {
    let mut buf = [0; 512];
    openssl::rand::rand_bytes(&mut buf).expect(
        "the OpenSSL CSPRNG could not supply random bytes (e.g. it is not seeded); \
         continuing would turn the zero-initialized buffer into a predictable secret",
    );
    openssl::base64::encode_block(&buf)
}

#[cfg(test)]
pub(crate) mod test_support {
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::role_group::{
        RoleGroupBuilder, broker, coordinator, historical, middle_manager, router,
    };
    use crate::{controller::validate::ValidatedCluster, crd::DruidRole};

    /// The [`RoleGroupBuilder`] of the role group, resolved by its role's module as
    /// [`build`](super::build) does, so that a test can build one resource of the role group
    /// without building the whole cluster.
    pub(crate) fn role_group_builder<'a>(
        cluster: &'a ValidatedCluster,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> RoleGroupBuilder<'a> {
        let missing = "the role group exists";
        match role {
            DruidRole::Coordinator => coordinator::build(
                cluster,
                role_group_name,
                cluster
                    .coordinator_role_group_configs
                    .get(role_group_name)
                    .expect(missing),
            ),
            DruidRole::Broker => broker::build(
                cluster,
                role_group_name,
                cluster
                    .broker_role_group_configs
                    .get(role_group_name)
                    .expect(missing),
            ),
            DruidRole::Historical => historical::build(
                cluster,
                role_group_name,
                cluster
                    .historical_role_group_configs
                    .get(role_group_name)
                    .expect(missing),
            ),
            DruidRole::MiddleManager => middle_manager::build(
                cluster,
                role_group_name,
                cluster
                    .middle_manager_role_group_configs
                    .get(role_group_name)
                    .expect(missing),
            ),
            DruidRole::Router => router::build(
                cluster,
                role_group_name,
                cluster
                    .router_role_group_configs
                    .get(role_group_name)
                    .expect(missing),
            ),
        }
        .expect("the role group resolves")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::{
        crd::listener::{self, v1alpha1::Listener},
        k8s_openapi::{
            ByteString,
            api::{
                apps::v1::{StatefulSet, StatefulSetSpec},
                core::v1::{ConfigMap, Container as PodContainer, PodSpec, Secret},
            },
        },
        kube::{Resource, api::ObjectMeta},
        utils::yaml_from_str_singleton_map,
        v2::types::operator::RoleGroupName,
    };
    use strum::IntoEnumIterator;

    use super::{
        KubernetesResources, Prepared, SecretKey, build,
        container::{
            DRUID_CONFIG_VOLUME_NAME, HDFS_CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME,
            LOG_VOLUME_NAME, RW_CONFIG_VOLUME_NAME,
        },
        internal_secret_keys,
        properties::ConfigFileName,
        resource::{config_map::INDEXER_JAVA_OPTS, listener::LISTENER_VOLUME_NAME},
        role_group::coordinator::derby_log_jvm_argument,
        security::{TLS_MOUNT_VOLUME_NAME, TLS_VOLUME_NAME},
    };
    use crate::{
        controller::validate::{
            ValidatedCluster,
            test_support::{
                MINIMAL_DRUID_YAML, dereferenced_objects, druid_from_yaml, validated_cluster,
                validated_cluster_from,
            },
        },
        crd::{
            Container, DruidRole, PROP_SEGMENT_CACHE_LOCATIONS,
            resource::SEGMENT_CACHE_VOLUME_NAME, security::TLS_PORT_NAME,
        },
    };

    /// The user-supplied extra volume of [`rich_druid_yaml`].
    const EXTRA_VOLUME_NAME: &str = "user-data";

    /// A cluster that takes every role-specific build path at once: TLS between the roles, OIDC
    /// authentication (which skips MiddleManagers), OPA authorization, the Vector agent on every
    /// role, a custom log ConfigMap on the Brokers, overrides for the three rendered files and
    /// the environment, an extra volume, a Historical segment cache, and two Broker role groups.
    ///
    /// S3 ingestion is not part of it: the MiddleManager indexer options and the JVM arguments
    /// it adds are the same for every role group of the role and are covered by the
    /// `ingestion-s3-ext` kuttl test.
    fn rich_druid_yaml() -> String {
        format!(
            r#"
apiVersion: druid.stackable.tech/v1alpha1
kind: DruidCluster
metadata:
  name: simple-druid
  namespace: default
  uid: c27b3971-ca72-42c1-80a4-abdfc1db0ddd
spec:
  image:
    productVersion: 30.0.0
  clusterConfig:
    authentication:
      - authenticationClass: oidc
        oidc:
          clientCredentialsSecret: oidc-client-credentials
    authorization:
      opa:
        configMapName: opa
        package: druid
    deepStorage:
      hdfs:
        configMapName: simple-hdfs
        directory: /druid
    extraVolumes:
      - name: {EXTRA_VOLUME_NAME}
        configMap:
          name: {EXTRA_VOLUME_NAME}
    metadataDatabase:
      postgresql:
        host: druid-postgresql
        database: druid
        credentialsSecretName: mySecret
    tls:
      serverAndInternalSecretClass: tls
    vectorAggregatorConfigMapName: vector-aggregator-discovery
    zookeeperConfigMapName: simple-druid-znode
  brokers:
    config:
      logging:
        enableVectorAgent: true
        containers:
          druid:
            custom:
              configMap: druid-log-config
    configOverrides:
      runtime.properties:
        druid.broker.http.numConnections: "10"
      security.properties:
        networkaddress.cache.ttl: "10"
    envOverrides:
      BROKER_ENV: broker
    roleGroups:
      default:
        replicas: 1
      secondary:
        replicas: 2
  coordinators:
    config:
      logging:
        enableVectorAgent: true
    roleGroups:
      default:
        replicas: 1
  historicals:
    config:
      logging:
        enableVectorAgent: true
      resources:
        memory:
          limit: 4Gi
        storage:
          segmentCache:
            freePercentage: 3
            emptyDir:
              capacity: 2G
    roleGroups:
      default:
        replicas: 1
  middleManagers:
    config:
      logging:
        enableVectorAgent: true
    roleGroups:
      default:
        replicas: 1
  routers:
    config:
      logging:
        enableVectorAgent: true
    roleGroups:
      default:
        replicas: 1
"#
        )
    }

    /// The OIDC `AuthenticationClass` referenced by [`rich_druid_yaml`].
    const OIDC_AUTHENTICATION_CLASS_YAML: &str = r#"
metadata:
  name: oidc
spec:
  provider:
    oidc:
      hostname: my.oidc.server
      principalClaim: preferred_username
      scopes: []
"#;

    /// Builds [`rich_druid_yaml`] through the real validate step with the OIDC
    /// `AuthenticationClass` and an OPA document URL dereferenced.
    fn rich_validated_cluster() -> ValidatedCluster {
        let druid = druid_from_yaml(&rich_druid_yaml());
        let oidc_authentication_class = yaml_from_str_singleton_map(OIDC_AUTHENTICATION_CLASS_YAML)
            .expect("the test AuthenticationClass YAML is valid");
        let dereferenced_objects = dereferenced_objects();
        validated_cluster_from(
            &druid,
            &crate::controller::dereference::DereferencedObjects {
                opa_base_document_url: Some(
                    "http://opa.default.svc.cluster.local:8081/v1/data/druid".to_string(),
                ),
                authentication_classes: vec![oidc_authentication_class],
                ..dereferenced_objects
            },
        )
    }

    /// The `default` role group, which every role of [`rich_druid_yaml`] has.
    fn default_role_group() -> RoleGroupName {
        "default".parse().expect("valid role group name")
    }

    /// The built ConfigMap of the role group, found by the name the builder derives from the
    /// cluster.
    fn role_group_config_map<'a>(
        resources: &'a KubernetesResources<Prepared>,
        cluster: &ValidatedCluster,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> &'a ConfigMap {
        let name = cluster
            .role_group_resource_names(role, role_group_name)
            .role_group_config_map()
            .to_string();
        resources
            .config_maps
            .iter()
            .find(|config_map| config_map.metadata.name.as_deref() == Some(name.as_str()))
            .expect("the role group's ConfigMap is built")
    }

    /// The built StatefulSet of the role group, found by the name the builder derives from the
    /// cluster.
    fn role_group_stateful_set<'a>(
        resources: &'a KubernetesResources<Prepared>,
        cluster: &ValidatedCluster,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> &'a StatefulSet {
        let name = cluster
            .role_group_resource_names(role, role_group_name)
            .stateful_set_name()
            .to_string();
        resources
            .stateful_sets
            .iter()
            .find(|stateful_set| stateful_set.metadata.name.as_deref() == Some(name.as_str()))
            .expect("the role group's StatefulSet is built")
    }

    fn stateful_set_spec<'a>(
        resources: &'a KubernetesResources<Prepared>,
        cluster: &ValidatedCluster,
        role: &DruidRole,
    ) -> &'a StatefulSetSpec {
        role_group_stateful_set(resources, cluster, role, &default_role_group())
            .spec
            .as_ref()
            .expect("the StatefulSet has a spec")
    }

    fn pod_spec(spec: &StatefulSetSpec) -> &PodSpec {
        spec.template
            .spec
            .as_ref()
            .expect("the pod template has a spec")
    }

    fn container<'a>(spec: &'a StatefulSetSpec, name: &str) -> &'a PodContainer {
        pod_spec(spec)
            .containers
            .iter()
            .find(|container| container.name == name)
            .expect("the container exists")
    }

    fn container_mounts(spec: &StatefulSetSpec, name: &str) -> Vec<String> {
        container(spec, name)
            .volume_mounts
            .iter()
            .flatten()
            .map(|mount| mount.name.clone())
            .collect()
    }

    fn has_pod_volume(spec: &StatefulSetSpec, name: &str) -> bool {
        pod_spec(spec)
            .volumes
            .iter()
            .flatten()
            .any(|volume| volume.name == name)
    }

    fn has_claim_template(spec: &StatefulSetSpec, name: &str) -> bool {
        spec.volume_claim_templates
            .iter()
            .flatten()
            .any(|pvc| pvc.metadata.name.as_deref() == Some(name))
    }

    fn config_map_data<'a>(
        resources: &'a KubernetesResources<Prepared>,
        cluster: &ValidatedCluster,
        role: &DruidRole,
    ) -> &'a BTreeMap<String, String> {
        role_group_config_map(resources, cluster, role, &default_role_group())
            .data
            .as_ref()
            .expect("the ConfigMap has data")
    }

    /// A pod's `volumes` are an ordered list: reordering them changes the pod template of every
    /// running StatefulSet and so restarts its pods. Pinned on the fixture that has every
    /// optional volume: the operator-managed volumes first, the Historical segment cache after
    /// them, the user's extra volumes last.
    #[test]
    fn pod_volumes_keep_their_order() {
        let cluster = rich_validated_cluster();
        let resources = build(&cluster).expect("build succeeds");
        for role in DruidRole::iter() {
            let mut expected: Vec<String> = vec![
                TLS_MOUNT_VOLUME_NAME.to_string(),
                TLS_VOLUME_NAME.to_string(),
                DRUID_CONFIG_VOLUME_NAME.to_string(),
                RW_CONFIG_VOLUME_NAME.to_string(),
                LOG_CONFIG_VOLUME_NAME.to_string(),
                LOG_VOLUME_NAME.to_string(),
                HDFS_CONFIG_VOLUME_NAME.to_string(),
            ];
            if matches!(role, DruidRole::Historical) {
                expected.push(SEGMENT_CACHE_VOLUME_NAME.to_string());
            }
            expected.push(EXTRA_VOLUME_NAME.to_string());

            let actual: Vec<String> = pod_spec(stateful_set_spec(&resources, &cluster, &role))
                .volumes
                .iter()
                .flatten()
                .map(|volume| volume.name.clone())
                .collect();
            assert_eq!(actual, expected, "{role:?} pod volumes");
        }
    }

    /// Only Brokers, Coordinators and Routers get a listener claim template.
    #[test]
    fn only_broker_coordinator_and_router_have_listener_claim_templates() {
        let cluster = rich_validated_cluster();
        let resources = build(&cluster).expect("build succeeds");
        let listener_volume_name = LISTENER_VOLUME_NAME.to_string();
        for role in DruidRole::iter() {
            let expected = matches!(
                role,
                DruidRole::Broker | DruidRole::Coordinator | DruidRole::Router
            );
            assert_eq!(
                has_claim_template(
                    stateful_set_spec(&resources, &cluster, &role),
                    &listener_volume_name
                ),
                expected,
                "{role:?} listener claim template"
            );
        }
    }

    /// Only Historicals get the segment cache: its pod volume, its mount on the `druid`
    /// container, and `druid.segmentCache.locations` in runtime.properties.
    #[test]
    fn only_historicals_have_the_segment_cache() {
        let cluster = rich_validated_cluster();
        let resources = build(&cluster).expect("build succeeds");
        let segment_cache_volume_name = SEGMENT_CACHE_VOLUME_NAME.to_string();
        let druid_container_name = Container::Druid.name().to_string();
        for role in DruidRole::iter() {
            let expected = matches!(role, DruidRole::Historical);
            let spec = stateful_set_spec(&resources, &cluster, &role);
            assert_eq!(
                has_pod_volume(spec, &segment_cache_volume_name),
                expected,
                "{role:?} segment cache volume"
            );
            assert_eq!(
                container_mounts(spec, &druid_container_name).contains(&segment_cache_volume_name),
                expected,
                "{role:?} segment cache mount"
            );
            assert_eq!(
                config_map_data(&resources, &cluster, &role)
                    [&ConfigFileName::RuntimeProperties.to_string()]
                    .contains(PROP_SEGMENT_CACHE_LOCATIONS),
                expected,
                "{role:?} segment cache locations"
            );
        }
    }

    /// Only MiddleManagers set `druid.indexer.runner.javaOptsArray`, in both runtime.properties
    /// and security.properties, and only they have a pre-stop hook on the `druid` container.
    #[test]
    fn only_middle_managers_have_indexer_opts_and_the_drain_hook() {
        let cluster = rich_validated_cluster();
        let resources = build(&cluster).expect("build succeeds");
        let druid_container_name = Container::Druid.name().to_string();
        for role in DruidRole::iter() {
            let expected = matches!(role, DruidRole::MiddleManager);
            let data = config_map_data(&resources, &cluster, &role);
            assert_eq!(
                data[&ConfigFileName::RuntimeProperties.to_string()].contains(INDEXER_JAVA_OPTS),
                expected,
                "{role:?} indexer opts in runtime.properties"
            );
            assert_eq!(
                data[&ConfigFileName::SecurityProperties.to_string()].contains(INDEXER_JAVA_OPTS),
                expected,
                "{role:?} indexer opts in security.properties"
            );
            assert_eq!(
                container(
                    stateful_set_spec(&resources, &cluster, &role),
                    &druid_container_name
                )
                .lifecycle
                .as_ref()
                .and_then(|lifecycle| lifecycle.pre_stop.as_ref())
                .is_some(),
                expected,
                "{role:?} pre-stop hook"
            );
        }
    }

    /// Only the Coordinator's jvm.config carries the Derby error-log argument.
    #[test]
    fn only_coordinators_set_the_derby_log() {
        let cluster = rich_validated_cluster();
        let resources = build(&cluster).expect("build succeeds");
        let derby_log_argument = derby_log_jvm_argument();
        for role in DruidRole::iter() {
            assert_eq!(
                config_map_data(&resources, &cluster, &role)
                    [&ConfigFileName::JvmConfig.to_string()]
                    .contains(&derby_log_argument),
                matches!(role, DruidRole::Coordinator),
                "{role:?} derby log"
            );
        }
    }

    /// The expected `app.kubernetes.io/version` label value for the given product version.
    ///
    /// The `-stackable` suffix carries the operator's own version, which is `0.0.0-dev` on main
    /// but rewritten by the release process — so tests must derive it rather than hardcode it,
    /// or they fail on release branches.
    fn app_version_label(product_version: &str) -> String {
        format!(
            "{product_version}-stackable{}",
            crate::built_info::PKG_VERSION
        )
    }

    fn sorted_names(resources: &[impl Resource]) -> Vec<&str> {
        let mut names: Vec<&str> = resources
            .iter()
            .filter_map(|resource| resource.meta().name.as_deref())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn build_produces_expected_resource_names() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");

        // One StatefulSet and one ConfigMap per role group (one role group per role).
        let expected_role_group_names = [
            "simple-druid-broker-default",
            "simple-druid-coordinator-default",
            "simple-druid-historical-default",
            "simple-druid-middlemanager-default",
            "simple-druid-router-default",
        ];
        assert_eq!(
            sorted_names(&resources.stateful_sets),
            expected_role_group_names
        );
        assert_eq!(
            sorted_names(&resources.config_maps),
            expected_role_group_names
        );

        // Group Listeners are built for the externally reachable roles: Broker, Coordinator and
        // Router.
        assert_eq!(
            sorted_names(&resources.listeners),
            [
                "simple-druid-broker",
                "simple-druid-coordinator",
                "simple-druid-router"
            ]
        );
    }

    /// A Router group Listener whose status carries an ingress address, as the listener-operator
    /// eventually writes it. The `validated_cluster` fixture enables TLS, so the address exposes
    /// the TLS port.
    fn router_listener_with_address() -> Listener {
        Listener {
            metadata: ObjectMeta::default(),
            spec: listener::v1alpha1::ListenerSpec::default(),
            status: Some(listener::v1alpha1::ListenerStatus {
                service_name: None,
                ingress_addresses: Some(vec![listener::v1alpha1::ListenerIngress {
                    address: "druid.example.com".to_string(),
                    address_type: listener::v1alpha1::AddressType::Hostname,
                    ports: BTreeMap::from([(TLS_PORT_NAME.to_string(), 9088)]),
                }]),
                node_ports: None,
            }),
        }
    }

    /// The built discovery ConfigMap (named after the cluster itself), if any.
    fn discovery_config_map(
        resources: &KubernetesResources<Prepared>,
    ) -> Option<&stackable_operator::k8s_openapi::api::core::v1::ConfigMap> {
        resources
            .config_maps
            .iter()
            .find(|config_map| config_map.metadata.name.as_deref() == Some("simple-druid"))
    }

    #[test]
    fn builds_discovery_config_map_with_listener_address() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);
        cluster.router_listener = Some(router_listener_with_address());

        let resources = build(&cluster).expect("build succeeds");

        let data = discovery_config_map(&resources)
            .expect("the discovery ConfigMap is built")
            .data
            .as_ref()
            .expect("the discovery ConfigMap carries data");
        assert_eq!(
            data.get("DRUID_ROUTER").map(String::as_str),
            Some("druid.example.com:9088")
        );
    }

    /// While the Listener is absent (the apply step has not created it yet) or carries no
    /// ingress address (the listener-operator has not reconciled it yet), the discovery
    /// ConfigMap is skipped, *without* failing the build: the Listener watch triggers a new
    /// reconcile run once the address is set.
    #[test]
    fn skips_discovery_config_map_without_listener_address() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);

        let no_listener = None;
        let no_status = Some(Listener {
            status: None,
            ..router_listener_with_address()
        });
        let no_addresses = Some(Listener {
            status: Some(listener::v1alpha1::ListenerStatus {
                service_name: None,
                ingress_addresses: Some(vec![]),
                node_ports: None,
            }),
            ..router_listener_with_address()
        });
        for router_listener in [no_listener, no_status, no_addresses] {
            cluster.router_listener = router_listener;

            let resources = build(&cluster).expect("build succeeds without a listener address");

            assert!(discovery_config_map(&resources).is_none());
        }
    }

    /// An existing shared internal Secret carrying the given keys in `data`, shaped as the
    /// dereference step fetches it from the cluster.
    fn internal_secret_with_keys(keys: &[&SecretKey]) -> Secret {
        Secret {
            data: Some(
                keys.iter()
                    .map(|key| (key.to_string(), ByteString(b"value".to_vec())))
                    .collect(),
            ),
            ..Secret::default()
        }
    }

    #[test]
    fn build_creates_the_internal_secret_when_none_exists() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        assert!(cluster.internal_secret.is_none(), "fixture precondition");

        let resources = build(&cluster).expect("build succeeds");

        let secret = &resources.internal_secret;
        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("simple-druid-shared-internal-secret")
        );
        let data = secret
            .string_data
            .as_ref()
            .expect("the built secret carries generated contents");
        for key in internal_secret_keys() {
            assert!(
                data.contains_key(key.as_ref()),
                "generated secret must contain {key}"
            );
        }
        assert_required_cluster_resource_labels(&secret.metadata);
    }

    #[test]
    fn build_replaces_the_internal_secret_when_a_required_key_is_missing() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);
        cluster.internal_secret = Some(internal_secret_with_keys(&internal_secret_keys()[..1]));

        let resources = build(&cluster).expect("build succeeds");

        let data = resources
            .internal_secret
            .string_data
            .as_ref()
            .expect("the replacement carries generated contents");
        for key in internal_secret_keys() {
            assert!(
                data.contains_key(key.as_ref()),
                "replacement must contain {key}"
            );
        }
    }

    /// An existing complete Secret is re-emitted with its fetched values unchanged (nothing is
    /// regenerated), so applying it is a no-op, and with the labels required by
    /// `ClusterResources::add` so it can be tracked like every other resource.
    #[test]
    fn reemits_existing_internal_secret_when_complete() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let mut cluster = validated_cluster(&druid);
        cluster.internal_secret = Some(internal_secret_with_keys(&internal_secret_keys()));

        let resources = build(&cluster).expect("build succeeds");

        let secret = &resources.internal_secret;
        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("simple-druid-shared-internal-secret")
        );
        assert_eq!(
            secret.data,
            internal_secret_with_keys(&internal_secret_keys()).data,
            "the fetched values must be carried over unchanged"
        );
        assert!(
            secret.string_data.is_none(),
            "no contents may be regenerated for a complete secret"
        );
        assert_required_cluster_resource_labels(&secret.metadata);
    }

    /// Asserts the labels [`ClusterResources::add`] requires; without them the apply step
    /// rejects the resource.
    ///
    /// [`ClusterResources::add`]: stackable_operator::cluster_resources::ClusterResources::add
    fn assert_required_cluster_resource_labels(
        metadata: &stackable_operator::kube::api::ObjectMeta,
    ) {
        let labels = metadata.labels.as_ref().expect("labels are set");
        for (key, value) in [
            ("app.kubernetes.io/instance", "simple-druid"),
            ("app.kubernetes.io/name", "druid"),
            (
                "app.kubernetes.io/managed-by",
                "druid.stackable.tech_druidcluster",
            ),
        ] {
            assert_eq!(
                labels.get(key).map(String::as_str),
                Some(value),
                "label {key} must be set"
            );
        }
    }

    /// Locks the RBAC resource names, the roleRef, and the recommended label set against
    /// accidental drift. The fixture's cluster name deliberately differs from the product name so
    /// that swapped `name`/`instance` label values cannot pass unnoticed.
    #[test]
    fn build_produces_rbac() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");

        assert_eq!(
            sorted_names(&resources.service_accounts),
            ["simple-druid-serviceaccount"]
        );
        assert_eq!(
            sorted_names(&resources.role_bindings),
            ["simple-druid-rolebinding"]
        );

        let expected_labels = BTreeMap::from(
            [
                ("app.kubernetes.io/instance", "simple-druid".to_string()),
                (
                    "app.kubernetes.io/managed-by",
                    "druid.stackable.tech_druidcluster".to_string(),
                ),
                ("app.kubernetes.io/name", "druid".to_string()),
                ("app.kubernetes.io/version", app_version_label("30.0.0")),
                ("stackable.tech/vendor", "Stackable".to_string()),
            ]
            .map(|(key, value)| (key.to_string(), value)),
        );
        let service_account = resources
            .service_accounts
            .first()
            .expect("a ServiceAccount is built");
        assert_eq!(
            service_account.metadata.labels,
            Some(expected_labels.clone())
        );

        let role_binding = resources
            .role_bindings
            .first()
            .expect("a RoleBinding is built");
        assert_eq!(role_binding.metadata.labels, Some(expected_labels));
        assert_eq!(role_binding.role_ref.name, "druid-clusterrole");
    }
}
