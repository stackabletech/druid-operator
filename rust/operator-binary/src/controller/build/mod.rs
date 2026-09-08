//! Build steps that turn a `ValidatedCluster` into Kubernetes resources.

use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::Secret,
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
        build::resource::{
            config_map::build_rolegroup_config_map,
            discovery::build_discovery_configmap,
            listener::{build_group_listener, group_listener_name},
            pdb::build_pdb,
            rbac::{build_role_binding, build_service_account},
            service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
            statefulset::build_rolegroup_statefulset,
        },
        validate::ValidatedCluster,
    },
    crd::{COOKIE_PASSPHRASE_SECRET_KEY, security::INTERNAL_INITIAL_CLIENT_PASSWORD_SECRET_KEY},
    internal_secret::build_shared_internal_secret_name,
};

pub mod authentication;
pub mod graceful_shutdown;
pub mod jvm;
pub mod properties;
pub mod resource;
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
    #[snafu(display("failed to build ConfigMap for role group {role_group}"))]
    ConfigMap {
        source: resource::config_map::Error,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build StatefulSet for role group {role_group}"))]
    StatefulSet {
        source: resource::statefulset::Error,
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
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut config_maps = vec![];
    let mut pod_disruption_budgets = vec![];

    for (druid_role, role_group_configs) in &cluster.role_group_configs {
        let role_config = cluster.role_config(druid_role);

        if let Some(pdb) = build_pdb(&role_config.pdb, cluster, druid_role) {
            pod_disruption_budgets.push(pdb);
        }

        if let Some(listener_class) = &role_config.listener_class
            && let Some(listener_group_name) = group_listener_name(&cluster.name, druid_role)
        {
            listeners.push(build_group_listener(
                cluster,
                listener_class,
                listener_group_name,
                druid_role,
            ));
        }

        for (role_group_name, rg) in role_group_configs {
            services.push(build_rolegroup_headless_service(
                cluster,
                druid_role,
                role_group_name,
            ));
            services.push(build_rolegroup_metrics_service(
                cluster,
                druid_role,
                role_group_name,
            ));
            config_maps.push(
                build_rolegroup_config_map(cluster, druid_role, role_group_name, rg).context(
                    ConfigMapSnafu {
                        role_group: role_group_name.clone(),
                    },
                )?,
            );
            stateful_sets.push(
                build_rolegroup_statefulset(cluster, druid_role, role_group_name, rg).context(
                    StatefulSetSnafu {
                        role_group: role_group_name.clone(),
                    },
                )?,
            );
        }
    }

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
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::{
        crd::listener::{self, v1alpha1::Listener},
        k8s_openapi::{ByteString, api::core::v1::Secret},
        kube::{Resource, api::ObjectMeta},
    };

    use super::{KubernetesResources, Prepared, SecretKey, build, internal_secret_keys};
    use crate::{
        controller::validate::test_support::{
            MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
        },
        crd::security::TLS_PORT_NAME,
    };

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
