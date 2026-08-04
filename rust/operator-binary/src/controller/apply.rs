//! The apply step in the DruidCluster controller.

use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    client::Client,
    cluster_resources::{ClusterResource, ClusterResourceApplyStrategy, ClusterResources},
    deep_merger::ObjectOverrides,
    k8s_openapi::api::core::v1::Secret,
    kube::ResourceExt,
    v2::{builder::meta::ownerreference_from_resource, cluster_resources::cluster_resources_new},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{
        Applied, KubernetesResources, Prepared, controller_name, operator_name, product_name,
        validate::ValidatedCluster,
    },
    crd::{COOKIE_PASSPHRASE_ENV, security::INTERNAL_INITIAL_CLIENT_PASSWORD_ENV},
    internal_secret::build_shared_internal_secret_name,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply Kubernetes resource"))]
    ApplyResource {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply internal secret"))]
    ApplyInternalSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to delete the immutable internal secret"))]
    DeleteImmutableInternalSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Applier for the Kubernetes resource specifications produced by this controller.
///
/// The implementation is not tied to this controller and could theoretically be moved to
/// stackable_operator if [`KubernetesResources`] would contain all possible resource types.
pub struct Applier<'a> {
    client: &'a Client,
    cluster_resources: ClusterResources<'a>,
}

impl<'a> Applier<'a> {
    pub fn new(
        client: &'a Client,
        cluster: &ValidatedCluster,
        apply_strategy: ClusterResourceApplyStrategy,
        object_overrides: &'a ObjectOverrides,
    ) -> Applier<'a> {
        let cluster_resources = cluster_resources_new(
            &product_name(),
            &operator_name(),
            &controller_name(),
            &cluster.name,
            &cluster.namespace,
            &cluster.uid,
            apply_strategy,
            object_overrides,
        );

        Applier {
            client,
            cluster_resources,
        }
    }

    /// Applies the given Kubernetes resources, deletes resources from earlier reconcile runs
    /// that were not applied in this one, and marks the resources as applied.
    ///
    /// Consumes the applier: a resource applied after the orphan deletion would itself be
    /// treated as an orphan and deleted by the next reconcile run.
    pub async fn apply(
        mut self,
        resources: KubernetesResources<Prepared>,
    ) -> Result<KubernetesResources<Applied>> {
        // Destructured without `..`, so adding a field to [`KubernetesResources`] fails to
        // compile here instead of silently never being applied.
        let KubernetesResources {
            stateful_sets,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: _,
        } = resources;

        // Apply order is: StatefulSets last (a changed mounted ConfigMap/Secret
        // must exist first, else Pods restart -- commons-operator#111). The ServiceAccount comes
        // first because the Pods reference it at creation time.
        let service_accounts = self.add_resources(service_accounts).await?;
        let role_bindings = self.add_resources(role_bindings).await?;
        let services = self.add_resources(services).await?;
        let listeners = self.add_resources(listeners).await?;
        let config_maps = self.add_resources(config_maps).await?;
        let pod_disruption_budgets = self.add_resources(pod_disruption_budgets).await?;
        let stateful_sets = self.add_resources(stateful_sets).await?;

        self.cluster_resources
            .delete_orphaned_resources(self.client)
            .await
            .context(DeleteOrphanedResourcesSnafu)?;

        Ok(KubernetesResources {
            stateful_sets,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: PhantomData,
        })
    }

    async fn add_resources<T: ClusterResource + Sync>(
        &mut self,
        resources: Vec<T>,
    ) -> Result<Vec<T>> {
        let mut applied_resources = vec![];

        for resource in resources {
            let applied_resource = self
                .cluster_resources
                .add(self.client, resource)
                .await
                .context(ApplyResourceSnafu)?;
            applied_resources.push(applied_resource);
        }

        Ok(applied_resources)
    }
}

/// Ensures the shared internal Secret (cookie passphrase + initial client password) exists,
/// creating it when missing, migrating away from the pre-2024-06 immutable Secret, and patching
/// in newly required keys. These are read-then-write client operations, so they cannot be part
/// of the client-free `build()` step; the Secret is also deliberately not tracked in
/// [`ClusterResources`], so it survives orphan deletion. Unlike a create-if-absent Secret, the
/// migration and repair paths may rewrite the contents (documented downtime warnings below).
pub async fn ensure_internal_secret(client: &Client, cluster: &ValidatedCluster) -> Result<()> {
    let controller_name = controller_name();
    let controller_name = controller_name.as_ref();
    let secret = build_shared_internal_secret(cluster);
    let existing_secret = client
        .get_opt::<Secret>(&secret.name_any(), cluster.namespace.as_ref())
        .await
        .context(FailedToRetrieveInternalSecretSnafu)?;
    let existing_immutable_secret = client
        .get_opt::<Secret>(
            &build_immutable_shared_internal_secret_name(cluster),
            cluster.namespace.as_ref(),
        )
        .await
        .context(FailedToRetrieveInternalSecretSnafu)?;

    match existing_secret {
        None => {
            match existing_immutable_secret {
                None => {
                    tracing::info!(
                        secret_name = secret.name_any(),
                        "Did not found a shared internal secret with the necessary data, creating one"
                    );
                    client
                        .apply_patch(controller_name, &secret, &secret)
                        .await
                        .context(ApplyInternalSecretSnafu)?;
                }
                Some(existing_immutable_secret) => {
                    // Before 2024-06-25 we did set `spec.immutable` to avoid accidentally changing the contents. Which was
                    // great back than, *but* we now need something more flexible. We can not make the Secret mutable,
                    // and re-creation with the same name is very error-prone so we create a mutable secret with a new name
                    // (see <https://github.com/kubernetes/website/issues/42359#issuecomment-2136192995>).
                    // We *could* read in the contents and use them during the re-creation (so we don't change the contents to avoid downtime),
                    // but we strive that our operators don't handle Secret contents and it's a one time migration.

                    tracing::warn!(
                        secret_name = secret.name_any(),
                        "Shared internal secret found, which is immutable. Re-creating it with a new name, as we can not modify it or re-create it \
                        with the same name. This should only happen once and will change the contents of the Secret. This might cause a short \
                        downtime of Druid, as the changed internal secrets need to propagate through all Druid nodes"
                    );

                    client
                        .delete(&existing_immutable_secret)
                        .await
                        .context(DeleteImmutableInternalSecretSnafu)?;

                    client
                        .apply_patch(controller_name, &secret, &secret)
                        .await
                        .context(ApplyInternalSecretSnafu)?;
                    return Ok(());
                }
            }
        }

        Some(existing_secret) => {
            let current_secret_keys = existing_secret
                .data
                .unwrap_or_default()
                .into_keys()
                .collect::<HashSet<_>>();
            for required in INTERNAL_SECRET_KEYS {
                if !current_secret_keys.contains(required) {
                    tracing::info!(
                        secret_name = secret.name_any(),
                        "Found shared internal secret, which is missing the key {required}, patching it"
                    );
                    tracing::warn!(
                        secret_name = secret.name_any(),
                        "Found shared internal secret, which is missing the key {required}, patching it. This \
                        should only happen once and will change the contents of the Secret. This might cause a short \
                        downtime of Druid, as the changed internal Secrets need to propagate through all Druid nodes"
                    );
                    client
                        .apply_patch(controller_name, &secret, &secret)
                        .await
                        .context(ApplyInternalSecretSnafu)?;
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// The keys the shared internal Secret must contain. Single source for both
/// [`build_shared_internal_secret`] and the missing-key check in [`ensure_internal_secret`].
const INTERNAL_SECRET_KEYS: [&str; 2] =
    [INTERNAL_INITIAL_CLIENT_PASSWORD_ENV, COOKIE_PASSPHRASE_ENV];

fn build_shared_internal_secret(cluster: &ValidatedCluster) -> Secret {
    let internal_secret: BTreeMap<String, String> = INTERNAL_SECRET_KEYS
        .iter()
        .map(|key| (key.to_string(), get_random_base64()))
        .collect();

    Secret {
        metadata: ObjectMetaBuilder::new()
            .name(build_shared_internal_secret_name(cluster))
            .namespace_opt(cluster.namespace())
            .ownerreference(ownerreference_from_resource(cluster, None, Some(true)))
            .build(),
        string_data: Some(internal_secret),
        ..Secret::default()
    }
}

fn build_immutable_shared_internal_secret_name(cluster: &ValidatedCluster) -> String {
    format!("{}-internal-secret", cluster.name_any())
}

fn get_random_base64() -> String {
    let mut buf = [0; 512];
    openssl::rand::rand_bytes(&mut buf).expect(
        "the OpenSSL CSPRNG could not supply random bytes (e.g. it is not seeded); \
         continuing would turn the zero-initialized buffer into a predictable secret",
    );
    openssl::base64::encode_block(&buf)
}
