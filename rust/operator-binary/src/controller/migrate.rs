//! Migrations from earlier operator versions. Everything in this file is temporary by design.
//!
//! Delete this whole file once no supported upgrade path can still contain the immutable
//! internal Secret (created by operator versions before 2024-06-25), together with its
//! remaining traces in `controller.rs`: the `mod migrate;` declaration, the call in
//! [`reconcile_druid`](crate::controller::reconcile_druid) and the `MigrateInternalSecret`
//! error variant.

use snafu::{ResultExt, Snafu};
use stackable_operator::{client::Client, k8s_openapi::api::core::v1::Secret, kube::ResourceExt};

use crate::{
    controller::validate::ValidatedCluster, internal_secret::build_shared_internal_secret_name,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to get the immutable internal Secret"))]
    GetImmutableInternalSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to delete the immutable internal secret"))]
    DeleteImmutableInternalSecret {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Deletes the immutable shared internal Secret created by operator versions before 2024-06-25.
/// The mutable replacement under the new name is produced by the regular build and apply steps
/// in the same reconcile run, so this function only removes the old Secret.
pub async fn delete_immutable_internal_secret(
    client: &Client,
    cluster: &ValidatedCluster,
) -> Result<()> {
    let secret_name = build_shared_internal_secret_name(cluster);

    let existing_immutable_secret = client
        .get_opt::<Secret>(
            &build_immutable_shared_internal_secret_name(cluster),
            cluster.namespace.as_ref(),
        )
        .await
        .context(GetImmutableInternalSecretSnafu)?;

    match existing_immutable_secret {
        None => {}
        Some(existing_immutable_secret) => {
            // Before 2024-06-25 we did set `spec.immutable` to avoid accidentally changing the contents. Which was
            // great back than, *but* we now need something more flexible. We can not make the Secret mutable,
            // and re-creation with the same name is very error-prone so we create a mutable secret with a new name
            // (see <https://github.com/kubernetes/website/issues/42359#issuecomment-2136192995>).
            // We *could* read in the contents and use them during the re-creation (so we don't change the contents to avoid downtime),
            // but we strive that our operators don't handle Secret contents and it's a one time migration.

            tracing::warn!(
                secret_name,
                "Shared internal secret found, which is immutable. Deleting it, as we can not modify it or re-create it \
                        with the same name; a mutable replacement with a new name is created in the same reconcile run. \
                        This should only happen once and will change the contents of the Secret. This might cause a short \
                        downtime of Druid, as the changed internal secrets need to propagate through all Druid nodes"
            );

            client
                .delete(&existing_immutable_secret)
                .await
                .context(DeleteImmutableInternalSecretSnafu)?;
        }
    }

    Ok(())
}

fn build_immutable_shared_internal_secret_name(cluster: &ValidatedCluster) -> String {
    format!("{}-internal-secret", cluster.name_any())
}
