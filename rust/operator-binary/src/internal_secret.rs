use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::security::INTERNAL_INITIAL_CLIENT_PASSWORD_ENV;
use stackable_druid_crd::DruidCluster;
use stackable_operator::k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};
use stackable_operator::kube::ResourceExt;
use stackable_operator::{
    builder::meta::ObjectMetaBuilder, client::Client, k8s_openapi::api::core::v1::Secret,
};
use std::collections::{BTreeMap, HashSet};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
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

    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },
}

pub async fn create_shared_internal_secret(
    druid: &DruidCluster,
    client: &Client,
    controller_name: &str,
) -> Result<(), Error> {
    let secret = build_shared_internal_secret(druid)?;
    let existing_secret = client
        .get_opt::<Secret>(
            &secret.name_any(),
            secret
                .namespace()
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
        )
        .await
        .context(FailedToRetrieveInternalSecretSnafu)?;
    let existing_immutable_secret = client
        .get_opt::<Secret>(
            &build_immutable_shared_internal_secret_name(druid),
            secret
                .namespace()
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
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
            for required in secret
                .string_data
                .as_ref()
                .expect("Secret data must be set by the `build_shared_internal_secret` function")
                .keys()
            {
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

pub fn build_shared_internal_secret(druid: &DruidCluster) -> Result<Secret, Error> {
    let mut internal_secret = BTreeMap::new();
    internal_secret.insert(
        INTERNAL_INITIAL_CLIENT_PASSWORD_ENV.to_string(),
        get_random_base64(),
    );

    Ok(Secret {
        metadata: ObjectMetaBuilder::new()
            .name(build_shared_internal_secret_name(druid))
            .namespace_opt(druid.namespace())
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        string_data: Some(internal_secret),
        ..Secret::default()
    })
}

pub fn build_immutable_shared_internal_secret_name(druid: &DruidCluster) -> String {
    format!("{}-internal-secret", druid.name_any())
}

pub fn build_shared_internal_secret_name(druid: &DruidCluster) -> String {
    format!("{}-shared-internal-secret", druid.name_any())
}

fn get_random_base64() -> String {
    let mut buf = [0; 512];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    openssl::base64::encode_block(&buf)
}

/// Give a secret name and an optional key in the secret to use.
/// The value from the key will be set into the given env var name.
/// If not secret key is given, the env var name will be used as the secret key.
pub fn env_var_from_secret(secret_name: &str, secret_key: Option<&str>, env_var: &str) -> EnvVar {
    EnvVar {
        name: env_var.to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                optional: Some(false),
                name: Some(secret_name.to_string()),
                key: secret_key.unwrap_or(env_var).to_string(),
            }),
            ..EnvVarSource::default()
        }),
        ..EnvVar::default()
    }
}
