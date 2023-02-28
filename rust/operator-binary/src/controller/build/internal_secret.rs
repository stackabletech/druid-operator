use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::DruidCluster;
use stackable_operator::k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};
use stackable_operator::kube::ResourceExt;
use stackable_operator::{
    builder::ObjectMetaBuilder, client::Client, k8s_openapi::api::core::v1::Secret,
};
use std::collections::BTreeMap;
use strum::{EnumDiscriminants, IntoStaticStr};

pub const ENV_INTERNAL_SECRET: &str = "INTERNAL_SECRET";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to apply internal secret"))]
    ApplyInternalSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
}

pub fn build_shared_internal_secret(druid: &DruidCluster) -> Result<Secret, Error> {
    let mut internal_secret = BTreeMap::new();
    internal_secret.insert(ENV_INTERNAL_SECRET.to_string(), get_random_base64());

    Ok(Secret {
        immutable: Some(true),
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

pub fn build_shared_internal_secret_name(druid: &DruidCluster) -> String {
    format!("{}-internal-secret", druid.name_any())
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
