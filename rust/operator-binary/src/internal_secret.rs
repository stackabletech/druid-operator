//! Pure helpers around the shared internal Secret: its name and the env vars that reference
//! it. The Secret itself is produced by `build_shared_internal_secret` in the build step (only
//! when it is absent or incomplete) and applied in the apply step.

use stackable_operator::{
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector},
    kube::ResourceExt,
};

pub fn build_shared_internal_secret_name<T: ResourceExt>(owner: &T) -> String {
    format!("{}-shared-internal-secret", owner.name_any())
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
                name: secret_name.to_string(),
                key: secret_key.unwrap_or(env_var).to_string(),
            }),
            ..EnvVarSource::default()
        }),
        ..EnvVar::default()
    }
}
