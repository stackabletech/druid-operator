//! Pure helper around the shared internal Secret: its name. The Secret itself is produced by
//! `build_internal_secret` in the build step on every reconcile run and applied in the apply
//! step.

use std::str::FromStr;

use stackable_operator::v2::types::{kubernetes::SecretName, operator::ClusterName};

pub fn build_shared_internal_secret_name(cluster_name: &ClusterName) -> SecretName {
    SecretName::from_str(&format!("{cluster_name}-shared-internal-secret")).expect(
        "the shared internal secret name is a valid Secret name, because a ClusterName is at \
         most 40 characters long, so the suffixed name stays within the length limit",
    )
}
