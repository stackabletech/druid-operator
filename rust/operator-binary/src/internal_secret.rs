//! Pure helper around the shared internal Secret: its name. The Secret itself is produced by
//! `build_internal_secret` in the build step on every reconcile run and applied in the apply
//! step.

use std::str::FromStr;

use stackable_operator::v2::types::{kubernetes::SecretName, operator::ClusterName};

pub fn build_shared_internal_secret_name(cluster_name: &ClusterName) -> SecretName {
    const SUFFIX: &str = "-shared-internal-secret";
    const _: () = assert!(
        ClusterName::MAX_LENGTH + SUFFIX.len() <= SecretName::MAX_LENGTH,
        "The string `<cluster_name>-shared-internal-secret` must not exceed the limit of Secret \
        names."
    );
    // A ClusterName is an RFC 1035 label, so appending an alphanumeric-terminated suffix keeps it a
    // valid RFC 1123 subdomain.
    let _ = ClusterName::IS_RFC_1123_SUBDOMAIN_NAME;

    SecretName::from_str(&format!("{cluster_name}{SUFFIX}"))
        .expect("the shared internal secret name is a valid Secret name")
}
