//! The validated Druid authentication decision.
//!
//! [`DruidAuthenticationConfig`] is the validated representation of the cluster's authentication
//! settings, produced by [`DruidAuthenticationConfig::from_auth_classes`] during the validate step.
//! The Kubernetes/config rendering derived from it (runtime.properties, container commands, volumes,
//! env vars) lives in the build step (`controller::build::authentication`).

use stackable_operator::crd::authentication;

use crate::crd::authentication::{AuthenticationClassResolved, AuthenticationClassesResolved};

/// Type alias for Druid's OIDC client authentication options, opting in to the
/// `clientAuthenticationMethod` field via [`oidc::v1alpha1::ClientAuthenticationMethodOption`].
pub type DruidClientAuthenticationOptions =
    authentication::oidc::v1alpha1::ClientAuthenticationOptions<
        authentication::oidc::v1alpha1::ClientAuthenticationMethodOption,
    >;

#[derive(Clone, Debug)]
pub enum DruidAuthenticationConfig {
    Tls {},
    Ldap {
        provider: authentication::ldap::v1alpha1::AuthenticationProvider,
    },
    Oidc {
        provider: authentication::oidc::v1alpha1::AuthenticationProvider,
        oidc: DruidClientAuthenticationOptions,
    },
}

impl DruidAuthenticationConfig {
    /// Maps the resolved `AuthenticationClass` references to the Druid authentication decision.
    ///
    /// Returns `None` when no authentication class is configured. Currently only one auth mechanism
    /// is supported in Druid (checked when resolving the authentication classes), so only the first
    /// entry is considered. This is a total mapping today; if future multi-mechanism validation is
    /// added here, this should become fallible again.
    pub fn from_auth_classes(auth_classes_resolved: AuthenticationClassesResolved) -> Option<Self> {
        match auth_classes_resolved.auth_classes.first() {
            None => None,
            Some(auth_class_resolved) => match auth_class_resolved {
                AuthenticationClassResolved::Tls { .. } => Some(Self::Tls {}),
                AuthenticationClassResolved::Ldap { provider, .. } => Some(Self::Ldap {
                    provider: provider.clone(),
                }),
                AuthenticationClassResolved::Oidc { provider, oidc, .. } => Some(Self::Oidc {
                    provider: provider.clone(),
                    oidc: oidc.clone(),
                }),
            },
        }
    }
}
