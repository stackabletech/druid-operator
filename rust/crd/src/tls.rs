use crate::security::DruidTlsSecurity;

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::schemars::{self, JsonSchema};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("The provided TLS configuration is invalid: {reason}"))]
    InvalidTlsConfiguration { reason: String },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTls {
    /// This setting controls client as well as internal tls usage:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the clients
    /// - Which cert the servers should use to authenticate themselves among each other
    // TODO: Separating internal and server TLS is currently not possible. Internal communication
    // happens via the HTTPS port. Even if both HTTPS and HTTP port are enabled, Druid clients
    // will default to using TLS.
    #[serde(default = "tls_default", skip_serializing_if = "Option::is_none")]
    pub server_and_internal_secret_class: Option<String>,
}

/// Default TLS settings. Internal and server communication default to "tls" secret class.
pub fn default_druid_tls() -> Option<DruidTls> {
    Some(DruidTls {
        server_and_internal_secret_class: tls_default(),
    })
}

/// Helper methods to provide defaults in the CRDs and tests
pub fn tls_default() -> Option<String> {
    Some(DruidTlsSecurity::TLS_DEFAULT_SECRET_CLASS.to_string())
}
