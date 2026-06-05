//! Per-file builders for Druid `.properties` files.

pub mod logging;
pub mod runtime_properties;
pub mod security_properties;

/// The names of the operator-written Druid config files assembled into the rolegroup ConfigMap.
#[derive(Clone, Copy, Debug, strum::Display)]
// The shared `Properties` suffix mirrors the actual on-disk file names; it is not redundant naming.
#[allow(clippy::enum_variant_names)]
pub enum ConfigFileName {
    #[strum(serialize = "runtime.properties")]
    RuntimeProperties,
    #[strum(serialize = "security.properties")]
    SecurityProperties,
    /// `log4j2.properties` is rendered by the logging framework rather than a properties builder,
    /// but it is still an operator-written file assembled into the rolegroup ConfigMap.
    #[strum(serialize = "log4j2.properties")]
    Log4j2Properties,
}
