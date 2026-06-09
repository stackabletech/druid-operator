//! Per-file builders for Druid `.properties` files.

pub mod logging;
pub mod runtime_properties;
pub mod security_properties;

/// The names of the operator-written Druid config files assembled into the rolegroup ConfigMap.
#[derive(Clone, Copy, Debug, strum::Display)]
pub enum ConfigFileName {
    #[strum(serialize = "runtime.properties")]
    RuntimeProperties,
    #[strum(serialize = "security.properties")]
    SecurityProperties,
    /// `log4j2.properties` is rendered by the logging framework rather than a properties builder,
    /// but it is still an operator-written file assembled into the rolegroup ConfigMap.
    #[strum(serialize = "log4j2.properties")]
    Log4j2Properties,
    /// `jvm.config` is rendered from JVM argument overrides by [`super::jvm`] rather than a
    /// properties builder, but it is still an operator-written file assembled into the rolegroup
    /// ConfigMap.
    #[strum(serialize = "jvm.config")]
    JvmConfig,
}
