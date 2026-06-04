//! Per-file builders for Druid `.properties` files.

pub mod writer;

pub mod runtime_properties;
pub mod security_properties;

/// The names of the operator-written Druid config files assembled into the rolegroup ConfigMap.
#[derive(Clone, Copy, Debug, strum::Display)]
pub enum ConfigFileName {
    #[strum(serialize = "runtime.properties")]
    RuntimeProperties,
    #[strum(serialize = "security.properties")]
    SecurityProperties,
}
