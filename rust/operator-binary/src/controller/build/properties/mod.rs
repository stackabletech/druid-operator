//! Per-file builders for Druid `.properties` files.

// The writer is vendored but not yet consumed; later refactor tasks wire it in.
#[allow(dead_code)]
pub mod writer;

// consumed by config_map builder in a later task
#[allow(dead_code)]
pub mod runtime_properties;
// consumed by config_map builder in a later task
#[allow(dead_code)]
pub mod security_properties;
