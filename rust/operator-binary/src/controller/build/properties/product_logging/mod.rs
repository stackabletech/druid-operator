//! Renders the logging config files (`log4j2.properties` and the Vector agent config) assembled
//! into the rolegroup `ConfigMap`.

use stackable_operator::{
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::{self, spec::AutomaticContainerLogConfig},
    v2::product_logging::framework::{STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice},
};

use crate::crd::Container;

/// Maximum size of all Druid log files combined, used both for the log4j2 rollover configuration
/// and to size the log volume in the controller.
pub const MAX_DRUID_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

const CONSOLE_CONVERSION_PATTERN: &str = "%d{ISO8601} %p [%t] %c - %m%n";

/// File that the Druid log4j2 config writes its rolling log output to.
const DRUID_LOG_FILE: &str = "druid.log4j2.xml";

/// The Vector agent configuration (`vector.yaml`).
const VECTOR_CONFIG: &str = include_str!("vector.yaml");

/// Returns the Vector agent config (`vector.yaml`) content, added to the rolegroup `ConfigMap`
/// only when the Vector agent is enabled.
pub fn vector_config_file_content() -> String {
    VECTOR_CONFIG.to_owned()
}

/// Renders the `log4j2.properties` content for the Druid container.
///
/// Returns `None` when the container uses a custom log ConfigMap rather than the operator's
/// automatic logging configuration (in which case no `log4j2.properties` is added).
pub fn build_log4j2(druid_container: &ValidatedContainerLogConfigChoice) -> Option<String> {
    match druid_container {
        ValidatedContainerLogConfigChoice::Automatic(log_config) => Some(log4j2_config(log_config)),
        ValidatedContainerLogConfigChoice::Custom(_) => None,
    }
}

fn log4j2_config(log_config: &AutomaticContainerLogConfig) -> String {
    product_logging::framework::create_log4j2_config(
        &format!(
            "{STACKABLE_LOG_DIR}/{container}",
            container = Container::Druid
        ),
        DRUID_LOG_FILE,
        MAX_DRUID_LOG_FILES_SIZE
            .scale_to(BinaryMultiple::Mebi)
            .floor()
            .value as u32,
        CONSOLE_CONVERSION_PATTERN,
        log_config,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_config_file_content_is_non_empty_and_keeps_log4j2_source() {
        let content = vector_config_file_content();
        assert!(!content.is_empty());
        assert!(content.contains("files_log4j2"));
    }
}
