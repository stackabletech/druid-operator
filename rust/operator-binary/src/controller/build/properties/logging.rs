//! Builds the log4j2 and Vector logging configuration for the rolegroup `ConfigMap`.

use stackable_operator::{
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::{
        self,
        spec::{ContainerLogConfig, ContainerLogConfigChoice, Logging},
    },
    role_utils::RoleGroupRef,
};

use crate::crd::{Container, STACKABLE_LOG_DIR, v1alpha1};

const CONSOLE_CONVERSION_PATTERN: &str = "%d{ISO8601} %p [%t] %c - %m%n";

/// File that the Druid log4j2 config writes its rolling log output to.
const DRUID_LOG_FILE: &str = "druid.log4j2.xml";

/// Maximum size of all Druid log files combined, used both for the log4j2 rollover configuration
/// and to size the log volume in the controller.
pub const MAX_DRUID_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

/// Renders the `log4j2.properties` content for the Druid container.
///
/// Returns `None` when the container uses a custom log ConfigMap rather than the operator's
/// automatic logging configuration.
pub fn build_log4j2_config(logging: &Logging<Container>) -> Option<String> {
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Druid)
    {
        Some(product_logging::framework::create_log4j2_config(
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
        ))
    } else {
        None
    }
}

/// Renders the Vector agent config (`vector.yaml`).
///
/// Returns `None` when the Vector agent is disabled for this role group.
pub fn build_vector_config(
    rolegroup: &RoleGroupRef<v1alpha1::DruidCluster>,
    logging: &Logging<Container>,
) -> Option<String> {
    if !logging.enable_vector_agent {
        return None;
    }

    let vector_log_config = if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Vector)
    {
        Some(log_config)
    } else {
        None
    };

    Some(product_logging::framework::create_vector_config(
        rolegroup,
        vector_log_config,
    ))
}
