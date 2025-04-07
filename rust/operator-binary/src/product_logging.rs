use snafu::Snafu;
use stackable_operator::{
    builder::configmap::ConfigMapBuilder,
    memory::BinaryMultiple,
    product_logging::{
        self,
        spec::{ContainerLogConfig, ContainerLogConfigChoice, Logging},
    },
    role_utils::RoleGroupRef,
};

use crate::crd::{
    v1alpha1, Container, DRUID_LOG_FILE, LOG4J2_CONFIG, MAX_DRUID_LOG_FILES_SIZE, STACKABLE_LOG_DIR,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to retrieve the ConfigMap {cm_name}"))]
    ConfigMapNotFound {
        source: stackable_operator::client::Error,
        cm_name: String,
    },
    #[snafu(display("failed to retrieve the entry {entry} for ConfigMap {cm_name}"))]
    MissingConfigMapEntry {
        entry: &'static str,
        cm_name: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

const CONSOLE_CONVERSION_PATTERN: &str = "%d{ISO8601} %p [%t] %c - %m%n";

/// Extend the role group ConfigMap with logging and Vector configurations
pub fn extend_role_group_config_map(
    rolegroup: &RoleGroupRef<v1alpha1::DruidCluster>,
    logging: &Logging<Container>,
    cm_builder: &mut ConfigMapBuilder,
) -> Result<()> {
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Druid)
    {
        cm_builder.add_data(
            LOG4J2_CONFIG,
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
            ),
        );
    }

    let vector_log_config = if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(&Container::Vector)
    {
        Some(log_config)
    } else {
        None
    };

    if logging.enable_vector_agent {
        cm_builder.add_data(
            product_logging::framework::VECTOR_CONFIG_FILE,
            product_logging::framework::create_vector_config(rolegroup, vector_log_config),
        );
    }

    Ok(())
}
