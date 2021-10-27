pub mod commands;
pub mod error;

use crate::commands::{Restart, Start, Stop};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::schemars::_serde_json::Value;
use kube::api::ApiResource;
use kube::CustomResource;
use kube::CustomResourceExt;
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::command::{CommandRef, HasCommands, HasRoleRestartOrder};
use stackable_operator::controller::HasOwned;
use stackable_operator::crd::HasApplication;
use stackable_operator::identity::PodToNodeMapping;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::Role;
use stackable_operator::status::{
    ClusterExecutionStatus, Conditions, HasClusterExecutionStatus, HasCurrentCommand, Status,
    Versioned,
};
use stackable_operator::versioning::{ProductVersion, Versioning, VersioningState};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use std::str::FromStr;

use tracing::{warn, info, debug, trace};

pub const APP_NAME: &str = "druid";
pub const CONF_DIR: &str = "conf";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

// environment variables
pub const JAVA_HOME: &str = "JAVA_HOME";

// port names
pub const PLAINTEXT: &str = "plaintext";

/////////////////////////////
//    CONFIG PROPERTIES    //
/////////////////////////////
pub const DRUID_SERVICE: &str = "druid.service";
pub const DRUID_PLAINTEXTPORT: &str = "druid.plaintextPort";
pub const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
// extension names
pub const EXT_HDFS_STORAGE: &str = "druid-hdfs-storage";
pub const EXT_KAFKA_INDEXING: &str = "druid-kafka-indexing-service";
pub const EXT_DATASKETCHES: &str = "druid-datasketches";
pub const EXT_PSQL_MD_ST: &str = "postgresql-metadata-storage";
// metadata storage config properties
pub const MD_ST_TYPE: &str = "druid.metadata.storage.type";
pub const MD_ST_CONNECT_URI: &str = "druid.metadata.storage.connector.connectURI";
pub const MD_ST_HOST: &str = "druid.metadata.storage.connector.host";
pub const MD_ST_PORT: &str = "druid.metadata.storage.connector.port";
pub const MD_ST_USER: &str = "druid.metadata.storage.connector.user";
pub const MD_ST_PASSWORD: &str = "druid.metadata.storage.connector.password";

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DruidCluster",
    plural = "druidclusters",
    shortname = "druid",
    namespaced
)]
#[kube(status = "DruidClusterStatus")]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterSpec {
    pub version: DruidVersion,
    pub brokers: Role<DruidConfig>,
    pub coordinators: Role<DruidConfig>,
    pub historicals: Role<DruidConfig>,
    pub middle_managers: Role<DruidConfig>,
    pub routers: Role<DruidConfig>,
    pub metadata_storage_database: DatabaseConnectionSpec,
    // TODO zookeeper reference
}

#[derive(
    Clone, Debug, Deserialize, Display, EnumIter, Eq, Hash, JsonSchema, PartialEq, Serialize, EnumString
)]
pub enum DruidRole {
    #[strum(serialize = "coordinator")]
    Coordinator,
    #[strum(serialize = "broker")]
    Broker,
    #[strum(serialize = "historical")]
    Historical,
    #[strum(serialize = "middleManager")]
    MiddleManager,
    #[strum(serialize = "router")]
    Router,
}

impl DruidRole {
    /// Returns the start commands for the different server types.
    pub fn get_command(
        &self,
        version: &DruidVersion,
    ) -> Vec<String> {
        vec![
            format!("{}/stackable/run-druid", version.package_name()),
            self.to_string(),
            format!("{{{{configroot}}}}/{}", CONF_DIR),
        ]
    }
}

impl Status<DruidClusterStatus> for DruidCluster {
    fn status(&self) -> &Option<DruidClusterStatus> {
        &self.status
    }
    fn status_mut(&mut self) -> &mut Option<DruidClusterStatus> {
        &mut self.status
    }
}

impl HasRoleRestartOrder for DruidCluster {
    fn get_role_restart_order() -> Vec<String> {
        // TODO verify if this order is correct
        vec![
            todo!(),
        ]
    }
}

impl HasCommands for DruidCluster {
    fn get_command_types() -> Vec<ApiResource> {
        vec![
            Start::api_resource(),
            Stop::api_resource(),
            Restart::api_resource(),
        ]
    }
}

impl HasOwned for DruidCluster {
    fn owned_objects() -> Vec<&'static str> {
        vec![Restart::crd_name(), Start::crd_name(), Stop::crd_name()]
    }
}

impl HasApplication for DruidCluster {
    fn get_application_name() -> &'static str {
        APP_NAME
    }
}

impl HasClusterExecutionStatus for DruidCluster {
    fn cluster_execution_status(&self) -> Option<ClusterExecutionStatus> {
        self.status
            .as_ref()
            .and_then(|status| status.cluster_execution_status.clone())
    }

    fn cluster_execution_status_patch(&self, execution_status: &ClusterExecutionStatus) -> Value {
        json!({ "clusterExecutionStatus": execution_status })
    }
}

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[kube(
group = "external.stackable.tech",
version = "v1alpha1",
kind = "DatabaseConnection",
plural = "databaseconnections",
shortname = "dbconn",
namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConnectionSpec {
    pub db_type: DbType,
    pub conn_string: String,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(
Clone,
Debug,
Deserialize,
Eq,
JsonSchema,
PartialEq,
Serialize,
strum_macros::Display,
strum_macros::EnumString,
)]
pub enum DbType {
    #[serde(rename = "derby")]
    #[strum(serialize = "derby")]
    Derby,

    #[serde(rename = "mysql")]
    #[strum(serialize = "mysql")]
    Mysql,

    #[serde(rename = "postgresql")]
    #[strum(serialize = "postgresql")]
    Postgresql,
}

impl Default for DbType {
    fn default() -> Self {
        Self::Derby
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfig {
    // port
    pub plaintext_port: Option<u16>,
    // misc
    pub java_home: Option<String>,  // needs to be java 8!
}

impl Configuration for DruidConfig {
    type Configurable = DruidCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Readd if we want jmx metrics gathered
        //if let Some(metrics_port) = self.metrics_port {
        //    result.insert(METRICS_PORT.to_string(), Some(metrics_port.to_string()));
        // }
        Ok(result)
    }

    fn compute_cli(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        resource: &Self::Configurable,
        role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let role = DruidRole::from_str(role_name).unwrap();

        let mut result = BTreeMap::new();
        match file {
            JVM_CONFIG => {},
            RUNTIME_PROPS => {
                // metadata storage
                let mds = &resource.spec.metadata_storage_database;
                result.insert(MD_ST_TYPE.to_string(), Some(mds.db_type.to_string()));
                result.insert(MD_ST_CONNECT_URI.to_string(), Some(mds.conn_string.to_string()));
                result.insert(MD_ST_HOST.to_string(), Some(mds.host.to_string()));
                result.insert(MD_ST_PORT.to_string(), Some(mds.port.to_string()));
                if let Some(user) = &mds.user {
                    result.insert(MD_ST_USER.to_string(), Some(user.to_string()));
                }
                if let Some(password) = &mds.password {
                    result.insert(MD_ST_PASSWORD.to_string(), Some(password.to_string()));
                }
                // plaintext port
                let plaintext_port = if let Some(port) = self.plaintext_port {
                    port
                } else {
                    match role {
                        DruidRole::Coordinator => 8081,
                        DruidRole::Broker => 8082,
                        DruidRole::Historical => 8083,
                        DruidRole::MiddleManager => 8091,
                        DruidRole::Router => 8888
                    }
                };
                result.insert(DRUID_PLAINTEXTPORT.to_string(), Some(plaintext_port.to_string()));
            },
            LOG4J2_CONFIG => {},
            _ => {},
        }

        Ok(result)
    }
}

#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
)]
pub enum DruidVersion {
    #[serde(rename = "0.22.0")]
    #[strum(serialize = "0.22.0")]
    v0_22_0,
}

impl DruidVersion {
    pub fn package_name(&self) -> String {
        format!("apache-druid-{}", self.to_string())
    }
}

impl Versioning for DruidVersion {
    fn versioning_state(&self, other: &Self) -> VersioningState {
        let from_version = match Version::parse(&self.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    self.to_string(),
                    e.to_string()
                ))
            }
        };

        let to_version = match Version::parse(&other.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    other.to_string(),
                    e.to_string()
                ))
            }
        };

        match to_version.cmp(&from_version) {
            Ordering::Greater => VersioningState::ValidUpgrade,
            Ordering::Less => VersioningState::ValidDowngrade,
            Ordering::Equal => VersioningState::NoOp,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ProductVersion<DruidVersion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<PodToNodeMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_command: Option<CommandRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_execution_status: Option<ClusterExecutionStatus>,
}

impl Versioned<DruidVersion> for DruidClusterStatus {
    fn version(&self) -> &Option<ProductVersion<DruidVersion>> {
        &self.version
    }
    fn version_mut(&mut self) -> &mut Option<ProductVersion<DruidVersion>> {
        &mut self.version
    }
}

impl Conditions for DruidClusterStatus {
    fn conditions(&self) -> &[Condition] {
        self.conditions.as_slice()
    }
    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }
}

impl HasCurrentCommand for DruidClusterStatus {
    fn current_command(&self) -> Option<CommandRef> {
        self.current_command.clone()
    }
    fn set_current_command(&mut self, command: CommandRef) {
        self.current_command = Some(command);
    }
    fn clear_current_command(&mut self) {
        self.current_command = None
    }
    fn tracking_location() -> &'static str {
        "/status/currentCommand"
    }
}

#[cfg(test)]
mod tests {
    use crate::DruidVersion;
    use stackable_operator::versioning::{Versioning, VersioningState};
    use std::str::FromStr;

    #[test]
    fn test_druid_version_versioning() {
        todo!();
    }

    #[test]
    #[test]
    fn test_version_conversion() {
        // TODO: Adapt to correct product version
        // DruidVersion::from_str("3.4.14").unwrap();
    }

    #[test]
    fn test_package_name() {
        assert_eq!(
            DruidVersion::v0_22_0.package_name(),
            format!("apache-druid-{}", DruidVersion::v0_22_0.to_string())
        );
    }
}
