pub mod commands;
pub mod error;

use crate::commands::{Restart, Start, Stop};

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::command::{CommandRef, HasCommands, HasRoleRestartOrder};
use stackable_operator::controller::HasOwned;
use stackable_operator::crd::HasApplication;
use stackable_operator::identity::PodToNodeMapping;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use stackable_operator::k8s_openapi::schemars::_serde_json::Value;
use stackable_operator::kube::api::ApiResource;
use stackable_operator::kube::CustomResource;
use stackable_operator::kube::CustomResourceExt;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::Role;
use stackable_operator::schemars::{self, JsonSchema};
use stackable_operator::status::{
    ClusterExecutionStatus, Conditions, HasClusterExecutionStatus, HasCurrentCommand, Status,
    Versioned,
};
use stackable_operator::versioning::{ProductVersion, Versioning, VersioningState};
use stackable_zookeeper_crd::discovery::ZookeeperReference;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::str::FromStr;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;

pub const APP_NAME: &str = "druid";
pub const CONF_DIR: &str = "conf";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

// port names
pub const CONTAINER_PLAINTEXT_PORT: &str = "plaintext";
pub const CONTAINER_METRICS_PORT: &str = "metrics";

/////////////////////////////
//    CONFIG PROPERTIES    //
/////////////////////////////
pub const DRUID_SERVICE: &str = "druid.service";
pub const DRUID_PLAINTEXTPORT: &str = "druid.plaintextPort";
pub const DRUID_METRICS_PORT: &str = "druid.emitter.prometheus.port";
pub const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
// extension names
pub const EXT_HDFS_STORAGE: &str = "druid-hdfs-storage";
pub const EXT_S3: &str = "druid-s3-extensions";
pub const EXT_KAFKA_INDEXING: &str = "druid-kafka-indexing-service";
pub const EXT_DATASKETCHES: &str = "druid-datasketches";
pub const PROMETHEUS_EMITTER: &str = "prometheus-emitter";
pub const EXT_PSQL_MD_ST: &str = "postgresql-metadata-storage";
pub const EXT_MYSQL_MD_ST: &str = "mysql-metadata-storage";
// zookeeper
pub const ZOOKEEPER_CONNECTION_STRING: &str = "druid.zk.service.host";
// deep storage
pub const DS_TYPE: &str = "druid.storage.type";
pub const DS_DIRECTORY: &str = "druid.storage.storageDirectory";
// S3
pub const DS_BUCKET: &str = "druid.storage.bucket";
pub const DS_BASE_KEY: &str = "druid.storage.baseKey";
pub const S3_ACCESS_KEY: &str = "druid.s3.accessKey";
pub const S3_SECRET_KEY: &str = "druid.s3.secretKey";
pub const S3_ENDPOINT_URL: &str = "druid.s3.endpoint.url";
// metadata storage config properties
pub const MD_ST_TYPE: &str = "druid.metadata.storage.type";
pub const MD_ST_CONNECT_URI: &str = "druid.metadata.storage.connector.connectURI";
pub const MD_ST_HOST: &str = "druid.metadata.storage.connector.host";
pub const MD_ST_PORT: &str = "druid.metadata.storage.connector.port";
pub const MD_ST_USER: &str = "druid.metadata.storage.connector.user";
pub const MD_ST_PASSWORD: &str = "druid.metadata.storage.connector.password";
// extra
pub const CREDENTIALS_SECRET_PROPERTY: &str = "credentialsSecret";

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DruidCluster",
    plural = "druidclusters",
    shortname = "druid",
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars",
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
    pub deep_storage: DeepStorageSpec,
    pub s3: Option<S3Spec>,
    pub zookeeper_reference: ZookeeperReference,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    EnumIter,
    Eq,
    Hash,
    JsonSchema,
    PartialEq,
    Serialize,
    EnumString,
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
    pub fn get_command(&self, _version: &DruidVersion) -> Vec<String> {
        vec![
            "/stackable/druid/bin/run-druid".to_string(),
            self.to_string(),
            "/stackable/conf".to_string(),
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
        // the order below is the reverse startup order taken from the sample configurations
        vec![
            DruidRole::MiddleManager.to_string(),
            DruidRole::Historical.to_string(),
            DruidRole::Router.to_string(),
            DruidRole::Broker.to_string(),
            DruidRole::Coordinator.to_string(),
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
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DatabaseConnection",
    plural = "databaseconnections",
    shortname = "dbconn",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
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
pub enum DeepStorageType {
    #[serde(rename = "local")]
    #[strum(serialize = "local")]
    Local,

    #[serde(rename = "s3")]
    #[strum(serialize = "s3")]
    S3,
}

impl Default for DeepStorageType {
    fn default() -> Self {
        Self::Local
    }
}

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DeepStorage",
    plural = "deepstorages",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
)]
#[serde(rename_all = "camelCase")]
pub struct DeepStorageSpec {
    pub storage_type: DeepStorageType,
    // local only
    pub data_node_selector: Option<BTreeMap<String, String>>,
    pub storage_directory: Option<String>,
    // S3 only
    pub bucket: Option<String>,
    pub base_key: Option<String>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "S3",
    plural = "S3s",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
)]
#[serde(rename_all = "camelCase")]
pub struct S3Spec {
    pub credentials_secret: String,
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfig {
    // port
    pub plaintext_port: u16,
    pub metrics_port: u16,
}

impl Configuration for DruidConfig {
    type Configurable = DruidCluster;

    fn compute_env(
        &self,
        resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();
        // s3
        if let Some(s3) = &resource.spec.s3 {
            result.insert(
                CREDENTIALS_SECRET_PROPERTY.to_string(),
                Some(s3.credentials_secret.clone()),
            );
        }
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
        let _role = DruidRole::from_str(role_name).unwrap();

        let mut result = BTreeMap::new();
        match file {
            JVM_CONFIG => {}
            RUNTIME_PROPS => {
                // extensions
                let mut extensions = vec![
                    String::from(EXT_KAFKA_INDEXING),
                    String::from(EXT_DATASKETCHES),
                    String::from(PROMETHEUS_EMITTER),
                    String::from(EXT_S3),
                ];
                // metadata storage
                let mds = &resource.spec.metadata_storage_database;
                match mds.db_type {
                    DbType::Derby => {} // no additional extensions required
                    DbType::Postgresql => extensions.push(EXT_PSQL_MD_ST.to_string()),
                    DbType::Mysql => extensions.push(EXT_MYSQL_MD_ST.to_string()),
                }
                result.insert(MD_ST_TYPE.to_string(), Some(mds.db_type.to_string()));
                result.insert(
                    MD_ST_CONNECT_URI.to_string(),
                    Some(mds.conn_string.to_string()),
                );
                result.insert(MD_ST_HOST.to_string(), Some(mds.host.to_string()));
                result.insert(MD_ST_PORT.to_string(), Some(mds.port.to_string()));
                if let Some(user) = &mds.user {
                    result.insert(MD_ST_USER.to_string(), Some(user.to_string()));
                }
                if let Some(password) = &mds.password {
                    result.insert(MD_ST_PASSWORD.to_string(), Some(password.to_string()));
                }
                // s3
                if let Some(s3) = &resource.spec.s3 {
                    if let Some(endpoint) = &s3.endpoint {
                        result.insert(S3_ENDPOINT_URL.to_string(), Some(endpoint.to_string()));
                    }
                }
                // deep storage
                let ds = &resource.spec.deep_storage;
                result.insert(DS_TYPE.to_string(), Some(ds.storage_type.to_string()));
                if let Some(bucket) = &ds.bucket {
                    result.insert(DS_BUCKET.to_string(), Some(bucket.to_string()));
                }
                if let Some(key) = &ds.base_key {
                    result.insert(DS_BASE_KEY.to_string(), Some(key.to_string()));
                }
                // other
                result.insert(
                    DRUID_PLAINTEXTPORT.to_string(),
                    Some(self.plaintext_port.to_string()),
                );
                result.insert(
                    DRUID_METRICS_PORT.to_string(),
                    Some(self.metrics_port.to_string()),
                );
                result.insert(
                    EXTENSIONS_LOADLIST.to_string(),
                    Some(build_string_list(&extensions)),
                );
            }
            LOG4J2_CONFIG => {}
            _ => {}
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

impl Versioning for DruidVersion {
    fn versioning_state(&self, other: &Self) -> VersioningState {
        let from_version = match Version::parse(&self.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    self.to_string(),
                    e.to_string()
                ));
            }
        };

        let to_version = match Version::parse(&other.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    other.to_string(),
                    e.to_string()
                ));
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

/// Takes a vec of strings and returns them as a formatted json
/// list.
fn build_string_list(strings: &[String]) -> String {
    let quoted_strings: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
    let comma_list = quoted_strings.join(", ");
    format!("[{}]", comma_list)
}
