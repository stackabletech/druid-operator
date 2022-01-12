use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use stackable_operator::{
    kube::{runtime::reflector::ObjectRef, CustomResource},
    product_config_utils::{ConfigError, Configuration},
    role_utils::{Role, RoleGroupRef},
    schemars::{self, JsonSchema},
};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::str::FromStr;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;

pub const APP_NAME: &str = "druid";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

// port names
pub const CONTAINER_HTTP_PORT: &str = "http";
pub const CONTAINER_METRICS_PORT: &str = "metrics";

/////////////////////////////
//    CONFIG PROPERTIES    //
/////////////////////////////
pub const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
// extension names
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
// S3
pub const DS_BUCKET: &str = "druid.storage.bucket";
pub const DS_BASE_KEY: &str = "druid.storage.baseKey";
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

pub const DRUID_METRICS_PORT: u16 = 9090;

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DruidCluster",
    plural = "druidclusters",
    shortname = "druid",
    status = "DruidClusterStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterSpec {
    /// Emergency stop button, if `true` then all pods are stopped without affecting configuration (as setting `replicas` to `0` would)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<bool>,
    /// Desired Druid version
    pub version: String,
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
    #[strum(serialize = "middlemanager")]
    MiddleManager,
    #[strum(serialize = "router")]
    Router,
}

impl DruidRole {
    /// Returns the name of the internal druid process name associated with the role.
    /// These strings are used by druid internally to identify processes.
    fn get_process_name(&self) -> &str {
        match &self {
            DruidRole::Coordinator => "coordinator",
            DruidRole::Broker => "broker",
            DruidRole::Historical => "historical",
            DruidRole::MiddleManager => "middleManager",
            DruidRole::Router => "router",
        }
    }

    /// Returns the default port for every role, as taken from the sample configs.
    pub fn get_http_port(&self) -> u16 {
        match &self {
            DruidRole::Coordinator => 8081,
            DruidRole::Broker => 8082,
            DruidRole::Historical => 8083,
            DruidRole::MiddleManager => 8091,
            DruidRole::Router => 8888,
        }
    }

    /// Returns the start commands for the different server types.
    pub fn get_command(&self, _version: &str) -> Vec<String> {
        vec![
            "/stackable/druid/bin/run-druid".to_string(),
            self.get_process_name().to_string(),
            "/stackable/conf".to_string(),
        ]
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("object has no namespace associated"))]
pub struct NoNamespaceError;

/// Reference to a single `Pod` that is a component of a [`DruidCluster`]
///
/// Used for service discovery.
#[derive(Debug, PartialEq, Eq)]
pub struct DruidPodRef {
    pub namespace: String,
    pub role_group_service_name: String,
    pub pod_name: String,
}

impl DruidPodRef {
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.{}.svc.cluster.local",
            self.pod_name, self.role_group_service_name, self.namespace
        )
    }
}

impl DruidCluster {
    /// The spec for the given Role
    pub fn get_role(&self, role: &DruidRole) -> &Role<DruidConfig> {
        match role {
            DruidRole::Coordinator => &self.spec.coordinators,
            DruidRole::Broker => &self.spec.brokers,
            DruidRole::MiddleManager => &self.spec.middle_managers,
            DruidRole::Historical => &self.spec.historicals,
            DruidRole::Router => &self.spec.routers,
        }
    }

    /// The name of the role-level load-balanced Kubernetes `Service`
    pub fn role_service_name(&self, role: &DruidRole) -> Option<String> {
        Some(format!(
            "{}-{}",
            self.metadata.name.clone()?,
            role.to_string()
        ))
    }

    /// The fully-qualified domain name of the role-level load-balanced Kubernetes `Service`
    pub fn role_service_fqdn(&self, role: &DruidRole) -> Option<String> {
        Some(format!(
            "{}.{}.svc.cluster.local",
            self.role_service_name(role)?,
            self.metadata.namespace.as_ref()?
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConnectionSpec {
    pub db_type: DbType,
    pub conn_string: String,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZookeeperReference {
    pub config_map_name: String,
    pub namespace: String,
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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Spec {
    pub credentials_secret: String,
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfig {}

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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterStatus {}

/// Takes a vec of strings and returns them as a formatted json
/// list.
fn build_string_list(strings: &[String]) -> String {
    let quoted_strings: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
    let comma_list = quoted_strings.join(", ");
    format!("[{}]", comma_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::role_utils::CommonConfiguration;
    use stackable_operator::role_utils::RoleGroup;
    use std::array::IntoIter;
    use std::collections::HashMap;

    #[test]
    fn test_service_name_generation() {
        let mut cluster = DruidCluster::new(
            "testcluster",
            DruidClusterSpec {
                stopped: None,
                version: "".to_string(),
                brokers: Role {
                    config: CommonConfiguration {
                        config: DruidConfig {},
                        config_overrides: Default::default(),
                        env_overrides: Default::default(),
                        cli_overrides: Default::default(),
                    },
                    role_groups: Default::default(),
                },
                coordinators: Role {
                    config: CommonConfiguration {
                        config: DruidConfig {},
                        config_overrides: Default::default(),
                        env_overrides: Default::default(),
                        cli_overrides: Default::default(),
                    },
                    role_groups: Default::default(),
                },
                historicals: Role {
                    config: CommonConfiguration {
                        config: DruidConfig {},
                        config_overrides: Default::default(),
                        env_overrides: Default::default(),
                        cli_overrides: Default::default(),
                    },
                    role_groups: Default::default(),
                },
                middle_managers: Role {
                    config: CommonConfiguration {
                        config: DruidConfig {},
                        config_overrides: Default::default(),
                        env_overrides: Default::default(),
                        cli_overrides: Default::default(),
                    },
                    role_groups: Default::default(),
                },
                routers: Role {
                    config: CommonConfiguration {
                        config: DruidConfig {},
                        config_overrides: Default::default(),
                        env_overrides: Default::default(),
                        cli_overrides: Default::default(),
                    },
                    role_groups: HashMap::<_, _>::from_iter(IntoIter::new([(
                        "default".to_string(),
                        RoleGroup {
                            config: CommonConfiguration {
                                config: DruidConfig {},
                                config_overrides: Default::default(),
                                env_overrides: Default::default(),
                                cli_overrides: Default::default(),
                            },
                            replicas: Some(1),
                            selector: None,
                        },
                    )])),
                },
                metadata_storage_database: Default::default(),
                deep_storage: Default::default(),
                s3: None,
                zookeeper_reference: Default::default(),
            },
        );

        cluster.metadata.namespace = Some("default".to_string());

        assert_eq!(cluster.metadata.name, Some("testcluster".to_string()));

        assert_eq!(
            cluster.role_service_name(&DruidRole::Router),
            Some("testcluster-router".to_string())
        );
    }
}
