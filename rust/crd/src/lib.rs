use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::commons::s3::{InlinedS3BucketSpec, S3BucketDef, S3ConnectionSpec};
use stackable_operator::kube::ResourceExt;
use stackable_operator::{
    commons::{opa::OpaConfig, s3::S3ConnectionDef},
    kube::CustomResource,
    product_config_utils::{ConfigError, Configuration},
    role_utils::Role,
    schemars::{self, JsonSchema},
};
use std::collections::BTreeMap;
use std::str::FromStr;
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};

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
// plaintext port / HTTP
pub const PLAINTEXT: &str = "druid.plaintext";
pub const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
// extension names
pub const EXT_S3: &str = "druid-s3-extensions";
pub const EXT_KAFKA_INDEXING: &str = "druid-kafka-indexing-service";
pub const EXT_DATASKETCHES: &str = "druid-datasketches";
pub const PROMETHEUS_EMITTER: &str = "prometheus-emitter";
pub const EXT_PSQL_MD_ST: &str = "postgresql-metadata-storage";
pub const EXT_MYSQL_MD_ST: &str = "mysql-metadata-storage";
pub const EXT_OPA_AUTHORIZER: &str = "druid-opa-authorizer";
pub const EXT_BASIC_SECURITY: &str = "druid-basic-security";
pub const EXT_HDFS: &str = "druid-hdfs-storage";
// zookeeper
pub const ZOOKEEPER_CONNECTION_STRING: &str = "druid.zk.service.host";
// deep storage
pub const DS_TYPE: &str = "druid.storage.type";
pub const DS_DIRECTORY: &str = "druid.storage.storageDirectory";
// S3
pub const DS_BUCKET: &str = "druid.storage.bucket";
pub const DS_BASE_KEY: &str = "druid.storage.baseKey";
pub const S3_ENDPOINT_URL: &str = "druid.s3.endpoint.url";
// OPA
pub const AUTH_AUTHORIZERS: &str = "druid.auth.authorizers";
pub const AUTH_AUTHORIZERS_VALUE: &str = "[\"OpaAuthorizer\"]";
pub const AUTH_AUTHORIZER_OPA_TYPE: &str = "druid.auth.authorizer.OpaAuthorizer.type";
pub const AUTH_AUTHORIZER_OPA_TYPE_VALUE: &str = "opa";
pub const AUTH_AUTHORIZER_OPA_URI: &str = "druid.auth.authorizer.OpaAuthorizer.opaUri";
// metadata storage config properties
pub const MD_ST_TYPE: &str = "druid.metadata.storage.type";
pub const MD_ST_CONNECT_URI: &str = "druid.metadata.storage.connector.connectURI";
pub const MD_ST_HOST: &str = "druid.metadata.storage.connector.host";
pub const MD_ST_PORT: &str = "druid.metadata.storage.connector.port";
pub const MD_ST_USER: &str = "druid.metadata.storage.connector.user";
pub const MD_ST_PASSWORD: &str = "druid.metadata.storage.connector.password";
// extra
pub const CREDENTIALS_SECRET_PROPERTY: &str = "credentialsSecret";

pub const PROMETHEUS_PORT: &str = "druid.emitter.prometheus.port";
pub const DRUID_METRICS_PORT: u16 = 9090;

// container locations
pub const S3_SECRET_DIR_NAME: &str = "/stackable/secrets";
const ENV_S3_ACCESS_KEY: &str = "AWS_ACCESS_KEY_ID";
const ENV_S3_SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const SECRET_KEY_S3_ACCESS_KEY: &str = "accessKey";
const SECRET_KEY_S3_SECRET_KEY: &str = "secretKey";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve S3 connection"))]
    ResolveS3Connection {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to resolve S3 bucket"))]
    ResolveS3Bucket {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("2 differing s3 connections were given, this is unsupported by Druid"))]
    IncompatibleS3Connections,
}

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
    pub ingestion: Option<IngestionSpec>,
    pub zookeeper_config_map_name: String,
    pub opa: Option<OpaConfig>,
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
    pub fn get_command(&self, mount_s3_credentials: bool) -> Vec<String> {
        let mut shell_cmd = vec![];
        if mount_s3_credentials {
            shell_cmd.push(format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_ACCESS_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_ACCESS_KEY
            ));
            shell_cmd.push(format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_SECRET_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_SECRET_KEY
            ));
        }
        shell_cmd.push(format!(
            "{} {} {}",
            "/stackable/druid/bin/run-druid".to_string(),
            self.get_process_name().to_string(),
            "/stackable/conf".to_string(),
        ));
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            shell_cmd.join(" && "),
        ]
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
        Some(format!("{}-{}", self.metadata.name.clone()?, role))
    }

    /// The fully-qualified domain name of the role-level load-balanced Kubernetes `Service`
    pub fn role_service_fqdn(&self, role: &DruidRole) -> Option<String> {
        Some(format!(
            "{}.{}.svc.cluster.local",
            self.role_service_name(role)?,
            self.metadata.namespace.as_ref()?
        ))
    }

    /// If an s3 connection for ingestion is given, as well as an s3 connection for deep storage, they need to be the same.
    /// This function returns the resolved connection, or raises an Error if the connections are not identical.
    pub async fn get_s3_connection(
        &self,
        client: &Client,
    ) -> Result<Option<S3ConnectionSpec>, Error> {
        // get connection for ingestion

        let ingestion_conn = if let Some(ic) = self
            .spec
            .ingestion
            .as_ref()
            .and_then(|is| is.s3connection.as_ref())
        {
            Some(
                ic.resolve(client, self.namespace().as_deref())
                    .await
                    .context(ResolveS3ConnectionSnafu)?,
            )
        } else {
            None
        };

        let storage_conn = match &self.spec.deep_storage {
            DeepStorageSpec::S3(s3_spec) => {
                let inlined_bucket: InlinedS3BucketSpec = s3_spec
                    .bucket
                    .resolve(client, self.namespace().as_deref())
                    .await
                    .context(ResolveS3BucketSnafu)?;
                inlined_bucket.connection
            }
            _ => None,
        };

        if ingestion_conn.is_some() && storage_conn.is_some() {
            if ingestion_conn == storage_conn {
                Ok(ingestion_conn)
            } else {
                Err(Error::IncompatibleS3Connections)
            }
        } else if ingestion_conn.is_some() {
            Ok(ingestion_conn)
        } else if storage_conn.is_some() {
            Ok(storage_conn)
        } else {
            Ok(None)
        }
    }

    /// Returns true if the cluster uses an s3 connection.
    /// This is a quicker convenience function over the [DruidCluster::get_s3_connection] function.
    pub fn uses_s3(&self) -> bool {
        let s3_ingestion = self
            .spec
            .ingestion
            .as_ref()
            .and_then(|spec| spec.s3connection.as_ref())
            .is_some();
        let s3_storage = self.spec.deep_storage.is_s3();
        s3_ingestion || s3_storage
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize, Display, EnumString)]
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

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Display)]
#[serde(rename_all = "camelCase")]
pub enum DeepStorageSpec {
    #[serde(rename = "hdfs")]
    #[strum(serialize = "hdfs")]
    HDFS(HdfsDeepStorageSpec),
    #[strum(serialize = "s3")]
    S3(S3DeepStorageSpec),
}

impl DeepStorageSpec {
    pub fn is_hdfs(&self) -> bool {
        matches!(self, DeepStorageSpec::HDFS(_))
    }

    pub fn is_s3(&self) -> bool {
        matches!(self, DeepStorageSpec::S3(_))
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsDeepStorageSpec {
    pub storage_directory: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3DeepStorageSpec {
    pub bucket: S3BucketDef,
    pub base_key: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestionSpec {
    pub s3connection: Option<S3ConnectionDef>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfig {}

impl Configuration for DruidConfig {
    type Configurable = DruidCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut _result = BTreeMap::new();
        Ok(_result)
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
            JVM_CONFIG => {}
            RUNTIME_PROPS => {
                // Plaintext port
                result.insert(
                    PLAINTEXT.to_string(),
                    Some(role.get_http_port().to_string()),
                );
                // extensions
                let mut extensions = vec![
                    String::from(EXT_KAFKA_INDEXING),
                    String::from(EXT_DATASKETCHES),
                    String::from(PROMETHEUS_EMITTER),
                    String::from(EXT_BASIC_SECURITY),
                    String::from(EXT_OPA_AUTHORIZER),
                    String::from(EXT_HDFS),
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
                if resource.uses_s3() {
                    extensions.push(EXT_S3.to_string());
                }
                // OPA
                if let Some(_opa) = &resource.spec.opa {
                    result.insert(
                        AUTH_AUTHORIZERS.to_string(),
                        Some(AUTH_AUTHORIZERS_VALUE.to_string()),
                    );
                    result.insert(
                        AUTH_AUTHORIZER_OPA_TYPE.to_string(),
                        Some(AUTH_AUTHORIZER_OPA_TYPE_VALUE.to_string()),
                    );
                    // The opaUri still needs to be set, but that requires a discovery config map and is handled in the druid_controller.rs
                }
                // deep storage
                result.insert(
                    DS_TYPE.to_string(),
                    Some(resource.spec.deep_storage.to_string()),
                );
                match &resource.spec.deep_storage {
                    DeepStorageSpec::HDFS(hdfs_spec) => {
                        result.insert(
                            DS_DIRECTORY.to_string(),
                            Some(hdfs_spec.storage_directory.clone()),
                        );
                    }
                    DeepStorageSpec::S3(s3_spec) => {
                        if let Some(key) = &s3_spec.base_key {
                            result.insert(DS_BASE_KEY.to_string(), Some(key.to_string()));
                        }
                        // bucket information (name, connection) needs to be resolved first,
                        // that is done directly in the controller
                    }
                }
                // other
                result.insert(
                    EXTENSIONS_LOADLIST.to_string(),
                    Some(build_string_list(&extensions)),
                );
                // metrics
                result.insert(
                    PROMETHEUS_PORT.to_string(),
                    Some(DRUID_METRICS_PORT.to_string()),
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
    use crate::DeepStorageSpec::HDFS;
    use stackable_operator::role_utils::CommonConfiguration;
    use stackable_operator::role_utils::RoleGroup;
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
                    role_groups: [(
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
                    )]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
                },
                metadata_storage_database: Default::default(),
                deep_storage: HDFS(HdfsDeepStorageSpec {
                    storage_directory: "/path/to/dir".to_string(),
                }),
                ingestion: Default::default(),
                zookeeper_config_map_name: Default::default(),
                opa: Default::default(),
            },
        );

        cluster.metadata.namespace = Some("default".to_string());

        assert_eq!(cluster.metadata.name, Some("testcluster".to_string()));

        assert_eq!(
            cluster.role_service_name(&DruidRole::Router),
            Some("testcluster-router".to_string())
        );

        assert_eq!(
            cluster.role_service_fqdn(&DruidRole::Router),
            Some("testcluster-router.default.svc.cluster.local".to_string())
        )
    }
}
