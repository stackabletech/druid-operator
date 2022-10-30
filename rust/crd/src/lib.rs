pub mod resource;
pub mod storage;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

use stackable_operator::product_config::types::PropertyNameKind;
use stackable_operator::role_utils::RoleGroupRef;
use stackable_operator::{
    client::Client,
    commons::{
        opa::OpaConfig,
        resources::{NoRuntimeLimits, Resources},
        s3::{InlinedS3BucketSpec, S3BucketDef, S3ConnectionDef, S3ConnectionSpec},
        tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
    },
    kube::{CustomResource, ResourceExt},
    product_config_utils::{ConfigError, Configuration},
    role_utils::Role,
    schemars::{self, JsonSchema},
};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};

pub const APP_NAME: &str = "druid";
pub const CONTROLLER_NAME: &str = "druid-operator";

// config directories
pub const DRUID_CONFIG_DIRECTORY: &str = "/stackable/config";
pub const HDFS_CONFIG_DIRECTORY: &str = "/stackable/hdfs";
pub const RW_CONFIG_DIRECTORY: &str = "/stackable/rwconfig";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

pub const SYSTEM_TRUST_STORE: &str = "/etc/pki/java/cacerts";
pub const SYSTEM_TRUST_STORE_PASSWORD: &str = "changeit";
pub const STACKABLE_TRUST_STORE: &str = "/stackable/truststore.p12";
pub const STACKABLE_TRUST_STORE_PASSWORD: &str = "changeit";
pub const CERTS_DIR: &str = "/stackable/certificates/";

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
pub const S3_PATH_STYLE_ACCESS: &str = "druid.s3.enablePathStyleAccess";
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
// indexer properties
pub const INDEXER_JAVA_OPTS: &str = "druid.indexer.runner.javaOptsArray";
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
// segment storage
pub const SC_LOCATIONS: &str = "druid.segmentCache.locations";
pub const SC_DIRECTORY: &str = "/stackable/var/druid/segment-cache";

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
    #[snafu(display("Unknown Druid role found {role}. Should be one of {roles:?}"))]
    UnknownDruidRole { role: String, roles: Vec<String> },
    #[snafu(display("failed to merge resource definitions"))]
    ResourceMerge { source: resource::Error },
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
    pub brokers: Role<BrokerConfig>,
    pub coordinators: Role<CoordinatorConfig>,
    pub historicals: Role<HistoricalConfig>,
    pub middle_managers: Role<MiddleManagerConfig>,
    pub routers: Role<RouterConfig>,
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
    pub fn get_command(&self, s3_connection: Option<&S3ConnectionSpec>) -> Vec<String> {
        let mut shell_cmd = vec![format!("keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {STACKABLE_TRUST_STORE} -deststoretype pkcs12 -deststorepass {STACKABLE_TRUST_STORE_PASSWORD} -noprompt")];

        if let Some(s3_connection) = s3_connection {
            if let Some(Tls {
                verification:
                    TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::SecretClass(secret_class),
                    }),
            }) = &s3_connection.tls
            {
                shell_cmd.push(format!("keytool -importcert -file /stackable/certificates/{secret_class}-tls-certificate/ca.crt -alias stackable-{secret_class} -keystore {STACKABLE_TRUST_STORE} -storepass {STACKABLE_TRUST_STORE_PASSWORD} -noprompt"));
            }

            if s3_connection.credentials.is_some() {
                shell_cmd.push(format!("export {ENV_S3_ACCESS_KEY}=$(cat {S3_SECRET_DIR_NAME}/{SECRET_KEY_S3_ACCESS_KEY})"));
                shell_cmd.push(format!("export {ENV_S3_SECRET_KEY}=$(cat {S3_SECRET_DIR_NAME}/{SECRET_KEY_S3_SECRET_KEY})"));
            }
        }

        // copy druid config to rw config
        shell_cmd.push(format!(
            "cp -RL {conf}/* {rw_conf}",
            conf = DRUID_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY
        ));

        // copy hdfs config to RW_CONFIG_DIRECTORY folder (if available)
        shell_cmd.push(format!(
            "cp -RL {hdfs_conf}/* {rw_conf} || :",
            hdfs_conf = HDFS_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY,
        ));

        shell_cmd.push(format!(
            "{} {} {}",
            "/stackable/druid/bin/run-druid",
            self.get_process_name(),
            RW_CONFIG_DIRECTORY,
        ));
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            shell_cmd.join(" && "),
        ]
    }
}

impl DruidCluster {
    pub fn common_compute_files(
        &self,
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
                let mds = self.spec.metadata_storage_database.clone();
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
                if self.uses_s3() {
                    extensions.push(EXT_S3.to_string());
                }
                // OPA
                if let Some(_opa) = self.spec.opa.clone() {
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
                    Some(self.spec.deep_storage.to_string()),
                );
                match self.spec.deep_storage.clone() {
                    DeepStorageSpec::HDFS(hdfs) => {
                        result.insert(DS_DIRECTORY.to_string(), Some(hdfs.directory));
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

    pub fn replicas(&self, rolegroup_ref: &RoleGroupRef<DruidCluster>) -> Option<i32> {
        match DruidRole::from_str(rolegroup_ref.role.as_str()).unwrap() {
            DruidRole::Broker => self
                .spec
                .brokers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.replicas)
                .map(i32::from),
            DruidRole::MiddleManager => self
                .spec
                .middle_managers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.replicas)
                .map(i32::from),
            DruidRole::Coordinator => self
                .spec
                .coordinators
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.replicas)
                .map(i32::from),
            DruidRole::Historical => self
                .spec
                .historicals
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.replicas)
                .map(i32::from),
            DruidRole::Router => self
                .spec
                .routers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.replicas)
                .map(i32::from),
        }
    }

    pub fn build_role_properties(
        &self,
    ) -> HashMap<
        String,
        (
            Vec<PropertyNameKind>,
            Role<impl Configuration<Configurable = DruidCluster>>,
        ),
    > {
        let config_files = vec![
            PropertyNameKind::Env,
            PropertyNameKind::File(JVM_CONFIG.to_string()),
            PropertyNameKind::File(LOG4J2_CONFIG.to_string()),
            PropertyNameKind::File(RUNTIME_PROPS.to_string()),
        ];

        vec![
            (
                DruidRole::Broker.to_string(),
                (config_files.clone(), self.spec.brokers.clone().erase()),
            ),
            (
                DruidRole::Historical.to_string(),
                (config_files.clone(), self.spec.historicals.clone().erase()),
            ),
            (
                DruidRole::Router.to_string(),
                (config_files.clone(), self.spec.routers.clone().erase()),
            ),
            (
                DruidRole::MiddleManager.to_string(),
                (
                    config_files.clone(),
                    self.spec.middle_managers.clone().erase(),
                ),
            ),
            (
                DruidRole::Coordinator.to_string(),
                (config_files, self.spec.coordinators.clone().erase()),
            ),
        ]
        .into_iter()
        .collect()
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
        // retrieve connection for ingestion (can be None)
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

        // retrieve connection for deep storage (can be None)
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

        // if both connections are specified and are identical, return it
        // if they differ, raise an error
        // if only one connection is specified, return it
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

    /// Retrieve and merge resource configs for role and role groups
    pub fn resources(
        &self,
        role: &DruidRole,
        rolegroup_ref: &RoleGroupRef<DruidCluster>,
    ) -> Result<resource::RoleResourceEnum, Error> {
        let mut rg_resources = self.rolegroup_resources(role, rolegroup_ref);
        let mut role_resources = self.role_resources(role);
        let mut default_resources = self.default_resources(role);

        let result = resource::try_merge(
            default_resources.as_mut(),
            role_resources.as_mut(),
            rg_resources.as_mut(),
        );

        result.context(ResourceMergeSnafu)
    }

    fn default_resources(&self, role: &DruidRole) -> Option<resource::RoleResourceEnum> {
        match role {
            DruidRole::Broker => Some(resource::RoleResourceEnum::Druid(
                BrokerConfig::default_resources(),
            )),
            DruidRole::Coordinator => Some(resource::RoleResourceEnum::Druid(
                CoordinatorConfig::default_resources(),
            )),
            DruidRole::Historical => Some(resource::RoleResourceEnum::Historical(
                HistoricalConfig::default_resources(),
            )),
            DruidRole::MiddleManager => Some(resource::RoleResourceEnum::Druid(
                MiddleManagerConfig::default_resources(),
            )),
            DruidRole::Router => Some(resource::RoleResourceEnum::Druid(
                RouterConfig::default_resources(),
            )),
        }
    }

    fn role_resources(&self, role: &DruidRole) -> Option<resource::RoleResourceEnum> {
        match role {
            DruidRole::Broker => self
                .spec
                .brokers
                .clone()
                .config
                .config
                .resources
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::Coordinator => self
                .spec
                .coordinators
                .clone()
                .config
                .config
                .resources
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::Historical => self
                .spec
                .historicals
                .clone()
                .config
                .config
                .resources
                .map(resource::RoleResourceEnum::Historical),
            DruidRole::MiddleManager => self
                .spec
                .middle_managers
                .clone()
                .config
                .config
                .resources
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::Router => self
                .spec
                .routers
                .clone()
                .config
                .config
                .resources
                .map(resource::RoleResourceEnum::Druid),
        }
    }

    fn rolegroup_resources(
        &self,
        role: &DruidRole,
        rolegroup_ref: &RoleGroupRef<DruidCluster>,
    ) -> Option<resource::RoleResourceEnum> {
        match role {
            DruidRole::Broker => self
                .spec
                .brokers
                .clone()
                .role_groups
                .get(&rolegroup_ref.role_group)
                .map(|rg| &rg.config.config)
                .and_then(|rg| rg.resources.clone())
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::Coordinator => self
                .spec
                .coordinators
                .role_groups
                .get(&rolegroup_ref.role_group)
                .map(|rg| &rg.config.config)
                .and_then(|rg| rg.resources.clone())
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::MiddleManager => self
                .spec
                .middle_managers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .map(|rg| &rg.config.config)
                .and_then(|rg| rg.resources.clone())
                .map(resource::RoleResourceEnum::Druid),
            DruidRole::Historical => self
                .spec
                .historicals
                .role_groups
                .get(&rolegroup_ref.role_group)
                .map(|rg| &rg.config.config)
                .and_then(|rg| rg.resources.clone())
                .map(resource::RoleResourceEnum::Historical),
            DruidRole::Router => self
                .spec
                .routers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .map(|rg| &rg.config.config)
                .and_then(|rg| rg.resources.clone())
                .map(resource::RoleResourceEnum::Druid),
        }
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

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize, Display)]
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsDeepStorageSpec {
    pub config_map_name: String,
    pub directory: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BrokerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Resources<storage::DruidStorage, NoRuntimeLimits>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CoordinatorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Resources<storage::DruidStorage, NoRuntimeLimits>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MiddleManagerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Resources<storage::DruidStorage, NoRuntimeLimits>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RouterConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Resources<storage::DruidStorage, NoRuntimeLimits>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<Resources<storage::HistoricalStorage, NoRuntimeLimits>>,
}

impl MiddleManagerConfig {
    pub fn default_resources() -> Resources<storage::DruidStorage, NoRuntimeLimits> {
        resource::DEFAULT_RESOURCES.clone()
    }
}

impl CoordinatorConfig {
    pub fn default_resources() -> Resources<storage::DruidStorage, NoRuntimeLimits> {
        resource::DEFAULT_RESOURCES.clone()
    }
}
impl RouterConfig {
    pub fn default_resources() -> Resources<storage::DruidStorage, NoRuntimeLimits> {
        resource::DEFAULT_RESOURCES.clone()
    }
}

impl BrokerConfig {
    pub fn default_resources() -> Resources<storage::DruidStorage, NoRuntimeLimits> {
        resource::DEFAULT_RESOURCES.clone()
    }
}

impl HistoricalConfig {
    pub fn default_resources() -> Resources<storage::HistoricalStorage, NoRuntimeLimits> {
        resource::HISTORICAL_RESOURCES.clone()
    }
}

impl Configuration for BrokerConfig {
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
        resource.common_compute_files(role_name, file)
    }
}

impl Configuration for HistoricalConfig {
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
        let mut result = resource.common_compute_files(role_name, file)?;

        if let Some(Resources { storage, .. }) = &self.resources.as_ref() {
            let max_size = storage.segment_cache_max_size();
            result.insert(
                SC_LOCATIONS.to_string(),
                Some(format!(
                    "[{{\"path\":\"{SC_DIRECTORY}\",\"maxSize\":\"{max_size}\"}}]"
                )),
            );
        }

        Ok(result)
    }
}

impl Configuration for RouterConfig {
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
        resource.common_compute_files(role_name, file)
    }
}

impl Configuration for MiddleManagerConfig {
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
        let mut result = resource.common_compute_files(role_name, file)?;
        result.insert(
            INDEXER_JAVA_OPTS.to_string(),
            Some(build_string_list(&[
                format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
                format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
                "-Djavax.net.ssl.trustStoreType=pkcs12".to_string(),
            ])),
        );
        Ok(result)
    }
}

impl Configuration for CoordinatorConfig {
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
        resource.common_compute_files(role_name, file)
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

    #[test]
    fn test_service_name_generation() {
        let cluster_cr =
            std::fs::File::open("test/resources/role_service/druid_cluster.yaml").unwrap();
        let cluster: DruidCluster = serde_yaml::from_reader(&cluster_cr).unwrap();

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
