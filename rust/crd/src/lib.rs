pub mod authentication;
pub mod authorization;
pub mod ldap;
pub mod memory;
pub mod resource;
pub mod security;
pub mod storage;
pub mod tls;

use crate::authentication::DruidAuthentication;
use crate::tls::DruidTls;

use authorization::DruidAuthorization;
use resource::RoleResource;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::{
        product_image_selection::ProductImage,
        resources::{NoRuntimeLimits, Resources},
        s3::{InlinedS3BucketSpec, S3BucketDef, S3ConnectionDef, S3ConnectionSpec},
        tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
    },
    config::{
        fragment::{self, Fragment, FromFragment, ValidationError},
        merge::Merge,
    },
    k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
    kube::{CustomResource, ResourceExt},
    labels::ObjectLabels,
    product_config::types::PropertyNameKind,
    product_config_utils::{ConfigError, Configuration},
    role_utils::{CommonConfiguration, Role, RoleGroup, RoleGroupRef},
    schemars::{self, JsonSchema},
};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};
use tls::default_druid_tls;

pub const APP_NAME: &str = "druid";
pub const OPERATOR_NAME: &str = "druid.stackable.tech";

// config directories
pub const DRUID_CONFIG_DIRECTORY: &str = "/stackable/config";
pub const HDFS_CONFIG_DIRECTORY: &str = "/stackable/hdfs";
pub const RW_CONFIG_DIRECTORY: &str = "/stackable/rwconfig";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

// store directories
pub const SYSTEM_TRUST_STORE: &str = "/etc/pki/java/cacerts";
pub const SYSTEM_TRUST_STORE_PASSWORD: &str = "changeit";
pub const STACKABLE_TRUST_STORE: &str = "/stackable/truststore.p12";
pub const STACKABLE_TRUST_STORE_PASSWORD: &str = "changeit";
pub const CERTS_DIR: &str = "/stackable/certificates";

pub const PROP_SEGMENT_CACHE_LOCATIONS: &str = "druid.segmentCache.locations";
pub const PATH_SEGMENT_CACHE: &str = "/stackable/var/druid/segment-cache";

/////////////////////////////
//    CONFIG PROPERTIES    //
/////////////////////////////
// extensions
pub const EXTENSIONS_LOADLIST: &str = "druid.extensions.loadList";
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
// historical settings
pub const PROCESSING_BUFFER_SIZE_BYTES: &str = "druid.processing.buffer.sizeBytes";
pub const PROCESSING_NUM_MERGE_BUFFERS: &str = "druid.processing.numMergeBuffers";
pub const PROCESSING_NUM_THREADS: &str = "druid.processing.numThreads";
// extra
pub const CREDENTIALS_SECRET_PROPERTY: &str = "credentialsSecret";
// metrics
pub const PROMETHEUS_PORT: &str = "druid.emitter.prometheus.port";
pub const METRICS_PORT: u16 = 9090;
// container locations
pub const S3_SECRET_DIR_NAME: &str = "/stackable/secrets";
const ENV_S3_ACCESS_KEY: &str = "AWS_ACCESS_KEY_ID";
const ENV_S3_SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const SECRET_KEY_S3_ACCESS_KEY: &str = "accessKey";
const SECRET_KEY_S3_SECRET_KEY: &str = "secretKey";
// segment storage
pub const SC_LOCATIONS: &str = "druid.segmentCache.locations";
pub const SC_DIRECTORY: &str = "/stackable/var/druid/segment-cache";
pub const SC_VOLUME_NAME: &str = "segment-cache";

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
    #[snafu(display("missing namespace for resource {name}"))]
    MissingNamespace { name: String },
    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },
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
    /// The Druid image to use
    pub image: ProductImage,
    /// Configuration of the broker role
    pub brokers: Role<BrokerConfigFragment>,
    /// Configuration of the coordinator role
    pub coordinators: Role<CoordinatorConfigFragment>,
    /// Configuration of the historical role
    pub historicals: Role<HistoricalConfigFragment>,
    /// Configuration of the middle managed role
    pub middle_managers: Role<MiddleManagerConfigFragment>,
    /// Configuration of the router role
    pub routers: Role<RouterConfigFragment>,
    /// Common cluster wide configuration that can not differ or be overridden on a role or role group level
    pub cluster_config: DruidClusterConfig,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterConfig {
    /// List of Authentication classes using like TLS or LDAP to authenticate users
    #[serde(default)]
    pub authentication: Vec<DruidAuthentication>,
    /// Authorization settings for Druid like OPA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<DruidAuthorization>,
    /// Deep storage settings for Druid like S3 or HDFS
    pub deep_storage: DeepStorageSpec,
    /// Ingestion settings for Druid like S3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingestion: Option<IngestionSpec>,
    /// Meta storage database like Derby or PostgreSQL
    pub metadata_storage_database: DatabaseConnectionSpec,
    /// TLS encryption settings for Druid.
    /// This setting only affects server and internal communication.
    /// It does not affect client tls authentication, use `clusterConfig.authentication` instead.
    #[serde(default = "default_druid_tls", skip_serializing_if = "Option::is_none")]
    pub tls: Option<DruidTls>,
    /// ZooKeeper discovery ConfigMap
    pub zookeeper_config_map_name: String,
}

pub struct MergedConfig {
    pub brokers: HashMap<String, BrokerConfig>,
    pub coordinators: HashMap<String, CoordinatorConfig>,
    pub historicals: HashMap<String, HistoricalConfig>,
    pub middle_managers: HashMap<String, MiddleManagerConfig>,
    pub routers: HashMap<String, RouterConfig>,
}

impl MergedConfig {
    pub fn resources(&self, role: DruidRole, role_group: &str) -> RoleResource {
        self.common_config(role, role_group).resources
    }

    pub fn common_config(&self, role: DruidRole, role_group: &str) -> CommonConfig {
        match role {
            DruidRole::Broker => {
                let config = self
                    .brokers
                    .get(role_group)
                    .cloned()
                    // TODO default?
                    .unwrap_or_default();
                CommonConfig {
                    resources: RoleResource::Druid(config.resources),
                }
            }
            DruidRole::Coordinator => {
                let config = self
                    .coordinators
                    .get(role_group)
                    .cloned()
                    .unwrap_or_default();
                CommonConfig {
                    resources: RoleResource::Druid(config.resources),
                }
            }
            DruidRole::Historical => {
                let config = self
                    .historicals
                    .get(role_group)
                    .cloned()
                    .unwrap_or_default();
                CommonConfig {
                    resources: RoleResource::Historical(config.resources),
                }
            }
            DruidRole::MiddleManager => {
                let config = self
                    .middle_managers
                    .get(role_group)
                    .cloned()
                    .unwrap_or_default();
                CommonConfig {
                    resources: RoleResource::Druid(config.resources),
                }
            }
            DruidRole::Router => {
                let config = self.routers.get(role_group).cloned().unwrap_or_default();
                CommonConfig {
                    resources: RoleResource::Druid(config.resources),
                }
            }
        }
    }
}

pub struct CommonConfig {
    pub resources: RoleResource,
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

    /// Returns the http port for every role
    pub fn get_http_port(&self) -> u16 {
        match &self {
            DruidRole::Coordinator => 8081,
            DruidRole::Broker => 8082,
            DruidRole::Historical => 8083,
            DruidRole::MiddleManager => 8091,
            DruidRole::Router => 8888,
        }
    }

    /// Returns the https port for every role
    pub fn get_https_port(&self) -> u16 {
        match &self {
            DruidRole::Coordinator => 8281,
            DruidRole::Broker => 8282,
            DruidRole::Historical => 8283,
            DruidRole::MiddleManager => 8291,
            DruidRole::Router => 9088,
        }
    }

    /// Returns the start commands for the different server types.
    pub fn get_command(
        &self,
        s3_connection: Option<&S3ConnectionSpec>,
        ldap_auth_cmd: Vec<String>,
    ) -> Vec<String> {
        let mut shell_cmd = vec![format!("keytool -importkeystore -srckeystore {SYSTEM_TRUST_STORE} -srcstoretype jks -srcstorepass {SYSTEM_TRUST_STORE_PASSWORD} -destkeystore {STACKABLE_TRUST_STORE} -deststoretype pkcs12 -deststorepass {STACKABLE_TRUST_STORE_PASSWORD} -noprompt")];

        if let Some(s3_connection) = s3_connection {
            if let Some(Tls {
                verification:
                    TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::SecretClass(secret_class),
                    }),
            }) = &s3_connection.tls
            {
                shell_cmd.push(format!("keytool -importcert -file {CERTS_DIR}/{secret_class}-tls-certificate/ca.crt -alias stackable-{secret_class} -keystore {STACKABLE_TRUST_STORE} -storepass {STACKABLE_TRUST_STORE_PASSWORD} -noprompt"));
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
            "cp -RL {hdfs_conf}/* {rw_conf} 2>/dev/null || :", // NOTE: the OR part is here because the command is not applicable sometimes, and would stop everything else from executing
            hdfs_conf = HDFS_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY,
        ));

        shell_cmd.extend(ldap_auth_cmd);

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
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();
        match file {
            JVM_CONFIG => {}
            RUNTIME_PROPS => {
                let mds = &self.spec.cluster_config.metadata_storage_database;
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

                // OPA
                if let Some(DruidAuthorization { opa: _ }) = &self.spec.cluster_config.authorization
                {
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
                    Some(self.spec.cluster_config.deep_storage.to_string()),
                );
                match self.spec.cluster_config.deep_storage.clone() {
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

                // metrics
                result.insert(PROMETHEUS_PORT.to_string(), Some(METRICS_PORT.to_string()));
            }
            LOG4J2_CONFIG => {}
            _ => {}
        }

        Ok(result)
    }

    /// Takes a rolegoup_ref (with role and role group name) and returns the selector defined for
    /// that role group.
    pub fn node_selector(
        &self,
        rolegroup_ref: &RoleGroupRef<DruidCluster>,
    ) -> Option<LabelSelector> {
        match DruidRole::from_str(rolegroup_ref.role.as_str()).unwrap() {
            DruidRole::Broker => self
                .spec
                .brokers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.selector.clone()),
            DruidRole::MiddleManager => self
                .spec
                .middle_managers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.selector.clone()),
            DruidRole::Coordinator => self
                .spec
                .coordinators
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.selector.clone()),
            DruidRole::Historical => self
                .spec
                .historicals
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.selector.clone()),
            DruidRole::Router => self
                .spec
                .routers
                .role_groups
                .get(&rolegroup_ref.role_group)
                .and_then(|rg| rg.selector.clone()),
        }
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
            .cluster_config
            .ingestion
            .as_ref()
            .and_then(|is| is.s3connection.as_ref())
        {
            Some(
                ic.resolve(
                    client,
                    self.namespace()
                        .context(MissingNamespaceSnafu {
                            name: &self.name_unchecked(),
                        })?
                        .as_ref(),
                )
                .await
                .context(ResolveS3ConnectionSnafu)?,
            )
        } else {
            None
        };

        // retrieve connection for deep storage (can be None)
        let storage_conn = match &self.spec.cluster_config.deep_storage {
            DeepStorageSpec::S3(s3_spec) => {
                let inlined_bucket: InlinedS3BucketSpec = s3_spec
                    .bucket
                    .resolve(
                        client,
                        self.namespace()
                            .context(MissingNamespaceSnafu {
                                name: &self.name_unchecked(),
                            })?
                            .as_ref(),
                    )
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
            .cluster_config
            .ingestion
            .as_ref()
            .and_then(|spec| spec.s3connection.as_ref())
            .is_some();
        let s3_storage = self.spec.cluster_config.deep_storage.is_s3();
        s3_ingestion || s3_storage
    }

    pub fn merged_config(&self) -> Result<MergedConfig, Error> {
        Ok(MergedConfig {
            brokers: DruidCluster::merged_role_config(
                &self.spec.brokers,
                &BrokerConfig::default_config(),
            )?,
            coordinators: DruidCluster::merged_role_config(
                &self.spec.coordinators,
                &CoordinatorConfig::default_config(),
            )?,
            historicals: DruidCluster::merged_role_config(
                &self.spec.historicals,
                &HistoricalConfig::default_config(),
            )?,
            middle_managers: DruidCluster::merged_role_config(
                &self.spec.middle_managers,
                &MiddleManagerConfig::default_config(),
            )?,
            routers: DruidCluster::merged_role_config(
                &self.spec.routers,
                &RouterConfig::default_config(),
            )?,
        })
    }

    fn merged_role_config<T>(
        role: &Role<T::Fragment>,
        default_config: &T::Fragment,
    ) -> Result<HashMap<String, T>, Error>
    where
        T: FromFragment,
        T::Fragment: Clone + Merge,
    {
        let mut merged_role_config = HashMap::new();

        for (
            rolegroup_name,
            RoleGroup {
                config:
                    CommonConfiguration {
                        config: rolegroup_config,
                        ..
                    },
                ..
            },
        ) in &role.role_groups
        {
            let merged_rolegroup_config = DruidCluster::merged_rolegroup_config(
                rolegroup_config,
                &role.config.config,
                default_config,
            )?;
            merged_role_config.insert(rolegroup_name.to_owned(), merged_rolegroup_config);
        }

        Ok(merged_role_config)
    }

    pub fn merged_rolegroup_config<T>(
        rolegroup_config: &T::Fragment,
        role_config: &T::Fragment,
        default_config: &T::Fragment,
    ) -> Result<T, Error>
    where
        T: FromFragment,
        T::Fragment: Clone + Merge,
    {
        let mut role_config = role_config.to_owned();
        let mut rolegroup_config = rolegroup_config.to_owned();

        role_config.merge(default_config);
        rolegroup_config.merge(&role_config);

        fragment::validate(rolegroup_config).context(FragmentValidationFailureSnafu)
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

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct BrokerConfig {
    #[fragment_attrs(serde(default))]
    resources: Resources<storage::DruidStorage, NoRuntimeLimits>,
}

impl BrokerConfig {
    fn default_config() -> BrokerConfigFragment {
        BrokerConfigFragment {
            resources: resource::DEFAULT_RESOURCES.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct CoordinatorConfig {
    #[fragment_attrs(serde(default))]
    resources: Resources<storage::DruidStorage, NoRuntimeLimits>,
}

impl CoordinatorConfig {
    fn default_config() -> CoordinatorConfigFragment {
        CoordinatorConfigFragment {
            resources: resource::DEFAULT_RESOURCES.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct MiddleManagerConfig {
    #[fragment_attrs(serde(default))]
    resources: Resources<storage::DruidStorage, NoRuntimeLimits>,
}

impl MiddleManagerConfig {
    fn default_config() -> MiddleManagerConfigFragment {
        MiddleManagerConfigFragment {
            resources: resource::DEFAULT_RESOURCES.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct RouterConfig {
    #[fragment_attrs(serde(default))]
    resources: Resources<storage::DruidStorage, NoRuntimeLimits>,
}

impl RouterConfig {
    fn default_config() -> RouterConfigFragment {
        RouterConfigFragment {
            resources: resource::DEFAULT_RESOURCES.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct HistoricalConfig {
    #[fragment_attrs(serde(default))]
    resources: Resources<storage::HistoricalStorage, NoRuntimeLimits>,
}

impl HistoricalConfig {
    fn default_config() -> HistoricalConfigFragment {
        HistoricalConfigFragment {
            resources: resource::HISTORICAL_RESOURCES.to_owned(),
        }
    }
}

impl Configuration for BrokerConfigFragment {
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
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        resource.common_compute_files(file)
    }
}

impl Configuration for HistoricalConfigFragment {
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
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        resource.common_compute_files(file)
    }
}

impl Configuration for RouterConfigFragment {
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
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        resource.common_compute_files(file)
    }
}

impl Configuration for MiddleManagerConfigFragment {
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
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = resource.common_compute_files(file)?;
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

impl Configuration for CoordinatorConfigFragment {
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
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        resource.common_compute_files(file)
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterStatus {}

/// Takes a vec of strings and returns them as a formatted json
/// list.
pub fn build_string_list(strings: &[String]) -> String {
    let quoted_strings: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
    let comma_list = quoted_strings.join(", ");
    format!("[{}]", comma_list)
}

/// Creates recommended `ObjectLabels` to be used in deployed resources
pub fn build_recommended_labels<'a, T>(
    owner: &'a T,
    controller_name: &'a str,
    app_version: &'a str,
    role: &'a str,
    role_group: &'a str,
) -> ObjectLabels<'a, T> {
    ObjectLabels {
        owner,
        app_name: APP_NAME,
        app_version,
        operator_name: OPERATOR_NAME,
        controller_name,
        role,
        role_group,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name_generation() {
        let cluster =
            deserialize_yaml_file::<DruidCluster>("test/resources/role_service/druid_cluster.yaml");

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

    pub fn deserialize_yaml_str<'a, T: serde::de::Deserialize<'a>>(value: &'a str) -> T {
        let deserializer = serde_yaml::Deserializer::from_str(value);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap()
    }

    pub fn deserialize_yaml_file<'a, T: serde::de::Deserialize<'a>>(path: &'a str) -> T {
        let file = std::fs::File::open(path).unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(file);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap()
    }
}
