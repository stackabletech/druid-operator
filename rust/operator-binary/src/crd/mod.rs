use std::collections::{BTreeMap, HashMap, HashSet};

use indoc::formatdoc;
use product_config::types::PropertyNameKind;
use security::add_cert_to_jvm_trust_store_cmd;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::pod::volume::ListenerOperatorVolumeSourceBuilderError,
    client::Client,
    commons::{
        affinity::StackableAffinity,
        cluster_operation::ClusterOperation,
        product_image_selection::ProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    config::{
        fragment::{self, Fragment, FromFragment, ValidationError},
        merge::Merge,
    },
    crd::{authentication::core, s3},
    deep_merger::ObjectOverrides,
    k8s_openapi::api::core::v1::{PodTemplateSpec, Volume},
    kube::{CustomResource, ResourceExt},
    kvp::ObjectLabels,
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{Configuration, Error as ConfigError},
    product_logging::{
        self,
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
        spec::Logging,
    },
    role_utils::{CommonConfiguration, GenericRoleConfig, JavaCommonConfig, Role, RoleGroup},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    utils::{COMMON_BASH_TRAP_FUNCTIONS, crds::raw_object_list_schema},
    versioned::versioned,
};
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};

use crate::crd::{
    affinity::get_affinity,
    authorization::DruidAuthorization,
    resource::RoleResource,
    tls::{DruidTls, default_druid_tls},
    v1alpha1::DruidRoleConfig,
};

pub mod affinity;
pub mod authentication;
pub mod authorization;
pub mod memory;
pub mod resource;
pub mod security;
pub mod storage;
pub mod tls;

pub const APP_NAME: &str = "druid";
pub const OPERATOR_NAME: &str = "druid.stackable.tech";
pub const FIELD_MANAGER: &str = "druid-operator";

// config directories
pub const DRUID_CONFIG_DIRECTORY: &str = "/stackable/config";
pub const HDFS_CONFIG_DIRECTORY: &str = "/stackable/hdfs";
pub const LOG_CONFIG_DIRECTORY: &str = "/stackable/log_config";
pub const RW_CONFIG_DIRECTORY: &str = "/stackable/rwconfig";

// config file names
pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.properties";
pub const JVM_SECURITY_PROPERTIES_FILE: &str = "security.properties";

// store directories
pub const STACKABLE_TRUST_STORE: &str = "/stackable/truststore.p12";
pub const STACKABLE_TRUST_STORE_PASSWORD: &str = "changeit";
pub const STACKABLE_LOG_DIR: &str = "/stackable/log";

// store file names
pub const DRUID_LOG_FILE: &str = "druid.log4j2.xml";

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
pub const S3_ACCESS_KEY: &str = "druid.s3.accessKey";
pub const S3_SECRET_KEY: &str = "druid.s3.secretKey";
pub const S3_PATH_STYLE_ACCESS: &str = "druid.s3.enablePathStyleAccess";
// OPA
pub const AUTH_AUTHORIZERS: &str = "druid.auth.authorizers";
pub const AUTH_AUTHORIZERS_VALUE: &str = "[\"OpaAuthorizer\"]";
pub const AUTH_AUTHORIZER_OPA_TYPE: &str = "druid.auth.authorizer.OpaAuthorizer.type";
pub const AUTH_AUTHORIZER_OPA_TYPE_VALUE: &str = "opa";
pub const AUTH_AUTHORIZER_OPA_URI: &str = "druid.auth.authorizer.OpaAuthorizer.opaUri";
// metadata storage config properties
const METADATA_STORAGE_TYPE: &str = "druid.metadata.storage.type";
const METADATA_STORAGE_URI: &str = "druid.metadata.storage.connector.connectURI";
const METADATA_STORAGE_HOST: &str = "druid.metadata.storage.connector.host";
const METADATA_STORAGE_PORT: &str = "druid.metadata.storage.connector.port";
const METADATA_STORAGE_USER: &str = "druid.metadata.storage.connector.user";
const METADATA_STORAGE_PASSWORD: &str = "druid.metadata.storage.connector.password";
// indexer properties
pub const INDEXER_JAVA_OPTS: &str = "druid.indexer.runner.javaOptsArray";
// historical settings
pub const PROCESSING_BUFFER_SIZE_BYTES: &str = "druid.processing.buffer.sizeBytes";
pub const PROCESSING_NUM_MERGE_BUFFERS: &str = "druid.processing.numMergeBuffers";
pub const PROCESSING_NUM_THREADS: &str = "druid.processing.numThreads";
// extra
pub const CREDENTIALS_SECRET_PROPERTY: &str = "credentialsSecret";
// logs
pub const MAX_DRUID_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};
// metrics
pub const PROMETHEUS_PORT: &str = "druid.emitter.prometheus.port";
pub const METRICS_PORT_NAME: &str = "metrics";
pub const METRICS_PORT: u16 = 9090;

pub const COOKIE_PASSPHRASE_ENV: &str = "OIDC_COOKIE_PASSPHRASE";

// DB credentials - both of these are read from an env var by Druid with the ${env:...} syntax
pub const DB_USERNAME_ENV: &str = "DB_USERNAME_ENV";
pub const DB_PASSWORD_ENV: &str = "DB_PASSWORD_ENV";

// Graceful shutdown timeouts
const DEFAULT_BROKER_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(5);
const DEFAULT_COORDINATOR_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(5);
const DEFAULT_MIDDLEMANAGER_GRACEFUL_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_minutes_unchecked(5);
const DEFAULT_ROUTER_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(5);
const DEFAULT_HISTORICAL_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(5);

// Auto TLS certificate lifetime
const DEFAULT_BROKER_SECRET_LIFETIME: Duration = Duration::from_days_unchecked(1);
const DEFAULT_COORDINATOR_SECRET_LIFETIME: Duration = Duration::from_days_unchecked(1);
const DEFAULT_MIDDLE_SECRET_LIFETIME: Duration = Duration::from_days_unchecked(1);
const DEFAULT_ROUTER_SECRET_LIFETIME: Duration = Duration::from_days_unchecked(1);
const DEFAULT_HISTORICAL_SECRET_LIFETIME: Duration = Duration::from_days_unchecked(1);

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("failed to resolve S3 connection"))]
    ResolveS3Connection {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to resolve S3 bucket"))]
    ResolveS3Bucket {
        source: stackable_operator::crd::s3::v1alpha1::BucketError,
    },

    #[snafu(display("2 differing s3 connections were given, this is unsupported by Druid"))]
    IncompatibleS3Connections,

    #[snafu(display("the role group {rolegroup_name} is not defined"))]
    CannotRetrieveRoleGroup { rolegroup_name: String },

    #[snafu(display("missing namespace for resource {name}"))]
    MissingNamespace { name: String },

    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },

    #[snafu(display("failed to build listener volume"))]
    BuildListenerVolume {
        source: ListenerOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },
}

#[versioned(
    version(name = "v1alpha1"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned"
    )
)]
pub mod versioned {
    /// A Druid cluster stacklet. This resource is managed by the Stackable operator for Apache Druid.
    /// Find more information on how to use it and the resources that the operator generates in the
    /// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/druid/).
    #[versioned(crd(
        group = "druid.stackable.tech",
        kind = "DruidCluster",
        plural = "druidclusters",
        shortname = "druid",
        status = "DruidClusterStatus",
        namespaced
    ))]
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DruidClusterSpec {
        /// Common cluster wide configuration that can not differ or be overridden on a role or role group level.
        pub cluster_config: v1alpha1::DruidClusterConfig,

        // no doc - docs provided by the struct.
        pub image: ProductImage,

        // no doc - docs provided by the struct.
        pub brokers: Role<BrokerConfigFragment, DruidRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        pub coordinators: Role<CoordinatorConfigFragment, DruidRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        pub historicals: Role<HistoricalConfigFragment, GenericRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        pub middle_managers: Role<MiddleManagerConfigFragment, GenericRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        pub routers: Role<RouterConfigFragment, DruidRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        // no doc - docs provided by the struct.
        #[serde(default)]
        pub object_overrides: ObjectOverrides,
    }

    #[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DruidClusterConfig {
        /// Additional extensions to load in Druid.
        /// The operator will automatically load all extensions needed based on the cluster
        /// configuration, but for extra functionality which the operator cannot anticipate, it can
        /// sometimes be necessary to load additional extensions.
        /// Add configuration for additional extensions using [configuration override for Druid](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/overrides).
        #[serde(default)]
        pub additional_extensions: HashSet<String>,

        /// List of [AuthenticationClasses](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication)
        /// to use for authenticating users. TLS, LDAP and OIDC authentication are supported. More information in
        /// the [Druid operator security documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/security#_authentication).
        ///
        /// For TLS: Please note that the SecretClass used to authenticate users needs to be the same
        /// as the SecretClass used for internal communication.
        #[serde(default)]
        pub authentication: Vec<core::v1alpha1::ClientAuthenticationDetails>,

        /// Authorization settings for Druid like OPA
        #[serde(skip_serializing_if = "Option::is_none")]
        pub authorization: Option<DruidAuthorization>,

        /// [Druid deep storage configuration](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/deep-storage).
        /// Only one backend can be used at a time. Either HDFS or S3 are supported.
        pub deep_storage: DeepStorageSpec,

        /// Configuration properties for data ingestion tasks.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ingestion: Option<IngestionSpec>,

        /// Druid requires an SQL database to store metadata into. Specify connection information here.
        pub metadata_storage_database: DatabaseConnectionSpec,

        /// TLS encryption settings for Druid, more information in the
        /// [security documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/security).
        /// This setting only affects server and internal communication.
        /// It does not affect client tls authentication, use `clusterConfig.authentication` instead.
        #[serde(default = "default_druid_tls", skip_serializing_if = "Option::is_none")]
        pub tls: Option<DruidTls>,

        /// Druid requires a ZooKeeper cluster connection to run.
        /// Provide the name of the ZooKeeper [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery)
        /// here. When using the [Stackable operator for Apache ZooKeeper](DOCS_BASE_URL_PLACEHOLDER/zookeeper/)
        /// to deploy a ZooKeeper cluster, this will simply be the name of your ZookeeperCluster resource.
        pub zookeeper_config_map_name: String,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<String>,

        /// Extra volumes similar to `.spec.volumes` on a Pod to mount into every container, this can be useful to for
        /// example make client certificates, keytabs or similar things available to processors. These volumes will be
        /// mounted into all pods at `/stackable/userdata/{volumename}`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[schemars(schema_with = "raw_object_list_schema")]
        pub extra_volumes: Vec<Volume>,
    }
    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DruidRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        #[serde(default = "druid_default_listener_class")]
        pub listener_class: String,
    }
}

// Required to retrieve the conditions from the cluster status
impl HasStatusCondition for v1alpha1::DruidCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

impl v1alpha1::DruidCluster {
    pub fn common_compute_files(
        &self,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();
        match file {
            JVM_CONFIG => {}
            RUNTIME_PROPS => {
                let mds = &self.spec.cluster_config.metadata_storage_database;
                result.insert(
                    METADATA_STORAGE_TYPE.to_string(),
                    Some(mds.db_type.to_string()),
                );
                result.insert(
                    METADATA_STORAGE_URI.to_string(),
                    Some(mds.conn_string.to_string()),
                );
                result.insert(
                    METADATA_STORAGE_HOST.to_string(),
                    Some(mds.host.to_string()),
                );
                result.insert(
                    METADATA_STORAGE_PORT.to_string(),
                    Some(mds.port.to_string()),
                );
                if mds.credentials_secret.is_some() {
                    result.insert(
                        METADATA_STORAGE_USER.to_string(),
                        Some(format!("${{env:{DB_USERNAME_ENV}}}")),
                    );
                    result.insert(
                        METADATA_STORAGE_PASSWORD.to_string(),
                        Some(format!("${{env:{DB_PASSWORD_ENV}}}")),
                    );
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
                    DeepStorageSpec::Hdfs(hdfs) => {
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
            _ => {}
        }

        Ok(result)
    }

    #[allow(clippy::type_complexity)]
    pub fn build_role_properties(
        &self,
    ) -> HashMap<
        String,
        (
            Vec<PropertyNameKind>,
            Role<
                impl Configuration<Configurable = v1alpha1::DruidCluster>,
                GenericRoleConfig,
                JavaCommonConfig,
            >,
        ),
    > {
        let config_files = vec![
            PropertyNameKind::Env,
            PropertyNameKind::File(JVM_CONFIG.to_string()),
            PropertyNameKind::File(RUNTIME_PROPS.to_string()),
            PropertyNameKind::File(JVM_SECURITY_PROPERTIES_FILE.to_string()),
        ];

        vec![
            (
                DruidRole::Broker.to_string(),
                (
                    config_files.clone(),
                    extract_role_from_role_config::<BrokerConfig>(self.spec.brokers.clone())
                        .erase(),
                ),
            ),
            (
                DruidRole::Coordinator.to_string(),
                (
                    config_files.clone(),
                    extract_role_from_role_config::<CoordinatorConfig>(
                        self.spec.coordinators.clone(),
                    )
                    .erase(),
                ),
            ),
            (
                DruidRole::Historical.to_string(),
                (config_files.clone(), self.spec.historicals.clone().erase()),
            ),
            (
                DruidRole::MiddleManager.to_string(),
                (
                    config_files.clone(),
                    self.spec.middle_managers.clone().erase(),
                ),
            ),
            (
                DruidRole::Router.to_string(),
                (
                    config_files,
                    extract_role_from_role_config::<RouterConfig>(self.spec.routers.clone())
                        .erase(),
                ),
            ),
        ]
        .into_iter()
        .collect()
    }

    /// If an s3 connection for ingestion is given, as well as an s3 connection for deep storage, they need to be the same.
    /// This function returns the resolved connection, or raises an Error if the connections are not identical.
    pub async fn get_s3_connection(
        &self,
        client: &Client,
    ) -> Result<Option<s3::v1alpha1::ConnectionSpec>, Error> {
        // retrieve connection for ingestion (can be None)
        let ingestion_conn = if let Some(ic) = self
            .spec
            .cluster_config
            .ingestion
            .as_ref()
            .and_then(|is| is.s3connection.as_ref())
        {
            Some(
                ic.clone()
                    .resolve(
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
                let inlined_bucket = s3_spec
                    .bucket
                    .clone()
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
                Some(inlined_bucket.connection)
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
    /// This is a quicker convenience function over the [v1alpha1::DruidCluster::get_s3_connection] function.
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

    /// Returns the merged and validated configuration for all roles
    pub fn merged_config(&self) -> Result<MergedConfig, Error> {
        let deep_storage = &self.spec.cluster_config.deep_storage;

        Ok(MergedConfig {
            brokers: v1alpha1::DruidCluster::merged_role(
                &extract_role_from_role_config::<BrokerConfig>(self.spec.brokers.clone()),
                &BrokerConfig::default_config(&self.name_any(), &DruidRole::Broker, deep_storage),
            )?,
            coordinators: v1alpha1::DruidCluster::merged_role(
                &extract_role_from_role_config::<CoordinatorConfig>(self.spec.coordinators.clone()),
                &CoordinatorConfig::default_config(
                    &self.name_any(),
                    &DruidRole::Coordinator,
                    deep_storage,
                ),
            )?,
            historicals: v1alpha1::DruidCluster::merged_role(
                &self.spec.historicals,
                &HistoricalConfig::default_config(
                    &self.name_any(),
                    &DruidRole::Historical,
                    deep_storage,
                ),
            )?,
            middle_managers: v1alpha1::DruidCluster::merged_role(
                &self.spec.middle_managers,
                &MiddleManagerConfig::default_config(
                    &self.name_any(),
                    &DruidRole::MiddleManager,
                    deep_storage,
                ),
            )?,
            routers: v1alpha1::DruidCluster::merged_role(
                &extract_role_from_role_config::<RouterConfig>(self.spec.routers.clone()),
                &RouterConfig::default_config(&self.name_any(), &DruidRole::Router, deep_storage),
            )?,
        })
    }

    /// Merges and validates the role groups of the given role with the given default configuration
    fn merged_role<T>(
        role: &Role<T::Fragment, GenericRoleConfig, JavaCommonConfig>,
        default_config: &T::Fragment,
    ) -> Result<HashMap<String, RoleGroup<T, JavaCommonConfig>>, Error>
    where
        T: FromFragment,
        T::Fragment: Clone + Merge,
    {
        let mut merged_role_config = HashMap::new();

        for (rolegroup_name, rolegroup) in &role.role_groups {
            let merged_rolegroup_config = v1alpha1::DruidCluster::merged_rolegroup(
                rolegroup,
                &role.config.config,
                default_config,
            )?;
            merged_role_config.insert(rolegroup_name.to_owned(), merged_rolegroup_config);
        }

        Ok(merged_role_config)
    }

    /// Merges and validates the given role group with the given role and default configurations
    fn merged_rolegroup<T>(
        rolegroup: &RoleGroup<T::Fragment, JavaCommonConfig>,
        role_config: &T::Fragment,
        default_config: &T::Fragment,
    ) -> Result<RoleGroup<T, JavaCommonConfig>, Error>
    where
        T: FromFragment,
        T::Fragment: Clone + Merge,
    {
        let merged_config = v1alpha1::DruidCluster::merged_rolegroup_config(
            &rolegroup.config.config,
            role_config,
            default_config,
        )?;
        Ok(RoleGroup {
            config: CommonConfiguration {
                config: merged_config,
                config_overrides: rolegroup.config.config_overrides.to_owned(),
                env_overrides: rolegroup.config.env_overrides.to_owned(),
                cli_overrides: rolegroup.config.cli_overrides.to_owned(),
                pod_overrides: rolegroup.config.pod_overrides.to_owned(),
                product_specific_common_config: rolegroup
                    .config
                    .product_specific_common_config
                    .to_owned(),
            },
            replicas: rolegroup.replicas,
        })
    }

    pub fn generic_role_config(&self, role: &DruidRole) -> &GenericRoleConfig {
        match role {
            DruidRole::Broker => &self.spec.brokers.role_config.common,
            DruidRole::Coordinator => &self.spec.coordinators.role_config.common,
            DruidRole::Historical => &self.spec.historicals.role_config,
            DruidRole::MiddleManager => &self.spec.middle_managers.role_config,
            DruidRole::Router => &self.spec.routers.role_config.common,
        }
    }

    /// Merges and validates the given role group, role, and default configurations
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

    pub fn get_role(
        &self,
        druid_role: &DruidRole,
    ) -> Role<
        impl Configuration<Configurable = v1alpha1::DruidCluster>,
        GenericRoleConfig,
        JavaCommonConfig,
    > {
        match druid_role {
            DruidRole::Broker => {
                extract_role_from_role_config::<BrokerConfig>(self.spec.brokers.clone()).erase()
            }
            DruidRole::Coordinator => {
                extract_role_from_role_config::<CoordinatorConfig>(self.spec.coordinators.clone())
                    .erase()
            }
            DruidRole::Historical => self.spec.historicals.clone().erase(),
            DruidRole::MiddleManager => self.spec.middle_managers.clone().erase(),
            DruidRole::Router => {
                extract_role_from_role_config::<RouterConfig>(self.spec.routers.clone()).erase()
            }
        }
    }

    pub fn pod_overrides_for_role(&self, role: &DruidRole) -> &PodTemplateSpec {
        match role {
            DruidRole::Broker => &self.spec.brokers.config.pod_overrides,
            DruidRole::Coordinator => &self.spec.coordinators.config.pod_overrides,
            DruidRole::Historical => &self.spec.historicals.config.pod_overrides,
            DruidRole::MiddleManager => &self.spec.middle_managers.config.pod_overrides,
            DruidRole::Router => &self.spec.routers.config.pod_overrides,
        }
    }

    pub fn pod_overrides_for_role_group(
        &self,
        role: &DruidRole,
        role_group: &str,
    ) -> Option<&PodTemplateSpec> {
        match role {
            DruidRole::Broker => self
                .spec
                .brokers
                .role_groups
                .get(role_group)
                .map(|rg| &rg.config.pod_overrides),
            DruidRole::Coordinator => self
                .spec
                .coordinators
                .role_groups
                .get(role_group)
                .map(|rg| &rg.config.pod_overrides),
            DruidRole::Historical => self
                .spec
                .historicals
                .role_groups
                .get(role_group)
                .map(|rg| &rg.config.pod_overrides),
            DruidRole::MiddleManager => self
                .spec
                .middle_managers
                .role_groups
                .get(role_group)
                .map(|rg| &rg.config.pod_overrides),
            DruidRole::Router => self
                .spec
                .routers
                .role_groups
                .get(role_group)
                .map(|rg| &rg.config.pod_overrides),
        }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    Eq,
    EnumIter,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum Container {
    Druid,
    Prepare,
    Vector,
}

/// Common configuration for all role groups
pub struct CommonRoleGroupConfig {
    pub resources: RoleResource,
    pub logging: Logging<Container>,
    pub replicas: Option<u16>,
    pub affinity: StackableAffinity,
    pub graceful_shutdown_timeout: Option<Duration>,
    pub requested_secret_lifetime: Duration,
}

/// Container for the merged and validated role group configurations
///
/// This structure contains for every role a map from the role group names to their configurations.
/// The role group configurations are merged with the role and default configurations. The product
/// configuration is not applied.
pub struct MergedConfig {
    /// Merged configuration of the broker role
    pub brokers: HashMap<String, RoleGroup<BrokerConfig, JavaCommonConfig>>,
    /// Merged configuration of the coordinator role
    pub coordinators: HashMap<String, RoleGroup<CoordinatorConfig, JavaCommonConfig>>,
    /// Merged configuration of the historical role
    pub historicals: HashMap<String, RoleGroup<HistoricalConfig, JavaCommonConfig>>,
    /// Merged configuration of the middle manager role
    pub middle_managers: HashMap<String, RoleGroup<MiddleManagerConfig, JavaCommonConfig>>,
    /// Merged configuration of the router role
    pub routers: HashMap<String, RoleGroup<RouterConfig, JavaCommonConfig>>,
}

impl MergedConfig {
    /// Returns the common configuration for the given role and rolegroup name
    pub fn common_config(
        &self,
        role: &DruidRole,
        rolegroup_name: &str,
    ) -> Result<CommonRoleGroupConfig, Error> {
        match role {
            DruidRole::Broker => {
                let rolegroup = self
                    .brokers
                    .get(rolegroup_name)
                    .context(CannotRetrieveRoleGroupSnafu { rolegroup_name })?;
                Ok(CommonRoleGroupConfig {
                    resources: RoleResource::Druid(rolegroup.config.config.resources.to_owned()),
                    logging: rolegroup.config.config.logging.to_owned(),
                    replicas: rolegroup.replicas,
                    affinity: rolegroup.config.config.affinity.clone(),
                    graceful_shutdown_timeout: rolegroup.config.config.graceful_shutdown_timeout,
                    requested_secret_lifetime: rolegroup
                        .config
                        .config
                        .requested_secret_lifetime
                        .context(MissingSecretLifetimeSnafu)?,
                })
            }
            DruidRole::Coordinator => {
                let rolegroup = self
                    .coordinators
                    .get(rolegroup_name)
                    .context(CannotRetrieveRoleGroupSnafu { rolegroup_name })?;
                Ok(CommonRoleGroupConfig {
                    resources: RoleResource::Druid(rolegroup.config.config.resources.to_owned()),
                    logging: rolegroup.config.config.logging.to_owned(),
                    replicas: rolegroup.replicas,
                    affinity: rolegroup.config.config.affinity.clone(),
                    graceful_shutdown_timeout: rolegroup.config.config.graceful_shutdown_timeout,
                    requested_secret_lifetime: rolegroup
                        .config
                        .config
                        .requested_secret_lifetime
                        .context(MissingSecretLifetimeSnafu)?,
                })
            }
            DruidRole::Historical => {
                let rolegroup = self
                    .historicals
                    .get(rolegroup_name)
                    .context(CannotRetrieveRoleGroupSnafu { rolegroup_name })?;
                Ok(CommonRoleGroupConfig {
                    resources: RoleResource::Historical(
                        rolegroup.config.config.resources.to_owned(),
                    ),
                    logging: rolegroup.config.config.logging.to_owned(),
                    replicas: rolegroup.replicas,
                    affinity: rolegroup.config.config.affinity.clone(),
                    graceful_shutdown_timeout: rolegroup.config.config.graceful_shutdown_timeout,
                    requested_secret_lifetime: rolegroup
                        .config
                        .config
                        .requested_secret_lifetime
                        .context(MissingSecretLifetimeSnafu)?,
                })
            }
            DruidRole::MiddleManager => {
                let rolegroup = self
                    .middle_managers
                    .get(rolegroup_name)
                    .context(CannotRetrieveRoleGroupSnafu { rolegroup_name })?;
                Ok(CommonRoleGroupConfig {
                    resources: RoleResource::Druid(rolegroup.config.config.resources.to_owned()),
                    logging: rolegroup.config.config.logging.to_owned(),
                    replicas: rolegroup.replicas,
                    affinity: rolegroup.config.config.affinity.clone(),
                    graceful_shutdown_timeout: rolegroup.config.config.graceful_shutdown_timeout,
                    requested_secret_lifetime: rolegroup
                        .config
                        .config
                        .requested_secret_lifetime
                        .context(MissingSecretLifetimeSnafu)?,
                })
            }
            DruidRole::Router => {
                let rolegroup = self
                    .routers
                    .get(rolegroup_name)
                    .context(CannotRetrieveRoleGroupSnafu { rolegroup_name })?;
                Ok(CommonRoleGroupConfig {
                    resources: RoleResource::Druid(rolegroup.config.config.resources.to_owned()),
                    logging: rolegroup.config.config.logging.to_owned(),
                    replicas: rolegroup.replicas,
                    affinity: rolegroup.config.config.affinity.clone(),
                    graceful_shutdown_timeout: rolegroup.config.config.graceful_shutdown_timeout,
                    requested_secret_lifetime: rolegroup
                        .config
                        .config
                        .requested_secret_lifetime
                        .context(MissingSecretLifetimeSnafu)?,
                })
            }
        }
    }
}

impl Default for v1alpha1::DruidRoleConfig {
    fn default() -> Self {
        v1alpha1::DruidRoleConfig {
            listener_class: druid_default_listener_class(),
            common: Default::default(),
        }
    }
}

fn druid_default_listener_class() -> String {
    "cluster-internal".to_string()
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

    /// Return the default graceful shutdown timeout
    pub fn default_graceful_shutdown_timeout(&self) -> Duration {
        match &self {
            DruidRole::Coordinator => DEFAULT_COORDINATOR_GRACEFUL_SHUTDOWN_TIMEOUT,
            DruidRole::Broker => DEFAULT_BROKER_GRACEFUL_SHUTDOWN_TIMEOUT,
            DruidRole::Historical => DEFAULT_HISTORICAL_GRACEFUL_SHUTDOWN_TIMEOUT,
            DruidRole::MiddleManager => DEFAULT_MIDDLEMANAGER_GRACEFUL_SHUTDOWN_TIMEOUT,
            DruidRole::Router => DEFAULT_ROUTER_GRACEFUL_SHUTDOWN_TIMEOUT,
        }
    }

    pub fn main_container_prepare_commands(
        &self,
        s3: Option<&s3::v1alpha1::ConnectionSpec>,
    ) -> Vec<String> {
        let mut commands = vec![];

        if let Some(s3) = s3 {
            if let Some(ca_cert_file) = s3.tls.tls_ca_cert_mount_path() {
                commands.extend(add_cert_to_jvm_trust_store_cmd(&ca_cert_file));
            }
        }

        // copy druid config to rw config
        commands.push(format!(
            "cp -RL {conf}/* {rw_conf}",
            conf = DRUID_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY
        ));

        // copy log config to rw config
        commands.push(format!(
            "cp -RL {conf}/* {rw_conf}",
            conf = LOG_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY
        ));

        // copy hdfs config to RW_CONFIG_DIRECTORY folder (if available)
        commands.push(format!(
            "cp -RL {hdfs_conf}/* {rw_conf} 2>/dev/null || :", // NOTE: the OR part is here because the command is not applicable sometimes, and would stop everything else from executing
            hdfs_conf = HDFS_CONFIG_DIRECTORY,
            rw_conf = RW_CONFIG_DIRECTORY,
        ));

        commands.extend([
            format!("config-utils template {RW_CONFIG_DIRECTORY}/runtime.properties",),
            format!("if test -f {RW_CONFIG_DIRECTORY}/core-site.xml; then config-utils template {RW_CONFIG_DIRECTORY}/core-site.xml; fi",),
            format!("if test -f {RW_CONFIG_DIRECTORY}/hdfs-site.xml; then config-utils template {RW_CONFIG_DIRECTORY}/hdfs-site.xml; fi",),
        ]);

        commands
    }

    pub fn main_container_start_command(&self) -> String {
        // We need to store the druid process PID for the graceful shutdown lifecycle pre stop hook.
        formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}
            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &
            /stackable/druid/bin/run-druid {process_name} {RW_CONFIG_DIRECTORY} &
            echo \"$!\" >> /tmp/DRUID_PID
            wait_for_termination $(cat /tmp/DRUID_PID)
            {create_vector_shutdown_file_command}
            ",
                process_name = self.get_process_name(),
        remove_vector_shutdown_file_command =
            remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        create_vector_shutdown_file_command =
            create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }
    }

    pub fn listener_class_name(&self, druid: &v1alpha1::DruidCluster) -> Option<String> {
        match self {
            Self::Broker => Some(druid.spec.brokers.role_config.listener_class.to_owned()),
            Self::Coordinator => Some(
                druid
                    .spec
                    .coordinators
                    .role_config
                    .listener_class
                    .to_owned(),
            ),
            Self::Router => Some(druid.spec.routers.role_config.listener_class.to_owned()),
            Self::Historical | Self::MiddleManager => None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConnectionSpec {
    /// The database type. Supported values are: `derby`, `mysql` and `postgres`.
    /// Note that a Derby database created locally in the container is not persisted!
    /// Derby is not suitable for production use.
    pub db_type: DbType,
    /// The connect string for the database, for Postgres this could look like:
    /// `jdbc:postgresql://postgresql-druid/druid`
    pub conn_string: String,
    /// The host, i.e. `postgresql-druid`.
    pub host: String,
    /// The port, i.e. 5432
    pub port: u16,
    /// A reference to a Secret containing the database credentials.
    /// The Secret needs to contain the keys `username` and `password`.
    pub credentials_secret: Option<String>,
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
    /// [The HDFS deep storage configuration](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/deep-storage#_hdfs).
    /// You can run an HDFS cluster with the [Stackable operator for Apache HDFS](DOCS_BASE_URL_PLACEHOLDER/hdfs/).
    #[serde(rename = "hdfs")]
    #[strum(serialize = "hdfs")]
    Hdfs(HdfsDeepStorageSpec),
    /// [The S3 deep storage configuration](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/deep-storage#_s3).
    #[strum(serialize = "s3")]
    S3(S3DeepStorageSpec),
}

impl DeepStorageSpec {
    pub fn is_hdfs(&self) -> bool {
        matches!(self, DeepStorageSpec::Hdfs(_))
    }

    pub fn is_s3(&self) -> bool {
        matches!(self, DeepStorageSpec::S3(_))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsDeepStorageSpec {
    /// The [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery)
    /// for the HDFS instance. When running an HDFS cluster with the Stackable operator, the operator
    /// will create this ConfigMap for you. It has the same name as your HDFSCluster resource.
    pub config_map_name: String,
    /// The directory inside of HDFS where Druid should store its data.
    pub directory: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3DeepStorageSpec {
    /// The S3 bucket to use for deep storage. Can either be defined inline or as a reference,
    /// read the [S3 bucket docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3) to learn more.
    pub bucket: s3::v1alpha1::InlineBucketOrReference,

    /// The `baseKey` is similar to the `directory` in HDFS; it is the root key at which
    /// Druid will create its deep storage. If no `baseKey` is given, the bucket root
    /// will be used.
    pub base_key: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestionSpec {
    /// Druid supports ingesting data from S3 buckets where the bucket name is specified in the ingestion task.
    /// However, the S3 connection has to be specified in advance and only a single S3 connection is supported.
    /// S3 connections can either be specified `inline` or as a `reference`.
    /// Read the [S3 resource concept docs](DOCS_BASE_URL_PLACEHOLDER/concepts/s3) to learn more.
    pub s3connection: Option<s3::v1alpha1::InlineConnectionOrReference>,
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
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
    /// The time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`.
    /// Read more about graceful shutdown in the
    /// [graceful shutdown documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/operations/graceful-shutdown).
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,

    /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
    /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
    #[fragment_attrs(serde(default))]
    pub requested_secret_lifetime: Option<Duration>,
}

impl BrokerConfig {
    fn default_config(
        cluster_name: &str,
        role: &DruidRole,
        deep_storage: &DeepStorageSpec,
    ) -> BrokerConfigFragment {
        BrokerConfigFragment {
            resources: resource::BROKER_RESOURCES.to_owned(),
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, deep_storage),
            graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
            requested_secret_lifetime: Some(DEFAULT_BROKER_SECRET_LIFETIME),
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
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
    /// The time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`.
    /// Read more about graceful shutdown in the
    /// [graceful shutdown documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/operations/graceful-shutdown).
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,

    /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
    /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
    #[fragment_attrs(serde(default))]
    pub requested_secret_lifetime: Option<Duration>,
}

impl CoordinatorConfig {
    fn default_config(
        cluster_name: &str,
        role: &DruidRole,
        deep_storage: &DeepStorageSpec,
    ) -> CoordinatorConfigFragment {
        CoordinatorConfigFragment {
            resources: resource::COORDINATOR_RESOURCES.to_owned(),
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, deep_storage),
            graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
            requested_secret_lifetime: Some(DEFAULT_COORDINATOR_SECRET_LIFETIME),
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
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
    /// The time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`.
    /// Read more about graceful shutdown in the
    /// [graceful shutdown documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/operations/graceful-shutdown).
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,

    /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
    /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
    #[fragment_attrs(serde(default))]
    pub requested_secret_lifetime: Option<Duration>,
}

impl MiddleManagerConfig {
    fn default_config(
        cluster_name: &str,
        role: &DruidRole,
        deep_storage: &DeepStorageSpec,
    ) -> MiddleManagerConfigFragment {
        MiddleManagerConfigFragment {
            resources: resource::MIDDLE_MANAGER_RESOURCES.to_owned(),
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, deep_storage),
            graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
            requested_secret_lifetime: Some(DEFAULT_MIDDLE_SECRET_LIFETIME),
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
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
    /// The time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`.
    /// Read more about graceful shutdown in the
    /// [graceful shutdown documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/operations/graceful-shutdown).
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,

    /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
    /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
    #[fragment_attrs(serde(default))]
    pub requested_secret_lifetime: Option<Duration>,
}

impl RouterConfig {
    fn default_config(
        cluster_name: &str,
        role: &DruidRole,
        deep_storage: &DeepStorageSpec,
    ) -> RouterConfigFragment {
        RouterConfigFragment {
            resources: resource::ROUTER_RESOURCES.to_owned(),
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, deep_storage),
            graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
            requested_secret_lifetime: Some(DEFAULT_ROUTER_SECRET_LIFETIME),
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
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
    /// The time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`.
    /// Read more about graceful shutdown in the
    /// [graceful shutdown documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/operations/graceful-shutdown).
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,

    /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
    /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
    #[fragment_attrs(serde(default))]
    pub requested_secret_lifetime: Option<Duration>,
}

impl HistoricalConfig {
    fn default_config(
        cluster_name: &str,
        role: &DruidRole,
        deep_storage: &DeepStorageSpec,
    ) -> HistoricalConfigFragment {
        HistoricalConfigFragment {
            resources: resource::HISTORICAL_RESOURCES.to_owned(),
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, deep_storage),
            graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
            requested_secret_lifetime: Some(DEFAULT_HISTORICAL_SECRET_LIFETIME),
        }
    }
}

impl Configuration for BrokerConfigFragment {
    type Configurable = v1alpha1::DruidCluster;

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
    type Configurable = v1alpha1::DruidCluster;

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
    type Configurable = v1alpha1::DruidCluster;

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
    type Configurable = v1alpha1::DruidCluster;

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
                "-Djavax.net.ssl.trustStoreType=pkcs12".to_owned(),
            ])),
        );
        Ok(result)
    }
}

impl Configuration for CoordinatorConfigFragment {
    type Configurable = v1alpha1::DruidCluster;

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
pub struct DruidClusterStatus {
    #[serde(default)]
    pub conditions: Vec<ClusterCondition>,
}

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

fn extract_role_from_role_config<T>(
    fragment: Role<T::Fragment, DruidRoleConfig, JavaCommonConfig>,
) -> Role<T::Fragment, GenericRoleConfig, JavaCommonConfig>
where
    T: FromFragment,
    T::Fragment: Clone + Merge,
{
    Role {
        config: CommonConfiguration {
            config: fragment.config.config,
            config_overrides: fragment.config.config_overrides,
            env_overrides: fragment.config.env_overrides,
            cli_overrides: fragment.config.cli_overrides,
            pod_overrides: fragment.config.pod_overrides,
            product_specific_common_config: fragment.config.product_specific_common_config,
        },
        role_config: fragment.role_config.common,
        role_groups: fragment
            .role_groups
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    RoleGroup {
                        config: CommonConfiguration {
                            config: v.config.config,
                            config_overrides: v.config.config_overrides,
                            env_overrides: v.config.env_overrides,
                            cli_overrides: v.config.cli_overrides,
                            pod_overrides: v.config.pod_overrides,
                            product_specific_common_config: v.config.product_specific_common_config,
                        },
                        replicas: v.replicas,
                    },
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
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
