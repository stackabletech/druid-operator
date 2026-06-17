use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use indoc::formatdoc;
use security::add_cert_to_jvm_trust_store_cmd;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::{
        affinity::StackableAffinity,
        cluster_operation::ClusterOperation,
        product_image_selection::ProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    config::{
        fragment::{Fragment, ValidationError},
        merge::Merge,
    },
    crd::{
        authentication::{core, oidc},
        s3,
    },
    deep_merger::ObjectOverrides,
    k8s_openapi::api::core::v1::Volume,
    kube::{CustomResource, ResourceExt},
    product_logging::{
        self,
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
        spec::Logging,
    },
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    utils::{COMMON_BASH_TRAP_FUNCTIONS, crds::raw_object_list_schema},
    v2::{
        builder::pod::container::{EnvVarName, EnvVarSet},
        config_overrides::KeyValueConfigOverrides,
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, VectorContainerLogConfig,
            validate_logging_configuration_for_container,
        },
        role_utils::{JavaCommonConfig, RoleGroupConfig, with_validated_config},
        types::{
            kubernetes::{ConfigMapName, ListenerClassName},
            operator::{RoleGroupName, RoleName},
        },
    },
    versioned::versioned,
};
use strum::{Display, EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};

use crate::crd::{
    affinity::get_affinity,
    authorization::DruidAuthorization,
    database::MetadataDatabaseConnection,
    resource::RoleResource,
    tls::{DruidTls, default_druid_tls},
};

pub mod affinity;
pub mod authentication;
pub mod authorization;
pub mod database;
pub mod memory;
pub mod resource;
pub mod security;
pub mod storage;
pub mod tls;

pub const APP_NAME: &str = "druid";
pub const OPERATOR_NAME: &str = "druid.stackable.tech";

// config directories
pub const DRUID_CONFIG_DIRECTORY: &str = "/stackable/config";
pub const HDFS_CONFIG_DIRECTORY: &str = "/stackable/hdfs";
pub const LOG_CONFIG_DIRECTORY: &str = "/stackable/log_config";
pub const RW_CONFIG_DIRECTORY: &str = "/stackable/rwconfig";

// store directories
pub const STACKABLE_TRUST_STORE: &str = "/stackable/truststore.p12";
pub const STACKABLE_TRUST_STORE_PASSWORD: &str = "changeit";
pub const STACKABLE_TRUST_STORE_TYPE: &str = "pkcs12";

pub const PROP_SEGMENT_CACHE_LOCATIONS: &str = "druid.segmentCache.locations";

/////////////////////////////
//    CONFIG PROPERTIES    //
/////////////////////////////
pub const METRICS_PORT_NAME: &str = "metrics";
pub const METRICS_PORT: u16 = 9090;

pub const COOKIE_PASSPHRASE_ENV: &str = "OIDC_COOKIE_PASSPHRASE";

/// Formats a Druid [dynamic config](https://druid.apache.org/docs/latest/operations/dynamic-config-provider)
/// reference to an environment variable, i.e. `${env:NAME}`.
pub(crate) fn env_var_reference(name: impl std::fmt::Display) -> String {
    format!("${{env:{name}}}")
}

/// Formats a Druid [dynamic config](https://druid.apache.org/docs/latest/operations/dynamic-config-provider)
/// reference to the UTF-8 contents of a file, i.e. `${file:UTF-8:PATH}`.
pub(crate) fn file_reference(path: impl std::fmt::Display) -> String {
    format!("${{file:UTF-8:{path}}}")
}

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

/// Typed config override strategies for Druid config files.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfigOverrides {
    /// Overrides for the `runtime.properties` file.
    // File name defined in [`crate::controller::build::properties::ConfigFileName`]
    #[serde(default, rename = "runtime.properties")]
    pub runtime_properties: KeyValueConfigOverrides,

    /// Overrides for the `jvm.config` file.
    // File name defined in [`crate::controller::build::properties::ConfigFileName`]
    #[serde(default, rename = "jvm.config")]
    pub jvm_config: KeyValueConfigOverrides,

    /// Overrides for the `security.properties` file.
    // File name defined in [`crate::controller::build::properties::ConfigFileName`]
    #[serde(default, rename = "security.properties")]
    pub security_properties: KeyValueConfigOverrides,
}

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

    #[snafu(display("failed to merge and validate config for role group {role_group:?}"))]
    FailedToMergeRoleGroupConfig {
        source: ValidationError,
        role_group: String,
    },

    #[snafu(display("invalid environment variable override name in role group {role_group:?}"))]
    ParseEnvVarName {
        source: stackable_operator::v2::builder::pod::container::Error,
        role_group: String,
    },

    #[snafu(display("invalid role group name {role_group:?}"))]
    ParseRoleGroupName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
        role_group: String,
    },

    #[snafu(display("failed to validate container log configuration"))]
    ValidateLoggingConfig {
        source: stackable_operator::v2::product_logging::framework::Error,
    },

    #[snafu(display(
        "the Vector agent is enabled but the Vector aggregator ConfigMap name is missing"
    ))]
    MissingVectorAggregatorConfigMapName,
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
        pub brokers:
            Role<BrokerConfigFragment, DruidConfigOverrides, DruidRoleConfig, JavaCommonConfig>,

        // no doc - docs provided by the struct.
        pub coordinators: Role<
            CoordinatorConfigFragment,
            DruidConfigOverrides,
            DruidRoleConfig,
            JavaCommonConfig,
        >,

        // no doc - docs provided by the struct.
        pub historicals: Role<
            HistoricalConfigFragment,
            DruidConfigOverrides,
            GenericRoleConfig,
            JavaCommonConfig,
        >,

        // no doc - docs provided by the struct.
        pub middle_managers: Role<
            MiddleManagerConfigFragment,
            DruidConfigOverrides,
            GenericRoleConfig,
            JavaCommonConfig,
        >,

        // no doc - docs provided by the struct.
        pub routers:
            Role<RouterConfigFragment, DruidConfigOverrides, DruidRoleConfig, JavaCommonConfig>,

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
        pub authentication: Vec<
            core::v1alpha1::ClientAuthenticationDetails<
                oidc::v1alpha1::ClientAuthenticationMethodOption,
            >,
        >,

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
        pub metadata_database: MetadataDatabaseConnection,

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
        pub zookeeper_config_map_name: ConfigMapName,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<ConfigMapName>,

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
        pub generic: GenericRoleConfig,

        #[serde(default = "druid_default_listener_class")]
        pub listener_class: ListenerClassName,
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

    /// Merges and validates all role groups of the given role. Invoked from the validate step
    /// (`controller::validate`).
    ///
    /// All four override categories (config / env / cli / pod) are merged by
    /// [`with_validated_config`] (role group wins over role); the typed per-role config is then
    /// erased to the shared [`ValidatedDruidConfig`] view consumed by the build step.
    ///
    /// This lives in `crate::crd` and is a `macro_rules!` rather than a generic function on purpose: the erasure
    /// reads the per-role configs' private `resources` field and calls their private
    /// `default_config`, and the five roles wrap *different* `resources` types into different
    /// [`RoleResource`] variants.
    pub fn merged_role(
        &self,
        role: &DruidRole,
    ) -> Result<BTreeMap<RoleGroupName, DruidRoleGroupConfig>, Error> {
        let deep_storage = &self.spec.cluster_config.deep_storage;
        let name = self.name_any();

        // The Vector aggregator discovery ConfigMap name (a typed `ConfigMapName`, so an invalid
        // name is already rejected at deserialization). It is only required when the Vector agent
        // is enabled for a role group.
        let vector_aggregator_config_map_name = self
            .spec
            .cluster_config
            .vector_aggregator_config_map_name
            .clone();

        // All roles erase to an identical `ValidatedDruidConfig`; only the typed config, the role
        // config type and the `RoleResource` variant (historicals carry typed storage) differ.
        macro_rules! merged_role {
            ($field:ident, $config:ty, $role_config:ty, $resource:path) => {{
                let typed_role = &self.spec.$field;
                let default_config = <$config>::default_config(&name, role, deep_storage);
                let mut groups = BTreeMap::new();
                for (rg_name, rg) in &typed_role.role_groups {
                    let validated = with_validated_config::<
                        $config,
                        JavaCommonConfig,
                        _,
                        $role_config,
                        DruidConfigOverrides,
                    >(rg, typed_role, &default_config)
                    .with_context(|_| FailedToMergeRoleGroupConfigSnafu {
                        role_group: rg_name.clone(),
                    })?;
                    let common = ValidatedDruidConfig {
                        resources: $resource(validated.config.config.resources),
                        logging: validate_logging(
                            &validated.config.config.logging,
                            &vector_aggregator_config_map_name,
                        )?,
                        affinity: validated.config.config.affinity,
                        graceful_shutdown_timeout: validated
                            .config
                            .config
                            .graceful_shutdown_timeout,
                        requested_secret_lifetime: validated
                            .config
                            .config
                            .requested_secret_lifetime
                            .context(MissingSecretLifetimeSnafu)?,
                    };
                    // Upstream returns env overrides as a `HashMap`; the build step consumes an
                    // `EnvVarSet`. Convert here, validating each name. (Role/role-group precedence
                    // is already resolved by `with_validated_config`.)
                    let mut env_overrides = EnvVarSet::new();
                    for (name, value) in validated.config.env_overrides {
                        env_overrides = env_overrides.with_value(
                            &EnvVarName::from_str(&name).with_context(|_| {
                                ParseEnvVarNameSnafu {
                                    role_group: rg_name.clone(),
                                }
                            })?,
                            value,
                        );
                    }
                    let role_group_name = RoleGroupName::from_str(rg_name).with_context(|_| {
                        ParseRoleGroupNameSnafu {
                            role_group: rg_name.clone(),
                        }
                    })?;
                    groups.insert(
                        role_group_name,
                        DruidRoleGroupConfig {
                            replicas: validated.replicas,
                            config: common,
                            config_overrides: validated.config.config_overrides,
                            env_overrides,
                            cli_overrides: validated.config.cli_overrides,
                            pod_overrides: validated.config.pod_overrides,
                            product_specific_common_config: validated
                                .config
                                .product_specific_common_config,
                        },
                    );
                }
                groups
            }};
        }

        let groups = match role {
            DruidRole::Broker => {
                merged_role!(
                    brokers,
                    BrokerConfig,
                    v1alpha1::DruidRoleConfig,
                    RoleResource::Druid
                )
            }
            DruidRole::Coordinator => merged_role!(
                coordinators,
                CoordinatorConfig,
                v1alpha1::DruidRoleConfig,
                RoleResource::Druid
            ),
            DruidRole::Historical => merged_role!(
                historicals,
                HistoricalConfig,
                GenericRoleConfig,
                RoleResource::Historical
            ),
            DruidRole::MiddleManager => merged_role!(
                middle_managers,
                MiddleManagerConfig,
                GenericRoleConfig,
                RoleResource::Druid
            ),
            DruidRole::Router => {
                merged_role!(
                    routers,
                    RouterConfig,
                    v1alpha1::DruidRoleConfig,
                    RoleResource::Druid
                )
            }
        };
        Ok(groups)
    }

    pub fn generic_role_config(&self, role: &DruidRole) -> &GenericRoleConfig {
        match role {
            DruidRole::Broker => &self.spec.brokers.role_config.generic,
            DruidRole::Coordinator => &self.spec.coordinators.role_config.generic,
            DruidRole::Historical => &self.spec.historicals.role_config,
            DruidRole::MiddleManager => &self.spec.middle_managers.role_config,
            DruidRole::Router => &self.spec.routers.role_config.generic,
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

/// The validated, merged Druid config shared by all role groups (the typed per-role config erased
/// to a single view). Mirrors the opensearch-operator's `ValidatedOpenSearchConfig`.
#[derive(Clone)]
pub struct ValidatedDruidConfig {
    pub affinity: StackableAffinity,
    pub graceful_shutdown_timeout: Option<Duration>,
    pub logging: ValidatedLogging,
    pub requested_secret_lifetime: Duration,
    pub resources: RoleResource,
}

/// Validated logging configuration for the Druid, Prepare (init) and (optional) Vector containers.
///
/// Produced up-front by [`validate_logging`] (mirroring the hive-/opensearch-operator) so that an
/// invalid custom log ConfigMap name or a missing Vector aggregator discovery ConfigMap name fails
/// reconciliation during validation rather than at resource-build time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLogging {
    pub druid_container: ValidatedContainerLogConfigChoice,
    pub prepare_container: ValidatedContainerLogConfigChoice,
    pub vector_container: Option<VectorContainerLogConfig>,
    pub enable_vector_agent: bool,
}

/// Validates the logging configuration for the Druid, Prepare and (optional) Vector containers.
///
/// `vector_aggregator_config_map_name` is the discovery ConfigMap name of the Vector aggregator;
/// it is required (and was validated up-front) only when the Vector agent is enabled.
fn validate_logging(
    logging: &Logging<Container>,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<ValidatedLogging, Error> {
    let druid_container = validate_logging_configuration_for_container(logging, &Container::Druid)
        .context(ValidateLoggingConfigSnafu)?;
    let prepare_container =
        validate_logging_configuration_for_container(logging, &Container::Prepare)
            .context(ValidateLoggingConfigSnafu)?;

    let vector_container = if logging.enable_vector_agent {
        let vector_aggregator_config_map_name = vector_aggregator_config_map_name
            .clone()
            .context(MissingVectorAggregatorConfigMapNameSnafu)?;
        Some(VectorContainerLogConfig {
            log_config: validate_logging_configuration_for_container(logging, &Container::Vector)
                .context(ValidateLoggingConfigSnafu)?,
            vector_aggregator_config_map_name,
        })
    } else {
        None
    };

    Ok(ValidatedLogging {
        druid_container,
        prepare_container,
        vector_container,
        enable_vector_agent: logging.enable_vector_agent,
    })
}

/// A validated, merged role-group config.
///
/// This is the upstream [`stackable_operator::v2::role_utils::RoleGroupConfig`] (config plus the
/// four merged override categories, role group winning over role), with the typed per-role config
/// erased to the shared [`ValidatedDruidConfig`] view. The merged JVM argument overrides live in
/// `product_specific_common_config`; the rendered per-file configs (runtime.properties /
/// security.properties / jvm.config) are produced later, in the config-map build step.
///
/// The StatefulSet replicas come from [`RoleGroupConfig::replicas`], which is optional: an
/// unspecified count is passed through as `None` to the StatefulSet so a HorizontalPodAutoscaler
/// can own the replica count.
pub type DruidRoleGroupConfig =
    RoleGroupConfig<ValidatedDruidConfig, JavaCommonConfig, DruidConfigOverrides>;

impl Default for v1alpha1::DruidRoleConfig {
    fn default() -> Self {
        v1alpha1::DruidRoleConfig {
            listener_class: druid_default_listener_class(),
            generic: Default::default(),
        }
    }
}

fn druid_default_listener_class() -> ListenerClassName {
    ListenerClassName::from_str("cluster-internal").expect("a valid listener class name")
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
    Ord,
    PartialEq,
    PartialOrd,
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
    /// Returns the typed role name used for Kubernetes labels and selectors.
    pub fn to_role_name(&self) -> RoleName {
        RoleName::from_str(&self.to_string())
            .expect("a DruidRole always serializes to a valid role name")
    }

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
    fn default_graceful_shutdown_timeout(&self) -> Duration {
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

        if let Some(s3) = s3
            && let Some(ca_cert_file) = s3.tls.tls_ca_cert_mount_path()
        {
            commands.extend(add_cert_to_jvm_trust_store_cmd(&ca_cert_file));
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

    pub fn listener_class_name(&self, druid: &v1alpha1::DruidCluster) -> Option<ListenerClassName> {
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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HdfsDeepStorageSpec {
    /// The [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery)
    /// for the HDFS instance. When running an HDFS cluster with the Stackable operator, the operator
    /// will create this ConfigMap for you. It has the same name as your HDFSCluster resource.
    pub config_map_name: ConfigMapName,
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

/// Generates a per-role config struct and its `default_config`. The four non-historical roles share
/// an identical shape; only the storage type, default [`resource`] profile and default secret
/// lifetime differ. The `Fragment` type (named `<name>Fragment` by the [`Fragment`] derive) is
/// passed explicitly because `macro_rules!` cannot synthesize identifiers.
macro_rules! role_group_config {
    ($name:ident, $fragment:ident, $storage:ty, $resources:expr, $secret_lifetime:expr $(,)?) => {
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
        pub struct $name {
            #[fragment_attrs(serde(default))]
            resources: Resources<$storage, NoRuntimeLimits>,
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

        impl $name {
            fn default_config(
                cluster_name: &str,
                role: &DruidRole,
                deep_storage: &DeepStorageSpec,
            ) -> $fragment {
                $fragment {
                    resources: $resources.to_owned(),
                    logging: product_logging::spec::default_logging(),
                    affinity: get_affinity(cluster_name, role, deep_storage),
                    graceful_shutdown_timeout: Some(role.default_graceful_shutdown_timeout()),
                    requested_secret_lifetime: Some($secret_lifetime),
                }
            }
        }
    };
}

role_group_config!(
    BrokerConfig,
    BrokerConfigFragment,
    storage::DruidStorage,
    resource::BROKER_RESOURCES,
    DEFAULT_BROKER_SECRET_LIFETIME,
);

role_group_config!(
    CoordinatorConfig,
    CoordinatorConfigFragment,
    storage::DruidStorage,
    resource::COORDINATOR_RESOURCES,
    DEFAULT_COORDINATOR_SECRET_LIFETIME,
);

role_group_config!(
    MiddleManagerConfig,
    MiddleManagerConfigFragment,
    storage::DruidStorage,
    resource::MIDDLE_MANAGER_RESOURCES,
    DEFAULT_MIDDLE_SECRET_LIFETIME,
);

role_group_config!(
    RouterConfig,
    RouterConfigFragment,
    storage::DruidStorage,
    resource::ROUTER_RESOURCES,
    DEFAULT_ROUTER_SECRET_LIFETIME,
);

role_group_config!(
    HistoricalConfig,
    HistoricalConfigFragment,
    storage::HistoricalStorage,
    resource::HISTORICAL_RESOURCES,
    DEFAULT_HISTORICAL_SECRET_LIFETIME,
);

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

#[cfg(test)]
mod tests {
    use stackable_operator::versioned::test_utils::RoundtripTestData;

    use crate::crd::v1alpha1;

    impl RoundtripTestData for v1alpha1::DruidClusterSpec {
        fn roundtrip_test_data() -> Vec<Self> {
            stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {"
              - image:
                  productVersion: 30.0.0
                  pullPolicy: IfNotPresent
                clusterOperation:
                  stopped: false
                  reconciliationPaused: false
                clusterConfig:
                  metadataDatabase:
                    postgresql:
                      host: druid-postgresql
                      database: druid
                      credentialsSecretName: mySecret
                  deepStorage:
                    hdfs:
                      configMapName: simple-hdfs
                      directory: /druid
                  ingestion:
                    s3connection:
                      inline:
                        host: s3-de-central.profitbricks.com
                        credentials:
                          secretClass: s3-credentials-class
                  zookeeperConfigMapName: simple-druid-znode
                  authorization:
                    opa:
                      configMapName: test-opa
                      package: druid
                  vectorAggregatorConfigMapName: vector-aggregator-discovery
                brokers:
                  config:
                    gracefulShutdownTimeout: 1s
                    logging:
                      enableVectorAgent: true
                      containers:
                        druid:
                          console:
                            level: INFO
                          file:
                            level: INFO
                          loggers:
                            ROOT:
                              level: INFO
                  configOverrides:
                    runtime.properties: &runtime-properties
                      druid.foo: bar
                  roleGroups:
                    default:
                      replicas: 1
                coordinators:
                  roleGroups:
                    default:
                      replicas: 1
                historicals:
                  roleGroups:
                    default:
                      replicas: 1
                middleManagers:
                  roleGroups:
                    default:
                      replicas: 1
                routers:
                  roleGroups:
                    default:
                      replicas: 1
        "})
            .expect("Failed to parse DruidClusterSpec YAML")
        }
    }
}
