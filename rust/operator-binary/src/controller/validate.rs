//! The validate step in the DruidCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedCluster`], consumed by the rest of `reconcile_druid`.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use serde::Serialize;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::{
        pdb::PdbConfig,
        product_image_selection::{self, ResolvedProductImage},
    },
    config::{
        fragment::{FromFragment, ValidationError},
        merge::Merge,
    },
    crd::{listener::v1alpha1::Listener, s3},
    database_connections::drivers::jdbc::{JdbcDatabaseConnection, JdbcDatabaseConnectionDetails},
    k8s_openapi::api::core::v1::{ConfigMap, Secret, Volume},
    kube::{Resource, ResourceExt, api::ObjectMeta},
    product_logging::spec::Logging,
    role_utils::GenericRoleConfig,
    schemars::JsonSchema,
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        product_logging::framework::{
            ValidatedContainerLogConfigChoice, VectorContainerLogConfig,
            validate_logging_configuration_for_container,
        },
        role_group_utils::ResourceNames,
        role_utils::{
            self, JavaCommonConfig, Role, RoleGroup, RoleGroupConfig, with_validated_config,
        },
        types::{
            kubernetes::{ConfigMapName, ListenerClassName, NamespaceName, Uid},
            operator::{ClusterName, ProductVersion, RoleGroupName},
        },
    },
};

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::{PRODUCT_NAME, dereference::DereferencedObjects},
    crd::{
        BrokerConfig, BrokerConfigFragment, Container, CoordinatorConfig,
        CoordinatorConfigFragment, DeepStorageSpec, DruidConfigOverrides, DruidRole,
        HistoricalConfig, HistoricalConfigFragment, MiddleManagerConfig,
        MiddleManagerConfigFragment, RouterConfig, RouterConfigFragment,
        authentication::AuthenticationClassesResolved, database::MetadataDatabaseConnection,
        security::DruidTlsSecurity, v1alpha1,
    },
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display(
        "failed to merge and validate the config of {role} role group {role_group:?}"
    ))]
    ValidateRoleGroupConfig {
        source: ValidationError,
        role: DruidRole,
        role_group: String,
    },

    #[snafu(display("invalid {role} role group name {role_group:?}"))]
    ParseRoleGroupName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
        role: DruidRole,
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

    #[snafu(display("failed to determine the cluster's name, namespace, or uid"))]
    ClusterIdentity {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("invalid metadata database connection"))]
    InvalidMetadataDatabaseConnection {
        source: stackable_operator::database_connections::Error,
    },

    #[snafu(display("failed to resolve authentication classes"))]
    ResolveAuthenticationClasses {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display(
        "two differing S3 connections were given (ingestion and deep storage), this is unsupported by Druid"
    ))]
    IncompatibleS3Connections,
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Validated logging configuration for the Druid, Prepare (init) and (optional) Vector containers.
///
/// Produced up-front by [`validate_logging`] so that an invalid custom log ConfigMap name or a
/// missing Vector aggregator discovery ConfigMap name fails reconciliation during validation
/// rather than at resource-build time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLogging {
    pub druid_container: ValidatedContainerLogConfigChoice,
    pub prepare_container: ValidatedContainerLogConfigChoice,
    pub vector_container: Option<VectorContainerLogConfig>,
    pub enable_vector_agent: bool,
}

/// A Coordinator role group's validated, merged config together with its validated logging.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCoordinatorConfig {
    pub config: CoordinatorConfig,
    /// Validated logging configuration (derived from `config.logging` during validation).
    pub logging: ValidatedLogging,
}

/// A Broker role group's validated, merged config together with its validated logging.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedBrokerConfig {
    pub config: BrokerConfig,
    /// Validated logging configuration (derived from `config.logging` during validation).
    pub logging: ValidatedLogging,
}

/// A Historical role group's validated, merged config together with its validated logging.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedHistoricalConfig {
    pub config: HistoricalConfig,
    /// Validated logging configuration (derived from `config.logging` during validation).
    pub logging: ValidatedLogging,
}

/// A MiddleManager role group's validated, merged config together with its validated logging.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMiddleManagerConfig {
    pub config: MiddleManagerConfig,
    /// Validated logging configuration (derived from `config.logging` during validation).
    pub logging: ValidatedLogging,
}

/// A Router role group's validated, merged config together with its validated logging.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedRouterConfig {
    pub config: RouterConfig,
    /// Validated logging configuration (derived from `config.logging` during validation).
    pub logging: ValidatedLogging,
}

/// The [`RoleGroupConfig`] of one Coordinator role group.
pub type CoordinatorRoleGroupConfig =
    RoleGroupConfig<ValidatedCoordinatorConfig, JavaCommonConfig, DruidConfigOverrides>;

/// The [`RoleGroupConfig`] of one Broker role group.
pub type BrokerRoleGroupConfig =
    RoleGroupConfig<ValidatedBrokerConfig, JavaCommonConfig, DruidConfigOverrides>;

/// The [`RoleGroupConfig`] of one Historical role group.
pub type HistoricalRoleGroupConfig =
    RoleGroupConfig<ValidatedHistoricalConfig, JavaCommonConfig, DruidConfigOverrides>;

/// The [`RoleGroupConfig`] of one MiddleManager role group.
pub type MiddleManagerRoleGroupConfig =
    RoleGroupConfig<ValidatedMiddleManagerConfig, JavaCommonConfig, DruidConfigOverrides>;

/// The [`RoleGroupConfig`] of one Router role group.
pub type RouterRoleGroupConfig =
    RoleGroupConfig<ValidatedRouterConfig, JavaCommonConfig, DruidConfigOverrides>;

/// Cluster-wide resolved fields that are not role/rolegroup specific.
pub struct ValidatedClusterConfig {
    pub zookeeper_connection_string: String,
    pub opa_connection_string: Option<String>,
    pub s3_connection: Option<s3::v1alpha1::ConnectionSpec>,
    pub deep_storage_bucket_name: Option<String>,
    pub druid_tls_security: DruidTlsSecurity,
    pub druid_auth_config: Option<DruidAuthenticationConfig>,
    /// The configured metadata database, carried so the build step can derive the
    /// `druid.metadata.storage.type` value and the metadata-storage extension.
    pub metadata_database: MetadataDatabaseConnection,
    /// User-supplied additional `druid.extensions.loadList` entries, carried so the build step can
    /// assemble the full extension list.
    pub additional_extensions: HashSet<String>,
    /// The JDBC connection details (URL plus credential env vars) for the metadata database.
    pub metadata_db_connection: JdbcDatabaseConnectionDetails,
    /// The deep-storage spec, carried so the build step can derive the cluster-level
    /// `runtime.properties` (deep storage type / directory / base key) without the raw
    /// `DruidCluster`.
    pub deep_storage: DeepStorageSpec,
    /// User-supplied extra volumes, mounted into every container, carried so the build step does
    /// not read the raw `DruidCluster`.
    pub extra_volumes: Vec<Volume>,
}

impl ValidatedClusterConfig {
    /// Whether the cluster uses S3, for deep storage or ingestion.
    pub fn uses_s3(&self) -> bool {
        self.s3_connection.is_some()
    }
}

/// The role-level config of a role that exposes a group Listener: Broker, Coordinator and Router
/// ([`v1alpha1::DruidRoleConfig`] in the CRD).
#[derive(Clone, Debug)]
pub struct ValidatedListenerRoleConfig {
    pub pdb: PdbConfig,
    pub listener_class: ListenerClassName,
}

/// The role-level config of a role without a Listener: Historical and MiddleManager
/// ([`GenericRoleConfig`] in the CRD).
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: PdbConfig,
}

/// Synchronous inputs the rest of `reconcile_druid` needs after dereferencing.
///
/// Every Druid role is required by the CRD, so every role has its role-level config and its map
/// of role groups; the fields are in [`DruidRole`] variant order.
pub struct ValidatedCluster {
    /// Mirrors `name`/`namespace`/`uid` below so that `ValidatedCluster` can implement
    /// [`Resource`] and be passed directly to the metadata/owner-reference builders.
    metadata: ObjectMeta,
    pub name: ClusterName,
    pub namespace: NamespaceName,
    pub uid: Uid,
    pub image: ResolvedProductImage,
    /// The product version as a valid label value, used for the recommended
    /// `app.kubernetes.io/version` label. Parsed once from the resolved image's app version label
    /// value, so the build steps don't re-parse it per resource.
    pub product_version: ProductVersion,
    pub cluster_config: ValidatedClusterConfig,
    /// The Coordinator role-level config.
    pub coordinator_config: ValidatedListenerRoleConfig,
    /// The validated config of every Coordinator role group, keyed by role group name.
    pub coordinator_role_group_configs: BTreeMap<RoleGroupName, CoordinatorRoleGroupConfig>,
    /// The Broker role-level config.
    pub broker_config: ValidatedListenerRoleConfig,
    /// The validated config of every Broker role group, keyed by role group name.
    pub broker_role_group_configs: BTreeMap<RoleGroupName, BrokerRoleGroupConfig>,
    /// The Historical role-level config.
    pub historical_config: ValidatedRoleConfig,
    /// The validated config of every Historical role group, keyed by role group name.
    pub historical_role_group_configs: BTreeMap<RoleGroupName, HistoricalRoleGroupConfig>,
    /// The MiddleManager role-level config.
    pub middle_manager_config: ValidatedRoleConfig,
    /// The validated config of every MiddleManager role group, keyed by role group name.
    pub middle_manager_role_group_configs: BTreeMap<RoleGroupName, MiddleManagerRoleGroupConfig>,
    /// The Router role-level config.
    pub router_config: ValidatedListenerRoleConfig,
    /// The validated config of every Router role group, keyed by role group name.
    pub router_role_group_configs: BTreeMap<RoleGroupName, RouterRoleGroupConfig>,
    pub router_listener: Option<Listener>,
    pub internal_secret: Option<Secret>,
    pub discovery_config_map: Option<ConfigMap>,
}

impl ValidatedCluster {
    /// The metadata that mirrors the cluster's name, namespace and uid, so that
    /// `ValidatedCluster` can implement [`Resource`] and stand in for the raw `DruidCluster`
    /// when building child-object metadata and owner references.
    pub(crate) fn object_meta(
        name: &ClusterName,
        namespace: &NamespaceName,
        uid: &Uid,
    ) -> ObjectMeta {
        ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            uid: Some(uid.to_string()),
            ..ObjectMeta::default()
        }
    }

    /// The product version as a valid label value. `app_version_label_value` is constructed to
    /// be a valid label value, so it is also a valid `ProductVersion`.
    pub(crate) fn product_version(image: &ResolvedProductImage) -> ProductVersion {
        ProductVersion::from_str(&image.app_version_label_value)
            .expect("the app version label value is a valid product version")
    }

    /// Type-safe names for the per-cluster RBAC resources: the ServiceAccount shared by all
    /// Pods, its (namespaced) RoleBinding, and the operator-deployed ClusterRole it binds.
    pub fn cluster_resource_names(&self) -> role_utils::ResourceNames {
        role_utils::ResourceNames {
            cluster_name: self.name.clone(),
            product_name: PRODUCT_NAME.clone(),
        }
    }

    /// Type-safe names for the resources of the given role's role group.
    pub(crate) fn role_group_resource_names(
        &self,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: (**role).clone(),
            role_group_name: role_group_name.clone(),
        }
    }
}

// Implementing `Resource` (plus `HasName`/`HasUid`) lets `ValidatedCluster` stand in for the raw
// `DruidCluster` when building child-object metadata and owner references. The identity-bearing
// methods are backed by the `metadata` built by [`ValidatedCluster::object_meta`], while
// kind/group/version/plural delegate to the CRD so produced owner references are byte-identical
// to the raw-cluster ones.
impl Resource for ValidatedCluster {
    type DynamicType = <v1alpha1::DruidCluster as Resource>::DynamicType;
    type Scope = <v1alpha1::DruidCluster as Resource>::Scope;

    fn kind(dt: &Self::DynamicType) -> Cow<'_, str> {
        v1alpha1::DruidCluster::kind(dt)
    }

    fn group(dt: &Self::DynamicType) -> Cow<'_, str> {
        v1alpha1::DruidCluster::group(dt)
    }

    fn version(dt: &Self::DynamicType) -> Cow<'_, str> {
        v1alpha1::DruidCluster::version(dt)
    }

    fn plural(dt: &Self::DynamicType) -> Cow<'_, str> {
        v1alpha1::DruidCluster::plural(dt)
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

impl HasName for ValidatedCluster {
    fn to_name(&self) -> String {
        self.name.to_string()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> Uid {
        self.uid.clone()
    }
}

impl NameIsValidLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        self.name.to_label_value()
    }
}

/// Validates the cluster spec and the dereferenced inputs.
pub fn validate(
    druid: &v1alpha1::DruidCluster,
    dereferenced_objects: &DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
) -> Result<ValidatedCluster> {
    let image = druid
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            &crate::built_info::PKG_VERSION_SEMVER,
        )
        .context(ResolveProductImageSnafu)?;

    let resolved_authentication_classes = AuthenticationClassesResolved::from_fetched(
        &druid.spec.cluster_config,
        &dereferenced_objects.authentication_classes,
    )
    .context(ResolveAuthenticationClassesSnafu)?;

    let druid_tls_security =
        DruidTlsSecurity::new_from_druid_cluster(druid, &resolved_authentication_classes);

    let druid_auth_config =
        DruidAuthenticationConfig::from_auth_classes(resolved_authentication_classes);

    let cluster_name = druid.name_any();
    let deep_storage = &druid.spec.cluster_config.deep_storage;
    // The Vector aggregator discovery ConfigMap name (a typed `ConfigMapName`, so an invalid name
    // is already rejected at deserialization). It is only required when the Vector agent is
    // enabled for a role group; see [`validate_logging`].
    let vector_aggregator_config_map_name = druid
        .spec
        .cluster_config
        .vector_aggregator_config_map_name
        .clone();

    // The first failure propagates, so this order decides which misconfiguration the user is told
    // about when more than one role is wrong. It is `DruidRole`'s variant order.
    let coordinator_role = &druid.spec.coordinators;
    let coordinator_role_group_configs = validate_coordinator_role_group_configs(
        coordinator_role,
        &CoordinatorConfig::default_config(&cluster_name, &DruidRole::Coordinator, deep_storage),
        &vector_aggregator_config_map_name,
    )?;
    let coordinator_config = validated_listener_role_config(&coordinator_role.role_config);

    let broker_role = &druid.spec.brokers;
    let broker_role_group_configs = validate_broker_role_group_configs(
        broker_role,
        &BrokerConfig::default_config(&cluster_name, &DruidRole::Broker, deep_storage),
        &vector_aggregator_config_map_name,
    )?;
    let broker_config = validated_listener_role_config(&broker_role.role_config);

    let historical_role = &druid.spec.historicals;
    let historical_role_group_configs = validate_historical_role_group_configs(
        historical_role,
        &HistoricalConfig::default_config(&cluster_name, &DruidRole::Historical, deep_storage),
        &vector_aggregator_config_map_name,
    )?;
    let historical_config = validated_role_config(&historical_role.role_config);

    let middle_manager_role = &druid.spec.middle_managers;
    let middle_manager_role_group_configs = validate_middle_manager_role_group_configs(
        middle_manager_role,
        &MiddleManagerConfig::default_config(
            &cluster_name,
            &DruidRole::MiddleManager,
            deep_storage,
        ),
        &vector_aggregator_config_map_name,
    )?;
    let middle_manager_config = validated_role_config(&middle_manager_role.role_config);

    let router_role = &druid.spec.routers;
    let router_role_group_configs = validate_router_role_group_configs(
        router_role,
        &RouterConfig::default_config(&cluster_name, &DruidRole::Router, deep_storage),
        &vector_aggregator_config_map_name,
    )?;
    let router_config = validated_listener_role_config(&router_role.role_config);

    let name = get_cluster_name(druid).context(ClusterIdentitySnafu)?;
    let namespace = get_namespace(druid).context(ClusterIdentitySnafu)?;
    let uid = get_uid(druid).context(ClusterIdentitySnafu)?;

    let metadata_db_connection = druid
        .spec
        .cluster_config
        .metadata_database
        .jdbc_connection_details("metadata")
        .context(InvalidMetadataDatabaseConnectionSnafu)?;

    // The deep storage bucket carries its own S3 connection; if ingestion also configures one, the
    // two must be identical, as Druid only supports a single S3 connection.
    let s3_deep_storage_connection = dereferenced_objects
        .s3_deep_storage_bucket
        .as_ref()
        .map(|bucket| &bucket.connection);
    let s3_connection = match (
        dereferenced_objects.s3_ingestion_connection.as_ref(),
        s3_deep_storage_connection,
    ) {
        (Some(ingestion), Some(deep_storage)) => {
            ensure!(ingestion == deep_storage, IncompatibleS3ConnectionsSnafu);
            Some(ingestion.clone())
        }
        (Some(connection), None) | (None, Some(connection)) => Some(connection.clone()),
        (None, None) => None,
    };
    let deep_storage_bucket_name = dereferenced_objects
        .s3_deep_storage_bucket
        .as_ref()
        .map(|bucket| bucket.bucket_name.clone());

    // The dereference step fetched the rule-agnostic OPA document URL; append the authorization
    // rule Druid queries.
    // TODO(@maltesander): This would rather be a preprocess step?
    let opa_connection_string = dereferenced_objects
        .opa_base_document_url
        .as_ref()
        .map(|base_url| format!("{base_url}/allow"));

    Ok(ValidatedCluster {
        metadata: ValidatedCluster::object_meta(&name, &namespace, &uid),
        name,
        namespace,
        uid,
        product_version: ValidatedCluster::product_version(&image),
        image,
        cluster_config: ValidatedClusterConfig {
            zookeeper_connection_string: dereferenced_objects.zookeeper_connection_string.clone(),
            opa_connection_string,
            s3_connection,
            deep_storage_bucket_name,
            druid_tls_security,
            druid_auth_config,
            metadata_database: druid.spec.cluster_config.metadata_database.clone(),
            additional_extensions: druid.spec.cluster_config.additional_extensions.clone(),
            metadata_db_connection,
            deep_storage: druid.spec.cluster_config.deep_storage.clone(),
            extra_volumes: druid.spec.cluster_config.extra_volumes.clone(),
        },
        coordinator_config,
        coordinator_role_group_configs,
        broker_config,
        broker_role_group_configs,
        historical_config,
        historical_role_group_configs,
        middle_manager_config,
        middle_manager_role_group_configs,
        router_config,
        router_role_group_configs,
        router_listener: dereferenced_objects.router_listener.clone(),
        internal_secret: dereferenced_objects.internal_secret.clone(),
        discovery_config_map: dereferenced_objects.discovery_config_map.clone(),
    })
}

/// The validated role-level config of a role with a group Listener.
///
/// [`v1alpha1::DruidRoleConfig`] and [`GenericRoleConfig`] are destructured without `..`, so a
/// field added upstream fails to compile here instead of being silently dropped.
fn validated_listener_role_config(
    role_config: &v1alpha1::DruidRoleConfig,
) -> ValidatedListenerRoleConfig {
    let v1alpha1::DruidRoleConfig {
        generic: GenericRoleConfig {
            pod_disruption_budget,
        },
        listener_class,
    } = role_config;
    ValidatedListenerRoleConfig {
        pdb: pod_disruption_budget.clone(),
        listener_class: listener_class.clone(),
    }
}

/// The validated role-level config of a role without a Listener.
///
/// [`GenericRoleConfig`] is destructured without `..`, so a field added upstream fails to compile
/// here instead of being silently dropped.
fn validated_role_config(role_config: &GenericRoleConfig) -> ValidatedRoleConfig {
    let GenericRoleConfig {
        pod_disruption_budget,
    } = role_config;
    ValidatedRoleConfig {
        pdb: pod_disruption_budget.clone(),
    }
}

/// Merges and validates every Coordinator role group (via [`validate_role_group_config`]), then
/// its logging, then its name.
fn validate_coordinator_role_group_configs(
    role: &Role<
        CoordinatorConfigFragment,
        DruidConfigOverrides,
        v1alpha1::DruidRoleConfig,
        JavaCommonConfig,
    >,
    default_config: &CoordinatorConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<BTreeMap<RoleGroupName, CoordinatorRoleGroupConfig>> {
    let druid_role = DruidRole::Coordinator;
    role.role_groups
        .iter()
        .map(|(role_group_name, role_group)| {
            let merged = validate_role_group_config::<_, CoordinatorConfig, _>(
                &druid_role,
                role,
                role_group_name,
                role_group,
                default_config,
            )?;
            let logging =
                validate_logging(&merged.config.logging, vector_aggregator_config_map_name)?;
            let validated = CoordinatorRoleGroupConfig {
                replicas: merged.replicas,
                config: ValidatedCoordinatorConfig {
                    config: merged.config,
                    logging,
                },
                config_overrides: merged.config_overrides,
                env_overrides: merged.env_overrides,
                cli_overrides: merged.cli_overrides,
                pod_overrides: merged.pod_overrides,
                product_specific_common_config: merged.product_specific_common_config,
            };
            Ok((
                parse_role_group_name(&druid_role, role_group_name)?,
                validated,
            ))
        })
        .collect()
}

/// Merges and validates every Broker role group (via [`validate_role_group_config`]), then its
/// logging, then its name.
fn validate_broker_role_group_configs(
    role: &Role<
        BrokerConfigFragment,
        DruidConfigOverrides,
        v1alpha1::DruidRoleConfig,
        JavaCommonConfig,
    >,
    default_config: &BrokerConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<BTreeMap<RoleGroupName, BrokerRoleGroupConfig>> {
    let druid_role = DruidRole::Broker;
    role.role_groups
        .iter()
        .map(|(role_group_name, role_group)| {
            let merged = validate_role_group_config::<_, BrokerConfig, _>(
                &druid_role,
                role,
                role_group_name,
                role_group,
                default_config,
            )?;
            let logging =
                validate_logging(&merged.config.logging, vector_aggregator_config_map_name)?;
            let validated = BrokerRoleGroupConfig {
                replicas: merged.replicas,
                config: ValidatedBrokerConfig {
                    config: merged.config,
                    logging,
                },
                config_overrides: merged.config_overrides,
                env_overrides: merged.env_overrides,
                cli_overrides: merged.cli_overrides,
                pod_overrides: merged.pod_overrides,
                product_specific_common_config: merged.product_specific_common_config,
            };
            Ok((
                parse_role_group_name(&druid_role, role_group_name)?,
                validated,
            ))
        })
        .collect()
}

/// Merges and validates every Historical role group (via [`validate_role_group_config`]), then
/// its logging, then its name.
fn validate_historical_role_group_configs(
    role: &Role<
        HistoricalConfigFragment,
        DruidConfigOverrides,
        GenericRoleConfig,
        JavaCommonConfig,
    >,
    default_config: &HistoricalConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<BTreeMap<RoleGroupName, HistoricalRoleGroupConfig>> {
    let druid_role = DruidRole::Historical;
    role.role_groups
        .iter()
        .map(|(role_group_name, role_group)| {
            let merged = validate_role_group_config::<_, HistoricalConfig, _>(
                &druid_role,
                role,
                role_group_name,
                role_group,
                default_config,
            )?;
            let logging =
                validate_logging(&merged.config.logging, vector_aggregator_config_map_name)?;
            let validated = HistoricalRoleGroupConfig {
                replicas: merged.replicas,
                config: ValidatedHistoricalConfig {
                    config: merged.config,
                    logging,
                },
                config_overrides: merged.config_overrides,
                env_overrides: merged.env_overrides,
                cli_overrides: merged.cli_overrides,
                pod_overrides: merged.pod_overrides,
                product_specific_common_config: merged.product_specific_common_config,
            };
            Ok((
                parse_role_group_name(&druid_role, role_group_name)?,
                validated,
            ))
        })
        .collect()
}

/// Merges and validates every MiddleManager role group (via [`validate_role_group_config`]), then
/// its logging, then its name.
fn validate_middle_manager_role_group_configs(
    role: &Role<
        MiddleManagerConfigFragment,
        DruidConfigOverrides,
        GenericRoleConfig,
        JavaCommonConfig,
    >,
    default_config: &MiddleManagerConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<BTreeMap<RoleGroupName, MiddleManagerRoleGroupConfig>> {
    let druid_role = DruidRole::MiddleManager;
    role.role_groups
        .iter()
        .map(|(role_group_name, role_group)| {
            let merged = validate_role_group_config::<_, MiddleManagerConfig, _>(
                &druid_role,
                role,
                role_group_name,
                role_group,
                default_config,
            )?;
            let logging =
                validate_logging(&merged.config.logging, vector_aggregator_config_map_name)?;
            let validated = MiddleManagerRoleGroupConfig {
                replicas: merged.replicas,
                config: ValidatedMiddleManagerConfig {
                    config: merged.config,
                    logging,
                },
                config_overrides: merged.config_overrides,
                env_overrides: merged.env_overrides,
                cli_overrides: merged.cli_overrides,
                pod_overrides: merged.pod_overrides,
                product_specific_common_config: merged.product_specific_common_config,
            };
            Ok((
                parse_role_group_name(&druid_role, role_group_name)?,
                validated,
            ))
        })
        .collect()
}

/// Merges and validates every Router role group (via [`validate_role_group_config`]), then its
/// logging, then its name.
fn validate_router_role_group_configs(
    role: &Role<
        RouterConfigFragment,
        DruidConfigOverrides,
        v1alpha1::DruidRoleConfig,
        JavaCommonConfig,
    >,
    default_config: &RouterConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<BTreeMap<RoleGroupName, RouterRoleGroupConfig>> {
    let druid_role = DruidRole::Router;
    role.role_groups
        .iter()
        .map(|(role_group_name, role_group)| {
            let merged = validate_role_group_config::<_, RouterConfig, _>(
                &druid_role,
                role,
                role_group_name,
                role_group,
                default_config,
            )?;
            let logging =
                validate_logging(&merged.config.logging, vector_aggregator_config_map_name)?;
            let validated = RouterRoleGroupConfig {
                replicas: merged.replicas,
                config: ValidatedRouterConfig {
                    config: merged.config,
                    logging,
                },
                config_overrides: merged.config_overrides,
                env_overrides: merged.env_overrides,
                cli_overrides: merged.cli_overrides,
                pod_overrides: merged.pod_overrides,
                product_specific_common_config: merged.product_specific_common_config,
            };
            Ok((
                parse_role_group_name(&druid_role, role_group_name)?,
                validated,
            ))
        })
        .collect()
}

/// Merges and validates one role group via [`with_validated_config`], which folds the config
/// fragment (default <- role <- role group) plus the `configOverrides`, `envOverrides`,
/// `cliOverrides`, `podOverrides` and `jvmArgumentOverrides` (role group wins) into a single
/// [`RoleGroupConfig`].
fn validate_role_group_config<Config, ValidatedConfig, RoleConfig>(
    druid_role: &DruidRole,
    role: &Role<Config, DruidConfigOverrides, RoleConfig, JavaCommonConfig>,
    role_group_name: &str,
    role_group: &RoleGroup<Config, JavaCommonConfig, DruidConfigOverrides>,
    default_config: &Config,
) -> Result<RoleGroupConfig<ValidatedConfig, JavaCommonConfig, DruidConfigOverrides>>
where
    Config: Clone + Merge,
    ValidatedConfig: FromFragment<Fragment = Config>,
    RoleConfig: Default + JsonSchema + Serialize,
{
    let merged = with_validated_config::<
        ValidatedConfig,
        JavaCommonConfig,
        Config,
        RoleConfig,
        DruidConfigOverrides,
    >(role_group, role, default_config)
    .with_context(|_| ValidateRoleGroupConfigSnafu {
        role: druid_role.clone(),
        role_group: role_group_name.to_owned(),
    })?;

    Ok(RoleGroupConfig {
        // Passed through as is, including `None`: the StatefulSet then leaves `.spec.replicas`
        // unset.
        replicas: merged.replicas,
        config: merged.config.config,
        config_overrides: merged.config.config_overrides,
        env_overrides: merged.config.env_overrides.into(),
        cli_overrides: merged.config.cli_overrides,
        pod_overrides: merged.config.pod_overrides,
        product_specific_common_config: merged.config.product_specific_common_config,
    })
}

/// Parses a role group name from the CRD into its type-safe form.
fn parse_role_group_name(druid_role: &DruidRole, role_group_name: &str) -> Result<RoleGroupName> {
    RoleGroupName::from_str(role_group_name).with_context(|_| ParseRoleGroupNameSnafu {
        role: druid_role.clone(),
        role_group: role_group_name.to_owned(),
    })
}

/// Validates the logging configuration for the Druid, Prepare and (optional) Vector containers.
///
/// `vector_aggregator_config_map_name` is the discovery ConfigMap name of the Vector aggregator;
/// it is required only when the Vector agent is enabled.
fn validate_logging(
    logging: &Logging<Container>,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<ValidatedLogging> {
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

#[cfg(test)]
pub(crate) mod test_support {
    use stackable_operator::cli::OperatorEnvironmentOptions;

    use super::{ValidatedCluster, validate};
    use crate::{controller::dereference::DereferencedObjects, crd::v1alpha1};

    /// Dereferenced inputs with test defaults: no S3, no OPA, no auth, a fixed ZooKeeper string.
    pub fn dereferenced_objects() -> DereferencedObjects {
        DereferencedObjects {
            zookeeper_connection_string: "zookeeper-connection-string".to_string(),
            opa_base_document_url: None,
            s3_ingestion_connection: None,
            s3_deep_storage_bucket: None,
            authentication_classes: Vec::new(),
            router_listener: None,
            internal_secret: None,
            discovery_config_map: None,
        }
    }

    pub fn operator_environment() -> OperatorEnvironmentOptions {
        OperatorEnvironmentOptions {
            operator_namespace: "stackable-operators".to_string(),
            operator_service_name: "druid-operator".to_string(),
            image_repository: "oci.example.org".to_string(),
        }
    }

    /// Builds a [`ValidatedCluster`] through the real [`validate`] step, so that everything the
    /// dereferenced inputs switch on (authentication, OPA, S3, the Router Listener) takes the same
    /// path as in the operator.
    pub fn validated_cluster_from(
        druid: &v1alpha1::DruidCluster,
        dereferenced_objects: &DereferencedObjects,
    ) -> ValidatedCluster {
        validate(druid, dereferenced_objects, &operator_environment())
            .expect("test: the cluster validates")
    }

    /// A minimal but fully-valid `DruidCluster` with one role group per role.
    pub const MINIMAL_DRUID_YAML: &str = r#"
apiVersion: druid.stackable.tech/v1alpha1
kind: DruidCluster
metadata:
  name: simple-druid
  namespace: default
  uid: c27b3971-ca72-42c1-80a4-abdfc1db0ddd
spec:
  image:
    productVersion: 30.0.0
  clusterConfig:
    deepStorage:
      hdfs:
        configMapName: simple-hdfs
        directory: /druid
    metadataDatabase:
      postgresql:
        host: druid-postgresql
        database: druid
        credentialsSecretName: mySecret
    zookeeperConfigMapName: simple-druid-znode
  brokers:
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
"#;

    /// Parses a `DruidCluster` from YAML the same way the operator does (singleton-map enums).
    pub fn druid_from_yaml(yaml: &str) -> v1alpha1::DruidCluster {
        let deserializer = serde_yaml::Deserializer::from_str(yaml);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .expect("invalid test DruidCluster YAML")
    }

    /// Builds a [`ValidatedCluster`] from a `DruidCluster` with the test defaults of
    /// [`dereferenced_objects`] (no S3, no OPA, no auth, a fixed ZooKeeper string).
    pub fn validated_cluster(druid: &v1alpha1::DruidCluster) -> ValidatedCluster {
        validated_cluster_from(druid, &dereferenced_objects())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::{
        Error,
        test_support::{
            MINIMAL_DRUID_YAML, dereferenced_objects, druid_from_yaml, operator_environment,
        },
        validate,
    };
    use crate::crd::DRUID_DEFAULT_LISTENER_CLASS;

    #[test]
    fn test_validate_ok() {
        let druid = druid_from_yaml(MINIMAL_DRUID_YAML);

        let validated = validate(&druid, &dereferenced_objects(), &operator_environment())
            .expect("the minimal cluster validates");

        assert_eq!(validated.name.to_string(), "simple-druid");
        assert_eq!(validated.namespace.to_string(), "default");
        assert_eq!(
            validated.uid.to_string(),
            "c27b3971-ca72-42c1-80a4-abdfc1db0ddd"
        );

        // Every role is merged: each has its one `default` role group.
        let default = RoleGroupName::from_str("default").expect("valid role group name");
        assert!(
            validated
                .coordinator_role_group_configs
                .contains_key(&default)
        );
        assert!(validated.broker_role_group_configs.contains_key(&default));
        assert!(
            validated
                .historical_role_group_configs
                .contains_key(&default)
        );
        assert!(
            validated
                .middle_manager_role_group_configs
                .contains_key(&default)
        );
        assert!(validated.router_role_group_configs.contains_key(&default));

        // The externally reachable roles (Broker, Coordinator, Router) carry the default listener
        // class.
        assert_eq!(
            validated.coordinator_config.listener_class,
            *DRUID_DEFAULT_LISTENER_CLASS
        );
        assert_eq!(
            validated.broker_config.listener_class,
            *DRUID_DEFAULT_LISTENER_CLASS
        );
        assert_eq!(
            validated.router_config.listener_class,
            *DRUID_DEFAULT_LISTENER_CLASS
        );

        // Defaults from the dereferenced inputs flow through.
        assert!(validated.cluster_config.druid_auth_config.is_none());
        assert!(!validated.cluster_config.uses_s3());
        assert_eq!(
            validated.cluster_config.zookeeper_connection_string,
            "zookeeper-connection-string"
        );
    }

    #[test]
    fn test_validate_err_missing_uid() {
        let mut druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        druid.metadata.uid = None;

        let result = validate(&druid, &dereferenced_objects(), &operator_environment());

        assert!(
            matches!(result, Err(Error::ClusterIdentity { .. })),
            "expected a ClusterIdentity error when the cluster has no uid"
        );
    }
}
