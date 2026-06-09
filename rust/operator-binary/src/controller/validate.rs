//! The validate step in the DruidCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedCluster`], consumed by the rest of `reconcile_druid`.

use std::{borrow::Cow, collections::BTreeMap};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection::{self, ResolvedProductImage},
    crd::s3,
    database_connections::drivers::jdbc::{JdbcDatabaseConnection, JdbcDatabaseConnectionDetails},
    kube::{Resource, api::ObjectMeta},
    v2::{
        HasName, HasUid,
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        types::{
            kubernetes::{NamespaceName, Uid},
            operator::ClusterName,
        },
    },
};
use strum::IntoEnumIterator;

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::dereference::DereferencedObjects,
    crd::{DeepStorageSpec, DruidErasedRole, DruidRole, security::DruidTlsSecurity, v1alpha1},
    extensions::get_extension_list,
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("invalid authentication configuration"))]
    InvalidDruidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },

    #[snafu(display("failed to determine the cluster's name, namespace, or uid"))]
    ClusterIdentity {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("invalid metadata database connection"))]
    InvalidMetadataDatabaseConnection {
        source: stackable_operator::database_connections::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type RoleGroupName = String;

/// A validated, merged role-group config.
///
/// This is the framework [`RoleGroupConfig`] (config plus the four merged override categories),
/// with the typed per-role config erased to [`CommonRoleGroupConfig`] so that all roles share a
/// single type. The rendered per-file configs (runtime.properties / security.properties /
/// jvm.config) are produced later, in the config-map build step.
///
/// Defined in [`crate::crd`] (where it has access to the private typed config fields) and
/// re-exported here for the build step.
pub use crate::crd::DruidRoleGroupConfig;

/// Cluster-wide resolved fields that are not role/rolegroup specific.
pub struct ValidatedClusterConfig {
    pub zookeeper_connection_string: String,
    pub opa_connection_string: Option<String>,
    pub s3_connection: Option<s3::v1alpha1::ConnectionSpec>,
    pub deep_storage_bucket_name: Option<String>,
    pub druid_tls_security: DruidTlsSecurity,
    pub druid_auth_config: Option<DruidAuthenticationConfig>,
    /// The `druid.extensions.loadList` entries, resolved from the metadata database, TLS, S3 and
    /// authentication settings during validation.
    pub extensions: Vec<String>,
    /// The `druid.metadata.storage.type` value derived from the configured metadata database.
    pub metadata_storage_type: String,
    /// The JDBC connection details (URL plus credential env vars) for the metadata database.
    pub metadata_db_connection: JdbcDatabaseConnectionDetails,
    /// The deep-storage spec, carried so the build step can derive the cluster-level
    /// `runtime.properties` (deep storage type / directory / base key) without the raw
    /// `DruidCluster`.
    pub deep_storage: DeepStorageSpec,
}

/// Synchronous inputs the rest of `reconcile_druid` needs after dereferencing.
pub struct ValidatedCluster {
    /// Mirrors `name`/`namespace`/`uid` below so that `ValidatedCluster` can implement
    /// [`Resource`] and be passed directly to the metadata/owner-reference builders.
    metadata: ObjectMeta,
    pub name: ClusterName,
    // Read from the mirrored `metadata` in the configmap path (via `name_and_namespace`); the typed
    // field is consumed directly when the service/statefulset builders move onto `ValidatedCluster`.
    #[allow(dead_code)]
    pub namespace: NamespaceName,
    pub uid: Uid,
    pub image: ResolvedProductImage,
    pub cluster_config: ValidatedClusterConfig,
    pub role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>>,
    /// The erased roles (see [`DruidErasedRole`]), retained so the build step can render
    /// `jvm.config` (which merges the role/rolegroup JVM argument overrides) without the raw
    /// `DruidCluster`.
    roles: BTreeMap<DruidRole, DruidErasedRole>,
}

impl ValidatedCluster {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: ClusterName,
        namespace: NamespaceName,
        uid: Uid,
        image: ResolvedProductImage,
        cluster_config: ValidatedClusterConfig,
        role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>>,
        roles: BTreeMap<DruidRole, DruidErasedRole>,
    ) -> Self {
        let metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            uid: Some(uid.to_string()),
            ..ObjectMeta::default()
        };
        Self {
            metadata,
            name,
            namespace,
            uid,
            image,
            cluster_config,
            role_group_configs,
            roles,
        }
    }

    /// The erased role (carrying the JVM argument overrides) for the given role. Used by the build
    /// step to render `jvm.config`.
    pub fn get_role(&self, role: &DruidRole) -> &DruidErasedRole {
        self.roles
            .get(role)
            .expect("every DruidRole is populated during validation")
    }
}

// Implementing `Resource` (plus `HasName`/`HasUid`) lets `ValidatedCluster` stand in for the raw
// `DruidCluster` when building child-object metadata and owner references. The identity-bearing
// methods are backed by the `metadata` built in `new`, while kind/group/version/plural delegate to
// the CRD so produced owner references are byte-identical to the previous raw-cluster ones.
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
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
        druid,
        &dereferenced_objects.resolved_authentication_classes,
    );

    let druid_auth_config = DruidAuthenticationConfig::try_from(
        dereferenced_objects.resolved_authentication_classes.clone(),
    )
    .context(InvalidDruidAuthenticationConfigSnafu)?;

    let mut role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>> =
        BTreeMap::new();
    let mut roles = BTreeMap::new();

    for druid_role in DruidRole::iter() {
        let group_map = druid
            .merged_role(&druid_role)
            .context(FailedToResolveConfigSnafu)?;
        role_group_configs.insert(druid_role.clone(), group_map);
        roles.insert(druid_role.clone(), druid.get_role(&druid_role));
    }

    let name = get_cluster_name(druid).context(ClusterIdentitySnafu)?;
    let namespace = get_namespace(druid).context(ClusterIdentitySnafu)?;
    let uid = get_uid(druid).context(ClusterIdentitySnafu)?;

    let extensions = get_extension_list(druid, &druid_tls_security, &druid_auth_config);
    let metadata_storage_type = druid
        .spec
        .cluster_config
        .metadata_database
        .as_metadata_storage_type()
        .to_string();
    let metadata_db_connection = druid
        .spec
        .cluster_config
        .metadata_database
        .jdbc_connection_details("metadata")
        .context(InvalidMetadataDatabaseConnectionSnafu)?;

    Ok(ValidatedCluster::new(
        name,
        namespace,
        uid,
        image,
        ValidatedClusterConfig {
            zookeeper_connection_string: dereferenced_objects.zookeeper_connection_string.clone(),
            opa_connection_string: dereferenced_objects.opa_connection_string.clone(),
            s3_connection: dereferenced_objects.s3_connection.clone(),
            deep_storage_bucket_name: dereferenced_objects.deep_storage_bucket_name.clone(),
            druid_tls_security,
            druid_auth_config,
            extensions,
            metadata_storage_type,
            metadata_db_connection,
            deep_storage: druid.spec.cluster_config.deep_storage.clone(),
        },
        role_group_configs,
        roles,
    ))
}
