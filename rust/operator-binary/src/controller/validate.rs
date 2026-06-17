//! The validate step in the DruidCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedCluster`], consumed by the rest of `reconcile_druid`.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    cli::OperatorEnvironmentOptions,
    commons::{
        pdb::PdbConfig,
        product_image_selection::{self, ResolvedProductImage},
    },
    crd::s3,
    database_connections::drivers::jdbc::{JdbcDatabaseConnection, JdbcDatabaseConnectionDetails},
    k8s_openapi::api::core::v1::Volume,
    kube::{Resource, api::ObjectMeta},
    kvp::Labels,
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        builder::meta::ownerreference_from_resource,
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        kvp::label::{recommended_labels, role_group_selector},
        role_group_utils::ResourceNames,
        types::{
            kubernetes::{ListenerClassName, NamespaceName, Uid},
            operator::{ClusterName, ProductVersion, RoleGroupName, RoleName},
        },
    },
};
use strum::IntoEnumIterator;

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::{controller_name, dereference::DereferencedObjects, operator_name, product_name},
    crd::{
        DeepStorageSpec, DruidRole, database::MetadataDatabaseConnection,
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

/// A validated, merged role-group config.
///
/// This is the upstream [`stackable_operator::v2::role_utils::RoleGroupConfig`] (config plus the
/// four merged override categories), with the typed per-role config erased to
/// [`ValidatedDruidConfig`] so that all roles share a single type. The rendered per-file configs
/// (runtime.properties / security.properties / jvm.config) are produced later, in the config-map
/// build step.
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

/// Per-role configuration extracted during validation, so the reconcile/build steps consume this
/// instead of re-reading the raw [`v1alpha1::DruidCluster`].
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: PdbConfig,
    /// The role's listener class, or `None` for roles without a listener
    /// ([`DruidRole::Historical`]/[`DruidRole::MiddleManager`]).
    pub listener_class: Option<ListenerClassName>,
}

/// Synchronous inputs the rest of `reconcile_druid` needs after dereferencing.
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
    /// The per-role config (PDB and listener class) for every [`DruidRole`].
    pub role_configs: BTreeMap<DruidRole, ValidatedRoleConfig>,
    pub role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>>,
}

impl ValidatedCluster {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        name: ClusterName,
        namespace: NamespaceName,
        uid: Uid,
        image: ResolvedProductImage,
        cluster_config: ValidatedClusterConfig,
        role_configs: BTreeMap<DruidRole, ValidatedRoleConfig>,
        role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>>,
    ) -> Self {
        let metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            uid: Some(uid.to_string()),
            ..ObjectMeta::default()
        };
        // `app_version_label_value` is constructed to be a valid label value, so it is also a valid
        // `ProductVersion`.
        let product_version = ProductVersion::from_str(&image.app_version_label_value)
            .expect("the app version label value is a valid product version");
        Self {
            metadata,
            name,
            namespace,
            uid,
            image,
            product_version,
            cluster_config,
            role_configs,
            role_group_configs,
        }
    }

    /// The validated per-role config (PDB and listener class) for the given role.
    pub(crate) fn role_config(&self, role: &DruidRole) -> &ValidatedRoleConfig {
        self.role_configs
            .get(role)
            .expect("every DruidRole has a validated role config")
    }

    /// Recommended labels for a role-group resource, using the given product version.
    ///
    /// Kept separate so the listener PVC templates (which require an immutable, version-independent
    /// label set) can pass the unversioned product version.
    pub(crate) fn recommended_labels_for(
        &self,
        role: &DruidRole,
        product_version: &ProductVersion,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        recommended_labels(
            self,
            &product_name(),
            product_version,
            &operator_name(),
            &controller_name(),
            &role.to_role_name(),
            role_group_name,
        )
    }

    /// Recommended labels for a role-group resource.
    pub(crate) fn recommended_labels(
        &self,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_for(role, &self.product_version, role_group_name)
    }

    /// Selector labels matching the pods of a role group.
    pub(crate) fn role_group_selector(
        &self,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        role_group_selector(self, &product_name(), &role.to_role_name(), role_group_name)
    }

    /// Returns an [`ObjectMetaBuilder`] pre-filled with the namespace, an owner reference back to
    /// this cluster, and the recommended labels for a resource named `name` in `role`/`role_group_name`.
    ///
    /// Consolidates the metadata chain repeated by the child-resource builders. Call sites that need
    /// extra labels/annotations chain them onto the returned builder.
    pub(crate) fn object_meta(
        &self,
        name: impl Into<String>,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> ObjectMetaBuilder {
        let mut builder = ObjectMetaBuilder::new();
        builder
            .name_and_namespace(self)
            .name(name)
            .ownerreference(ownerreference_from_resource(self, None, Some(true)))
            .with_labels(self.recommended_labels(role, role_group_name));
        builder
    }

    /// Type-safe names for the resources of the given role's role group.
    pub(crate) fn resource_names(
        &self,
        role: &DruidRole,
        role_group_name: &RoleGroupName,
    ) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: RoleName::from_str(&role.to_string())
                .expect("a DruidRole is a valid role name"),
            role_group_name: role_group_name.clone(),
        }
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
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
        druid,
        &dereferenced_objects.resolved_authentication_classes,
    );

    let druid_auth_config = DruidAuthenticationConfig::from_auth_classes(
        dereferenced_objects.resolved_authentication_classes.clone(),
    );

    let mut role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, DruidRoleGroupConfig>> =
        BTreeMap::new();
    let mut role_configs: BTreeMap<DruidRole, ValidatedRoleConfig> = BTreeMap::new();

    for druid_role in DruidRole::iter() {
        let group_map = druid
            .merged_role(&druid_role)
            .context(FailedToResolveConfigSnafu)?;
        role_group_configs.insert(druid_role.clone(), group_map);

        role_configs.insert(
            druid_role.clone(),
            ValidatedRoleConfig {
                pdb: druid
                    .generic_role_config(&druid_role)
                    .pod_disruption_budget
                    .clone(),
                listener_class: druid_role.listener_class_name(druid),
            },
        );
    }

    let name = get_cluster_name(druid).context(ClusterIdentitySnafu)?;
    let namespace = get_namespace(druid).context(ClusterIdentitySnafu)?;
    let uid = get_uid(druid).context(ClusterIdentitySnafu)?;

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
            metadata_database: druid.spec.cluster_config.metadata_database.clone(),
            additional_extensions: druid.spec.cluster_config.additional_extensions.clone(),
            metadata_db_connection,
            deep_storage: druid.spec.cluster_config.deep_storage.clone(),
            extra_volumes: druid.spec.cluster_config.extra_volumes.clone(),
        },
        role_configs,
        role_group_configs,
    ))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::{collections::BTreeMap, str::FromStr};

    use stackable_operator::{
        database_connections::drivers::jdbc::JdbcDatabaseConnection,
        kube::ResourceExt,
        v2::types::{
            kubernetes::{NamespaceName, Uid},
            operator::ClusterName,
        },
    };
    use strum::IntoEnumIterator;

    use super::{RoleGroupName, ValidatedCluster, ValidatedClusterConfig, ValidatedRoleConfig};
    use crate::{
        controller::CONTAINER_IMAGE_BASE_NAME,
        crd::{DruidRole, security::DruidTlsSecurity, v1alpha1},
    };

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

    /// Builds a [`ValidatedCluster`] from a `DruidCluster` using test defaults for the
    /// dereferenced/cluster-wide fields (no S3, no auth, fixed zookeeper string). Runs the real
    /// `merged_role` pipeline for every role.
    pub fn validated_cluster(druid: &v1alpha1::DruidCluster) -> ValidatedCluster {
        let image = druid
            .spec
            .image
            .resolve(
                CONTAINER_IMAGE_BASE_NAME,
                "oci.example.org",
                crate::built_info::PKG_VERSION,
            )
            .expect("test: resolvable product image");

        let druid_tls_security = DruidTlsSecurity::new(false, Some("tls".to_string()));

        let mut role_group_configs: BTreeMap<DruidRole, BTreeMap<RoleGroupName, _>> =
            BTreeMap::new();
        let mut role_configs: BTreeMap<DruidRole, ValidatedRoleConfig> = BTreeMap::new();
        for role in DruidRole::iter() {
            role_group_configs.insert(
                role.clone(),
                druid.merged_role(&role).expect("test: merged role"),
            );
            role_configs.insert(
                role.clone(),
                ValidatedRoleConfig {
                    pdb: druid
                        .generic_role_config(&role)
                        .pod_disruption_budget
                        .clone(),
                    listener_class: role.listener_class_name(druid),
                },
            );
        }

        let metadata_db_connection = druid
            .spec
            .cluster_config
            .metadata_database
            .jdbc_connection_details("metadata")
            .expect("test: valid metadata db connection");

        ValidatedCluster::new(
            ClusterName::from_str(&druid.name_any()).expect("test: valid cluster name"),
            NamespaceName::from_str("default").expect("test: valid namespace"),
            Uid::from_str("c27b3971-ca72-42c1-80a4-abdfc1db0ddd").expect("test: valid uid"),
            image,
            ValidatedClusterConfig {
                zookeeper_connection_string: "zookeeper-connection-string".to_string(),
                opa_connection_string: None,
                s3_connection: None,
                deep_storage_bucket_name: None,
                druid_tls_security,
                druid_auth_config: None,
                metadata_database: druid.spec.cluster_config.metadata_database.clone(),
                additional_extensions: druid.spec.cluster_config.additional_extensions.clone(),
                metadata_db_connection,
                deep_storage: druid.spec.cluster_config.deep_storage.clone(),
                extra_volumes: druid.spec.cluster_config.extra_volumes.clone(),
            },
            role_configs,
            role_group_configs,
        )
    }
}
