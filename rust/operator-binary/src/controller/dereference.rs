//! The dereference step in the DruidCluster controller

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::opa::OpaApiVersion,
    crd::{authentication::core, s3},
    k8s_openapi::api::core::v1::ConfigMap,
};

use crate::crd::{
    DeepStorageSpec, authentication::fetch_authentication_classes,
    authorization::DruidAuthorization, v1alpha1,
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display(
        "failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::client::Error,
        cm_name: String,
    },

    #[snafu(display(
        "failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },

    #[snafu(display(
        "failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::commons::opa::Error,
        cm_name: String,
    },

    #[snafu(display("failed to resolve the ingestion S3 connection"))]
    ResolveS3Connection {
        source: stackable_operator::crd::s3::v1alpha1::ConnectionError,
    },

    #[snafu(display("failed to resolve the deep storage S3 bucket"))]
    ResolveS3Bucket {
        source: stackable_operator::crd::s3::v1alpha1::BucketError,
    },

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: crate::crd::authentication::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Kubernetes objects referenced from the DruidCluster spec, already fetched. Validation and
/// derivation of final values happens in the validate step.
pub struct DereferencedObjects {
    pub zookeeper_connection_string: String,
    /// The rule-agnostic OPA document URL (package level, no rule). The validate step appends the
    /// concrete authorization rule to produce the connection string.
    pub opa_base_document_url: Option<String>,
    /// The resolved ingestion S3 connection (if any). The validate step checks it against the deep
    /// storage connection.
    pub s3_ingestion_connection: Option<s3::v1alpha1::ConnectionSpec>,
    /// The resolved deep storage S3 bucket (if deep storage uses S3). Carries both the bucket name
    /// and its connection.
    pub s3_deep_storage_bucket: Option<s3::v1alpha1::ResolvedBucket>,
    /// The raw, fetched `AuthenticationClass` objects (in spec order). Validation of these happens
    /// in the validate step via
    /// [`crate::crd::authentication::AuthenticationClassesResolved::from_fetched`].
    pub authentication_classes: Vec<core::v1alpha1::AuthenticationClass>,
}

/// Fetches all Kubernetes objects referenced from the [`v1alpha1::DruidCluster`] spec.
pub async fn dereference(
    client: &Client,
    druid: &v1alpha1::DruidCluster,
) -> Result<DereferencedObjects> {
    let namespace = druid
        .metadata
        .namespace
        .as_deref()
        .context(ObjectHasNoNamespaceSnafu)?;

    let zk_confmap = druid
        .spec
        .cluster_config
        .zookeeper_config_map_name
        .to_string();
    let zookeeper_connection_string = client
        .get::<ConfigMap>(&zk_confmap, namespace)
        .await
        .context(GetZookeeperConnStringConfigMapSnafu {
            cm_name: zk_confmap.clone(),
        })?
        .data
        .and_then(|mut data| data.remove("ZOOKEEPER"))
        .context(MissingZookeeperConnStringSnafu {
            cm_name: zk_confmap.clone(),
        })?;

    // Fetch the rule-agnostic OPA document URL (package level, no rule). The validate step appends
    // the concrete authorization rule.
    let opa_base_document_url = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(client, druid, None, &OpaApiVersion::V1)
                .await
                .context(GetOpaConnStringSnafu {
                    cm_name: opa_config.config_map_name.clone(),
                })?,
        )
    } else {
        None
    };

    // Resolve the ingestion and deep storage S3 references separately. Checking that they are
    // compatible (and extracting the bucket name) is done in the validate step.
    let s3_ingestion_connection = if let Some(ingestion_connection) = druid
        .spec
        .cluster_config
        .ingestion
        .as_ref()
        .and_then(|ingestion| ingestion.s3connection.as_ref())
    {
        Some(
            ingestion_connection
                .clone()
                .resolve(client, namespace)
                .await
                .context(ResolveS3ConnectionSnafu)?,
        )
    } else {
        None
    };

    let s3_deep_storage_bucket = match &druid.spec.cluster_config.deep_storage {
        DeepStorageSpec::S3(s3_spec) => Some(
            s3_spec
                .bucket
                .clone()
                .resolve(client, namespace)
                .await
                .context(ResolveS3BucketSnafu)?,
        ),
        _ => None,
    };

    let authentication_classes = fetch_authentication_classes(&druid.spec.cluster_config, client)
        .await
        .context(AuthenticationClassRetrievalSnafu)?;

    Ok(DereferencedObjects {
        zookeeper_connection_string,
        opa_base_document_url,
        s3_ingestion_connection,
        s3_deep_storage_bucket,
        authentication_classes,
    })
}
