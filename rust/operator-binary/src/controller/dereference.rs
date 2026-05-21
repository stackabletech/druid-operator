//! The dereference step in the DruidCluster controller
//!
//! Fetches all Kubernetes objects referenced by the DruidCluster spec and returns them in
//! [`DereferencedObjects`]. The helpers called here (`AuthenticationClassesResolved::from`,
//! `DruidCluster::get_s3_connection`, `S3Bucket::resolve`,
//! `OpaConfig::full_document_url_from_config_map`) currently mix fetching and validation;
//! their outputs are treated as "dereferenced" for now. Splitting those helpers is a
//! follow-up.

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::opa::OpaApiVersion,
    crd::s3,
    k8s_openapi::api::core::v1::ConfigMap,
};

use crate::crd::{
    DeepStorageSpec, authentication::AuthenticationClassesResolved,
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

    #[snafu(display("failed to get valid S3 connection"))]
    GetS3Connection { source: crate::crd::Error },

    #[snafu(display("failed to get deep storage bucket"))]
    GetDeepStorageBucket {
        source: stackable_operator::crd::s3::v1alpha1::BucketError,
    },

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: crate::crd::authentication::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Kubernetes objects referenced from the DruidCluster spec, already fetched (and, for now,
/// partly validated by the existing helper functions).
pub struct DereferencedObjects {
    pub zookeeper_connection_string: String,
    pub opa_connection_string: Option<String>,
    pub s3_connection: Option<s3::v1alpha1::ConnectionSpec>,
    pub deep_storage_bucket_name: Option<String>,
    pub resolved_authentication_classes: AuthenticationClassesResolved,
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

    let zk_confmap = druid.spec.cluster_config.zookeeper_config_map_name.clone();
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

    let opa_connection_string = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(client, druid, Some("allow"), &OpaApiVersion::V1)
                .await
                .context(GetOpaConnStringSnafu {
                    cm_name: opa_config.config_map_name.clone(),
                })?,
        )
    } else {
        None
    };

    let s3_connection = druid
        .get_s3_connection(client)
        .await
        .context(GetS3ConnectionSnafu)?;

    let deep_storage_bucket_name = match &druid.spec.cluster_config.deep_storage {
        DeepStorageSpec::S3(s3_spec) => Some(
            s3_spec
                .bucket
                .clone()
                .resolve(client, namespace)
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name,
        ),
        _ => None,
    };

    let resolved_authentication_classes =
        AuthenticationClassesResolved::from(&druid.spec.cluster_config, client)
            .await
            .context(AuthenticationClassRetrievalSnafu)?;

    Ok(DereferencedObjects {
        zookeeper_connection_string,
        opa_connection_string,
        s3_connection,
        deep_storage_bucket_name,
        resolved_authentication_classes,
    })
}
