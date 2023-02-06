use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{
    authorization::DruidAuthorization, security::resolve_authentication_classes, DeepStorageSpec,
    DruidCluster,
};
use stackable_operator::{
    client::Client,
    commons::{opa::OpaApiVersion, product_image_selection::ResolvedProductImage},
    k8s_openapi::api::core::v1::ConfigMap,
};
use std::{ops::Deref, sync::Arc};
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{types::AdditionalData, DOCKER_IMAGE_BASE_NAME};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display(
        "failed to get ZooKeeper discovery config map for cluster: {}",
        cm_name
    ))]
    GetZookeeperConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display(
        "failed to get OPA discovery config map and/or connection string for cluster: {}",
        cm_name
    ))]
    GetOpaConnString {
        source: stackable_operator::error::Error,
        cm_name: String,
    },
    #[snafu(display("failed to get valid S3 connection"))]
    GetS3Connection { source: stackable_druid_crd::Error },
    #[snafu(display("failed to get deep storage bucket"))]
    GetDeepStorageBucket {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "failed to get ZooKeeper connection string from config map {}",
        cm_name
    ))]
    MissingZookeeperConnString { cm_name: String },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to initialize security context"))]
    FailedToInitializeSecurityContext {
        source: stackable_druid_crd::security::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn fetch_additional_data(
    druid: &Arc<DruidCluster>,
    client: &Client,
) -> Result<AdditionalData> {
    let namespace = &druid
        .metadata
        .namespace
        .clone()
        .with_context(|| ObjectHasNoNamespaceSnafu {})?;
    let resolved_product_image: ResolvedProductImage =
        druid.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);

    let zk_confmap = druid.spec.cluster_config.zookeeper_config_map_name.clone();

    let zk_connstr = client
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

    // Assemble the OPA connection string from the discovery and the given path, if a spec is given.
    let opa_connstr = if let Some(DruidAuthorization { opa: opa_config }) =
        &druid.spec.cluster_config.authorization
    {
        Some(
            opa_config
                .full_document_url_from_config_map(
                    client,
                    druid.deref(),
                    Some("allow"),
                    OpaApiVersion::V1,
                )
                .await
                .context(GetOpaConnStringSnafu {
                    cm_name: opa_config.config_map_name.clone(),
                })?,
        )
    } else {
        None
    };

    // Get the s3 connection if one is defined
    let s3_conn = druid
        .get_s3_connection(client)
        .await
        .context(GetS3ConnectionSnafu)?;

    let deep_storage_bucket_name = match &druid.spec.cluster_config.deep_storage {
        DeepStorageSpec::S3(s3_spec) => {
            s3_spec
                .bucket
                .resolve(client, namespace)
                .await
                .context(GetDeepStorageBucketSnafu)?
                .bucket_name
        }
        _ => None,
    };

    let resolved_authentication_classes = resolve_authentication_classes(client, druid)
        .await
        .context(FailedToInitializeSecurityContextSnafu)?;

    let additional_data = AdditionalData {
        opa_connstr,
        resolved_authentication_classes,
        resolved_product_image,
        zk_connstr,
        s3_conn,
        deep_storage_bucket_name,
    };
    Ok(additional_data)
}
