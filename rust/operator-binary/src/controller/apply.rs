use crate::OPERATOR_NAME;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_druid_crd::{DruidCluster, APP_NAME};
use stackable_operator::{
    client::Client,
    cluster_resources::ClusterResources,
    k8s_openapi::api::core::v1::Secret,
    kube::{runtime::controller::Action, Resource, ResourceExt},
    role_utils::RoleGroupRef,
};
use std::sync::Arc;
use strum::{EnumDiscriminants, IntoStaticStr};

use super::{types::AppliableClusterResource, CONTROLLER_NAME};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply discovery ConfigMap"))]
    ApplyDiscoveryConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<DruidCluster>,
    },
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply internal secret"))]
    ApplyInternalSecret {
        source: stackable_operator::error::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn handle_cluster_resources(
    client: &Client,
    druid: &Arc<DruidCluster>,
    appliable_cluster_resources: Vec<AppliableClusterResource>,
) -> Result<Action> {
    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        &druid.object_ref(&()),
    )
    .context(CreateClusterResourcesSnafu)?;

    for cluster_resource in appliable_cluster_resources {
        match cluster_resource {
            AppliableClusterResource::RoleService(role_service) => {
                cluster_resources
                    .add(client, &role_service)
                    .await
                    .context(ApplyRoleServiceSnafu)?;
            }
            AppliableClusterResource::DiscoveryConfigMap(config_map) => {
                cluster_resources
                    .add(client, &config_map)
                    .await
                    .context(ApplyDiscoveryConfigSnafu)?;
            }
            AppliableClusterResource::RolegroupService(rg_service, rolegroup) => {
                cluster_resources
                    .add(client, &rg_service)
                    .await
                    .with_context(|_| ApplyRoleGroupServiceSnafu {
                        rolegroup: rolegroup.clone(),
                    })?;
            }
            AppliableClusterResource::RolegroupConfigMap(rg_configmap, rolegroup) => {
                cluster_resources
                    .add(client, &rg_configmap)
                    .await
                    .with_context(|_| ApplyRoleGroupConfigSnafu {
                        rolegroup: rolegroup.clone(),
                    })?;
            }
            AppliableClusterResource::RolegroupStatefulSet(rg_statefulset, rolegroup) => {
                cluster_resources
                    .add(client, &rg_statefulset)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        rolegroup: rolegroup.clone(),
                    })?;
            }
            AppliableClusterResource::InternalSecret(secret) => {
                // TODO: I must admit, I don't quite know what's going on here right now
                if client
                    .get_opt::<Secret>(
                        &secret.name_any(),
                        secret
                            .namespace()
                            .as_deref()
                            .context(ObjectHasNoNamespaceSnafu)?,
                    )
                    .await
                    .context(FailedToRetrieveInternalSecretSnafu)?
                    .is_none()
                {
                    client
                        .apply_patch(CONTROLLER_NAME, &secret, &secret)
                        .await
                        .context(ApplyInternalSecretSnafu)?;
                }
            }
        };
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(Action::await_change())
}
