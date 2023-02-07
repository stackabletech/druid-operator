mod config;
mod discovery;
mod extensions;
mod internal_secret;
mod roles;

use discovery::build_discovery_configmaps;
use internal_secret::build_shared_internal_secret;

use snafu::{ResultExt, Snafu};
use stackable_druid_crd::{
    ldap::DruidLdapSettings, resource, security::DruidTlsSecurity, DruidCluster, DruidRole,
};
use stackable_operator::{
    kube::runtime::reflector::ObjectRef,
    product_config::ProductConfigManager,
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::RoleGroupRef,
};
use std::{str::FromStr, sync::Arc};
use strum::{EnumDiscriminants, IntoStaticStr};

use self::roles::{
    build_role_service, build_rolegroup_config_map, build_rolegroup_services,
    build_rolegroup_statefulset,
};

use super::{
    types::{AdditionalData, AppliableClusterResource},
    CONTROLLER_NAME,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("failed to build discovery ConfigMap"))]
    BuildDiscoveryConfig { source: discovery::Error },
    #[snafu(display("could not parse Druid role [{role}]"))]
    UnidentifiedDruidRole {
        source: strum::ParseError,
        role: String,
    },
    #[snafu(display("failed to resolve and merge resource config for role and role group"))]
    FailedToResolveResourceConfig {
        source: stackable_druid_crd::resource::Error,
    },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedInternalSecretCreation { source: internal_secret::Error },
    #[snafu(display("failed to build role related cluster resource"))]
    RoleBuildError { source: roles::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn create_appliable_cluster_resources(
    druid: Arc<DruidCluster>,
    additional_data: AdditionalData,
    product_config: &ProductConfigManager,
) -> Result<Vec<AppliableClusterResource>> {
    let mut appliable_cluster_resources: Vec<AppliableClusterResource> = Vec::new();

    let druid_ldap_settings =
        DruidLdapSettings::new_from(&additional_data.resolved_authentication_classes);

    let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
        &druid,
        additional_data.resolved_authentication_classes,
    );

    // False positive, auto-deref breaks type inference
    #[allow(clippy::explicit_auto_deref)]
    let role_config = transform_all_roles_to_config(&*druid, druid.build_role_properties());
    let validated_role_config = validate_all_roles_and_groups_config(
        &additional_data.resolved_product_image.product_version,
        &role_config.context(ProductConfigTransformSnafu)?,
        product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(
            &druid,
            &additional_data.resolved_product_image,
            &druid_role,
            &druid_tls_security,
        )
        .context(RoleBuildSnafu)?;

        appliable_cluster_resources
            .push(AppliableClusterResource::RoleService(role_service.clone()));

        let internal_secret =
            build_shared_internal_secret(&druid).context(FailedInternalSecretCreationSnafu)?;
        appliable_cluster_resources.push(AppliableClusterResource::InternalSecret(internal_secret));

        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let resources = resource::resources(&druid, &druid_role, &rolegroup)
                .context(FailedToResolveResourceConfigSnafu)?;

            let rg_service = build_rolegroup_services(
                &druid,
                &additional_data.resolved_product_image,
                &rolegroup,
                &druid_tls_security,
            )
            .context(RoleBuildSnafu)?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &additional_data.resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &additional_data.zk_connstr,
                additional_data.opa_connstr.as_deref(),
                additional_data.s3_conn.as_ref(),
                additional_data.deep_storage_bucket_name.as_deref(),
                &resources,
                &druid_tls_security,
                &druid_ldap_settings,
            )
            .context(RoleBuildSnafu)?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &additional_data.resolved_product_image,
                &rolegroup,
                rolegroup_config,
                additional_data.s3_conn.as_ref(),
                &resources,
                &druid_tls_security,
                &druid_ldap_settings,
            )
            .context(RoleBuildSnafu)?;

            appliable_cluster_resources.push(AppliableClusterResource::RolegroupService(
                rg_service,
                rolegroup.clone(),
            ));
            appliable_cluster_resources.push(AppliableClusterResource::RolegroupConfigMap(
                rg_configmap,
                rolegroup.clone(),
            ));
            appliable_cluster_resources.push(AppliableClusterResource::RolegroupStatefulSet(
                rg_statefulset,
                rolegroup.clone(),
            ));
        }
    }

    // discovery
    for discovery_cm in build_discovery_configmaps(
        &druid,
        &*druid,
        &additional_data.resolved_product_image,
        &druid_tls_security,
    )
    .await
    .context(BuildDiscoveryConfigSnafu)?
    {
        appliable_cluster_resources
            .push(AppliableClusterResource::DiscoveryConfigMap(discovery_cm));
    }

    Ok(appliable_cluster_resources)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::controller::types::AdditionalData;

    use super::create_appliable_cluster_resources;
    use stackable_druid_crd::{authentication::ResolvedAuthenticationClasses, DruidCluster};
    use stackable_operator::{
        commons::product_image_selection::ResolvedProductImage,
        product_config::ProductConfigManager,
    };

    #[tokio::test]
    async fn test_build_step_just_runs() {
        let cluster_cr = std::fs::File::open("test/smoke/druid_cluster.yaml").unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid_cluster: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/smoke/properties.yaml").unwrap();

        let result = create_appliable_cluster_resources(
            Arc::new(druid_cluster),
            AdditionalData {
                opa_connstr: None,
                resolved_authentication_classes: ResolvedAuthenticationClasses::new(vec![]),
                resolved_product_image: ResolvedProductImage {
                    product_version: "0.1.0".to_string(),
                    app_version_label: "".to_string(),
                    image: "".to_string(),
                    image_pull_policy: "".to_string(),
                    pull_secrets: None,
                },
                zk_connstr: "".to_string(),
                s3_conn: None,
                deep_storage_bucket_name: None,
            },
            &product_config_manager,
        )
        .await;

        assert!(result.is_ok(), "we want an ok, instead we got {:?}", result);
    }
}
