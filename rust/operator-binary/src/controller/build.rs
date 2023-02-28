mod config;
mod discovery;
mod extensions;
mod internal_secret;
mod product_logging;
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
    types::{BuiltClusterResource, FetchedAdditionalData},
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

pub fn build_cluster_resources(
    druid: Arc<DruidCluster>,
    additional_data: FetchedAdditionalData,
    product_config: &ProductConfigManager,
) -> Result<Vec<BuiltClusterResource>> {
    let mut built_cluster_resources: Vec<BuiltClusterResource> = Vec::new();

    let client = &ctx.client;
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

    let vector_aggregator_address = resolve_vector_aggregator_address(&druid, client)
        .await
        .context(ResolveVectorAggregatorAddressSnafu)?;

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

    let resolved_authentication_classes = resolve_authentication_classes(client, &druid)
        .await
        .context(FailedToInitializeSecurityContextSnafu)?;

    let druid_ldap_settings = DruidLdapSettings::new_from(&resolved_authentication_classes);

    let druid_tls_security =
        DruidTlsSecurity::new_from_druid_cluster(&druid, resolved_authentication_classes);

    let role_config = transform_all_roles_to_config(druid.as_ref(), druid.build_role_properties());
    let validated_role_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &role_config.context(ProductConfigTransformSnafu)?,
        &ctx.product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    let merged_config = druid.merged_config().context(FailedToResolveConfigSnafu)?;

    for (role_name, role_config) in validated_role_config.iter() {
        let druid_role = DruidRole::from_str(role_name).context(UnidentifiedDruidRoleSnafu {
            role: role_name.to_string(),
        })?;

        let role_service = build_role_service(
            &druid,
            &resolved_product_image,
            &druid_role,
            &druid_tls_security,
        )
        .context(RoleBuildSnafu)?;
        built_cluster_resources.push(BuiltClusterResource::RoleService(role_service.clone()));

        create_shared_internal_secret(&druid, client, CONTROLLER_NAME)
            .await
            .context(FailedInternalSecretCreationSnafu)?;

        for (rolegroup_name, rolegroup_config) in role_config.iter() {
            let rolegroup = RoleGroupRef {
                cluster: ObjectRef::from_obj(&*druid),
                role: role_name.into(),
                role_group: rolegroup_name.into(),
            };

            let merged_rolegroup_config = merged_config
                .common_config(druid_role.clone(), rolegroup_name)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_services(
                &druid,
                &resolved_product_image,
                &rolegroup,
                &druid_tls_security,
            )?;
            let rg_configmap = build_rolegroup_config_map(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                &zk_connstr,
                vector_aggregator_address.as_deref(),
                opa_connstr.as_deref(),
                s3_conn.as_ref(),
                deep_storage_bucket_name.as_deref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            let rg_statefulset = build_rolegroup_statefulset(
                &druid,
                &resolved_product_image,
                &rolegroup,
                rolegroup_config,
                &merged_rolegroup_config,
                s3_conn.as_ref(),
                &druid_tls_security,
                &druid_ldap_settings,
            )?;
            built_cluster_resources.push(BuiltClusterResource::RolegroupService(
                rg_service,
                rolegroup.clone(),
            ));
            built_cluster_resources.push(BuiltClusterResource::RolegroupConfigMap(
                rg_configmap,
                rolegroup.clone(),
            ));
            built_cluster_resources.push(BuiltClusterResource::RolegroupStatefulSet(
                rg_statefulset,
                rolegroup.clone(),
            ));
        }
    }

    // discovery
    for discovery_cm in build_discovery_configmaps(
        &druid,
        &*druid,
        &resolved_product_image,
        &druid_tls_security,
    )
    .await
    .context(BuildDiscoveryConfigSnafu)?
    {
        built_cluster_resources.push(BuiltClusterResource::DiscoveryConfigMap(discovery_cm));
    }

    built_cluster_resources.push(BuiltClusterResource::DeleteOrphaned);

    Ok(built_cluster_resources)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::controller::types::{BuiltClusterResource, FetchedAdditionalData};

    use super::build_cluster_resources;
    use assert_json_diff::{assert_json_matches_no_panic, CompareMode, Config};
    use stackable_druid_crd::{authentication::ResolvedAuthenticationClasses, DruidCluster};
    use stackable_operator::{
        commons::product_image_selection::ResolvedProductImage, kube::ResourceExt,
        product_config::ProductConfigManager,
    };

    #[test]
    fn test_build_step_just_runs() {
        let cluster_cr = std::fs::File::open("test/smoke/druid_cluster.yaml").unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid_cluster: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/smoke/properties.yaml").unwrap();

        let result = build_cluster_resources(
            Arc::new(druid_cluster),
            FetchedAdditionalData {
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
        );

        assert!(result.is_ok(), "we want an ok, instead we got {:?}", result);
    }

    // Felix test suggestions:
    //  * testing vs not testing? decided not to, due to overhead: https://github.com/stackabletech/druid-operator/issues/381
    //  * check values in config maps https://github.com/stackabletech/druid-operator/blob/main/tests/templates/kuttl/resources/30-assert.yaml
    //  * checking pod template for content https://github.com/stackabletech/druid-operator/blob/main/tests/templates/kuttl/resources/20-assert.yaml

    #[test]
    fn test_override_runtime_properties() {
        let cluster_cr = std::fs::File::open("test/override/druid_cluster.yaml").unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid_cluster: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/smoke/properties.yaml").unwrap(); // dummy value

        let list_of_appliable_resources = build_cluster_resources(
            Arc::new(druid_cluster),
            FetchedAdditionalData {
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
        .expect("failed to create cluster resources");

        let mut checked = false;
        for entry in list_of_appliable_resources.iter() {
            if let BuiltClusterResource::RolegroupConfigMap(the_cm, _) = entry {
                if the_cm.name_unchecked() == "testcluster-broker-default" {
                    let runtime_properties_string =
                        the_cm.data.as_ref().unwrap()["runtime.properties"].clone();
                    runtime_properties_string.contains(r#"druid.extensions.loadList=\"[\\ \\\\\"druid-basic-security\\\\\",\\ \\\\\"prometheus-emitter\\\\\",\\ \\\\\"druid-kafka-indexing-service\\\\\",\\ \\\\\"druid-parquet-extensions\\\\\",\\ \\\\\"druid-histogram\\\\\",\\ \\\\\"druid-datasketches\\\\\",\\ \\\\\"druid-lookups-cached-global\\\\\",\\ \\\\\"druid-hdfs-storage\\\\\",\\ \\\\\"druid-opa-authorizer\\\\\",\\ \\\\\"postgresql-metadata-storage\\\\\",\\ \\\\\"druid-multi-stage-query\\\\\",\\ \\\\\"druid-s3-extensions\\\\\",\\ \\\\\"druid-moving-average-query\\\\\"\\ ]"#);
                    checked = true;
                }
            }
        }
        if !checked {
            panic!("config map was not found");
        }
    }

    #[test]
    fn test_replace_kuttl_resources_test() {
        let cluster_cr =
            std::fs::File::open("test/replace_kuttl_resources_test/druid_cluster.yaml").unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(&cluster_cr);
        let druid_cluster: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        let product_config_manager =
            ProductConfigManager::from_yaml_file("test/smoke/properties.yaml").unwrap(); // dummy value

        let list_of_appliable_resources = build_cluster_resources(
            Arc::new(druid_cluster),
            FetchedAdditionalData {
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
        .expect("failed to create cluster resources");

        struct StatefulSetYamlTestCases {
            stateful_set_name: String,
            yaml_path: String,
        }

        let stateful_set_tests: [&str; 6] = [
            "druid-resources-broker-default",
            "druid-resources-coordinator-default",
            "druid-resources-historical-default",
            "druid-resources-middlemanager-resources-from-role",
            "druid-resources-middlemanager-resources-from-role-group",
            "druid-resources-router-default",
        ];

        // NOTE: this part tries to replicate the "expected yaml fields show up" part of the kuttl test resources/20-assert.yaml
        for test_stateful_set_name in stateful_set_tests {
            let test_data_yaml_path =
                format!("test/replace_kuttl_resources_test/stateful_set_snippets/{test_stateful_set_name}.yaml");

            let mut checked = false;
            for entry in list_of_appliable_resources.iter() {
                if let BuiltClusterResource::RolegroupStatefulSet(the_set, _) = entry {
                    if the_set.name_unchecked() == test_stateful_set_name {
                        let generated_json_string = serde_json::to_string(&the_set).unwrap(); // TODO: convert the_set to a yaml, and to a blank dict
                        let actual_generated_json: serde_json::Value =
                            serde_json::from_str::<serde_json::Value>(&generated_json_string)
                                .unwrap();

                        let yaml_file = std::fs::File::open(&test_data_yaml_path).unwrap();
                        let deserializer = serde_yaml::Deserializer::from_reader(&yaml_file);
                        let expected_json: serde_json::Value =
                            serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
                                .unwrap();

                        // https://docs.rs/assert-json-diff/latest/assert_json_diff/#partial-matching
                        // allows FIRST ENTRY to have more fields than SECOND ENTRY, due to Inclusive flag
                        // we would use assert_json_include! instead here, but it does not allow for useful error string additions
                        let compare_result = assert_json_matches_no_panic(
                            &actual_generated_json,
                            &expected_json,
                            Config::new(CompareMode::Inclusive),
                        );
                        if let Err(error_string) = compare_result {
                            panic!(
                                "{} does not contain content of path {}, diff: \n\n{}\n\n",
                                test_stateful_set_name, test_data_yaml_path, error_string
                            );
                        }

                        checked = true;
                        break;
                    }
                }
            }

            if !checked {
                panic!(
                    "expected stateful set {} was not found",
                    test_stateful_set_name
                );
            }
        }

        // NOTE: this part tries to replicate the "expected yaml fields show up" part of the kuttl test resources/30-assert.yaml
        struct ConfigMapTestCases {
            config_map_name: String,
            expected_substrings: Vec<String>,
        }

        let config_map_tests: Vec<ConfigMapTestCases> = vec![
            ConfigMapTestCases {
                config_map_name: "druid-resources-historical-default".to_string(),
                expected_substrings: vec![
                    "-Xmx2847m".to_string(),
                    "druid.processing.numThreads=3".to_string(),
                    "druid.processing.numMergeBuffers=2".to_string(),
                    "druid.processing.buffer.sizeBytes=161962Ki".to_string(),
                ],
            },
            ConfigMapTestCases {
                config_map_name: "druid-resources-broker-default".to_string(),
                expected_substrings: vec!["-Xmx1348m".to_string()],
            },
            ConfigMapTestCases {
                config_map_name: "druid-resources-coordinator-default".to_string(),
                expected_substrings: vec!["-Xmx1748m".to_string()],
            },
            ConfigMapTestCases {
                config_map_name: "druid-resources-middlemanager-resources-from-role".to_string(),
                expected_substrings: vec!["-Xmx724m".to_string()],
            },
            ConfigMapTestCases {
                config_map_name: "druid-resources-middlemanager-resources-from-role-group"
                    .to_string(),
                expected_substrings: vec!["-Xmx2772m".to_string()],
            },
            ConfigMapTestCases {
                config_map_name: "druid-resources-router-default".to_string(),
                expected_substrings: vec!["-Xmx1620m".to_string()],
            },
        ];

        fn a_contains_b(_a: &str, _b: &str) -> bool {
            _a.contains(_b)
        }

        for test_entry in config_map_tests {
            let mut checked = false;
            for entry in list_of_appliable_resources.iter() {
                if let BuiltClusterResource::RolegroupConfigMap(the_cm, _) = entry {
                    if the_cm.name_unchecked() == test_entry.config_map_name {
                        let yaml_from_cm = serde_yaml::to_string(&the_cm).unwrap();

                        for substring in test_entry.expected_substrings {
                            assert!(
                                a_contains_b(&yaml_from_cm, &substring),
                                "yaml of cm {} did not contain substring {}",
                                test_entry.config_map_name,
                                substring
                            );
                        }
                        checked = true;
                        break;
                    }
                }
            }

            if !checked {
                panic!(
                    "expected config map {} was not found",
                    test_entry.config_map_name
                );
            }
        }
    }

    /*
    Scenario: tls is enabled
      * we want a volume mount of the trust store
      * we want commands to fill that trust store (init container?)
      * we want configs in the runtime.properties
     */
}
