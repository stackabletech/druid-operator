use stackable_operator::{
    commons::affinity::{affinity_between_role_pods, StackableAffinityFragment},
    k8s_openapi::api::core::v1::{PodAffinity, PodAntiAffinity},
};

use crate::{DeepStorageSpec, DruidRole, HdfsDeepStorageSpec, APP_NAME};

/// Please have a look at the architecture diagram in <https://druid.apache.org/assets/images/druid-architecture-7db1cd79d2d70b2e5ccc73b6bebfcaa4.svg>
/// to understand which roles do communicate with each other.
pub fn get_affinity(
    cluster_name: &str,
    role: &DruidRole,
    deep_storage: &DeepStorageSpec,
) -> StackableAffinityFragment {
    // Add affinities between roles
    let affinities = match role {
        // Manages data availability on the cluster
        DruidRole::Coordinator => vec![],
        // Handles queries from external clients
        DruidRole::Broker => vec![affinity_between_role_pods(
            APP_NAME,
            cluster_name,
            &DruidRole::Historical.to_string(),
            60, // The historicals store all the queryable data, so the affinity is more important than the affinity to the MiddleManagers
        ), affinity_between_role_pods(
            APP_NAME,
            cluster_name,
            &DruidRole::MiddleManager.to_string(),
            40,
        )],
        // Stores queryable data
        DruidRole::Historical |
        // Ingests data
        DruidRole::MiddleManager => {
            if let DeepStorageSpec::HDFS(HdfsDeepStorageSpec {
                config_map_name: hdfs_discovery_cm_name,
                ..
            }) = deep_storage
            {
                vec![affinity_between_role_pods(
                    "hdfs",
                    hdfs_discovery_cm_name, // The discovery cm has the same name as the HdfsCluster itself
                    "datanode",
                    50,
                )]
            } else {
                vec![]
            }
        }
        // Routes requests to Brokers, Coordinators, and Overlords
        DruidRole::Router => {
            vec![affinity_between_role_pods(
                APP_NAME,
                cluster_name,
                &DruidRole::Broker.to_string(),
                40,
            )]
        }
    };

    StackableAffinityFragment {
        pod_affinity: Some(PodAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(affinities),
            required_during_scheduling_ignored_during_execution: None,
        }),
        pod_anti_affinity: Some(PodAntiAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![
                affinity_between_role_pods(APP_NAME, cluster_name, &role.to_string(), 70),
            ]),
            required_during_scheduling_ignored_during_execution: None,
        }),
        node_affinity: None,
        node_selector: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;
    use std::collections::BTreeMap;

    use crate::DruidCluster;
    use stackable_operator::{
        commons::affinity::StackableAffinity,
        k8s_openapi::{
            api::core::v1::{
                PodAffinity, PodAffinityTerm, PodAntiAffinity, WeightedPodAffinityTerm,
            },
            apimachinery::pkg::apis::meta::v1::LabelSelector,
        },
    };

    #[rstest]
    #[case(DruidRole::Coordinator)]
    #[case(DruidRole::Broker)]
    #[case(DruidRole::Historical)]
    #[case(DruidRole::MiddleManager)]
    #[case(DruidRole::Router)]
    fn test_affinity_defaults(#[case] role: DruidRole) {
        let input = r#"
        apiVersion: druid.stackable.tech/v1alpha1
        kind: DruidCluster
        metadata:
          name: simple-druid
        spec:
          image:
            productVersion: 28.0.1
          clusterConfig:
            deepStorage:
              hdfs:
                configMapName: simple-hdfs
                directory: /druid
            metadataStorageDatabase:
              dbType: postgresql
              connString: jdbc:postgresql://druid-postgresql/druid
              host: druid-postgresql
              port: 5432
              credentialsSecret: mySecret
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
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let druid: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        let merged_config = druid
            .merged_config()
            .unwrap()
            .common_config(role.clone(), "default")
            .unwrap();

        let mut expected_affinities = vec![];

        match role {
            DruidRole::Broker => {
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "druid".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-druid".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "historical".to_string(),
                                ),
                            ])),
                        }),
                        match_label_keys: None,
                        mismatch_label_keys: None,
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 60,
                });
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "druid".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-druid".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "middlemanager".to_string(),
                                ),
                            ])),
                        }),
                        match_label_keys: None,
                        mismatch_label_keys: None,
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 40,
                });
            }
            DruidRole::Router => {
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "druid".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-druid".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "broker".to_string(),
                                ),
                            ])),
                        }),
                        match_label_keys: None,
                        mismatch_label_keys: None,
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 40,
                });
            }
            DruidRole::MiddleManager | DruidRole::Historical => {
                expected_affinities.push(WeightedPodAffinityTerm {
                    pod_affinity_term: PodAffinityTerm {
                        label_selector: Some(LabelSelector {
                            match_expressions: None,
                            match_labels: Some(BTreeMap::from([
                                ("app.kubernetes.io/name".to_string(), "hdfs".to_string()),
                                (
                                    "app.kubernetes.io/instance".to_string(),
                                    "simple-hdfs".to_string(),
                                ),
                                (
                                    "app.kubernetes.io/component".to_string(),
                                    "datanode".to_string(),
                                ),
                            ])),
                        }),
                        match_label_keys: None,
                        mismatch_label_keys: None,
                        namespace_selector: None,
                        namespaces: None,
                        topology_key: "kubernetes.io/hostname".to_string(),
                    },
                    weight: 50,
                });
            }
            _ => (),
        };

        assert_eq!(
            merged_config.affinity,
            StackableAffinity {
                pod_affinity: Some(PodAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(expected_affinities),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        ("app.kubernetes.io/name".to_string(), "druid".to_string(),),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-druid".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/component".to_string(),
                                            role.to_string(),
                                        )
                                    ]))
                                }),
                                match_label_keys: None,
                                mismatch_label_keys: None,
                                namespace_selector: None,
                                namespaces: None,
                                topology_key: "kubernetes.io/hostname".to_string(),
                            },
                            weight: 70
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: None,
                node_selector: None,
            }
        );
    }
}
