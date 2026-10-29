//! Builds the rolegroup [`StatefulSet`] from a role group's [`RoleGroupBuilder`].
//!
//! Everything this needs is already resolved on the builder, so it reads straight through: open
//! the pod, add the containers and volumes gathered for the role group, close it.

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, security::PodSecurityContextBuilder},
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::apps::v1::{StatefulSet, StatefulSetSpec},
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
};

use crate::controller::build::{
    object_meta, recommended_labels_for_role_group_resources, role_group::RoleGroupBuilder,
    role_group_selector,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to set the termination grace period"))]
    TerminationGracePeriod {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The role group's [`StatefulSet`].
pub(crate) fn build_statefulset(builder: &RoleGroupBuilder) -> Result<StatefulSet> {
    let cluster = builder.cluster;
    let role = &builder.role;
    let role_group_name = &builder.role_group_name;
    let resource_names = cluster.role_group_resource_names(role, role_group_name);

    let mut pb = PodBuilder::new();
    pb.affinity(&builder.affinity);
    // This must be always set by the merge mechanism, as we provide a default value,
    // users can not disable graceful shutdown.
    if let Some(termination_grace_period) = &builder.graceful_shutdown_timeout {
        pb.termination_grace_period(termination_grace_period)
            .context(TerminationGracePeriodSnafu)?;
    }

    // The volumes in the order the builder gathered them, which is part of the pod template
    // (pinned by `pod_volumes_keep_their_order` in `build/mod.rs`). A volume whose name collides
    // with another volume's is rejected here.
    pb.add_volumes(builder.pod_volumes.clone())
        .context(AddVolumeSnafu)?;

    let metadata = ObjectMetaBuilder::new()
        .with_labels(recommended_labels_for_role_group_resources(
            cluster,
            role,
            role_group_name,
        ))
        .build();

    pb.image_pull_secrets_from_product_image(&cluster.image)
        .metadata(metadata)
        .service_account_name(
            cluster
                .cluster_resource_names()
                .service_account_name()
                .to_string(),
        )
        .security_context(
            PodSecurityContextBuilder::with_stackable_defaults()
                .fs_group(1000)
                .build(),
        );
    for init_container in &builder.init_containers {
        pb.add_init_container(init_container.clone());
    }
    for container in &builder.containers {
        pb.add_container(container.clone());
    }

    let mut pod_template = pb.build_template();
    // The role and rolegroup pod overrides were already merged (rolegroup wins) during validation.
    pod_template.merge_from(builder.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: object_meta(
            cluster,
            resource_names.stateful_set_name().to_string(),
            recommended_labels_for_role_group_resources(cluster, role, role_group_name),
        )
        .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
        .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            // Leave `replicas` unset when the role group does not specify a count, so a
            // HorizontalPodAutoscaler can own the replica count without the operator fighting it.
            replicas: builder.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(role_group_selector(cluster, role, role_group_name).into()),
                ..LabelSelector::default()
            },
            service_name: Some(resource_names.headless_service_name().to_string()),
            template: pod_template,
            volume_claim_templates: builder.volume_claim_templates.clone(),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stackable_operator::{
        k8s_openapi::api::core::v1::{ConfigMapVolumeSource, Volume},
        v2::types::operator::RoleGroupName,
    };

    use super::*;
    use crate::{
        controller::{
            build::{
                Error as BuildError, build,
                container::{CONTAINERDEBUG_LOG_DIRECTORY, LOG_VOLUME_NAME},
                role_group,
                test_support::role_group_stateful_set,
            },
            validate::test_support::{MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster},
        },
        crd::{Container, DruidRole},
    };

    /// The user-supplied `envOverrides` must be merged in after all operator-set environment
    /// variables, so that they can override any of them. `CONTAINERDEBUG_LOG_DIRECTORY` is used
    /// as the example here because it is set unconditionally by the operator.
    #[test]
    fn env_overrides_override_operator_set_env_vars() {
        let druid = druid_from_yaml(
            r#"
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
    envOverrides:
      CONTAINERDEBUG_LOG_DIRECTORY: /custom/log/dir
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
"#,
        );
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");

        let env = role_group_stateful_set(
            &resources,
            &cluster,
            &DruidRole::Broker,
            &RoleGroupName::from_str("default").expect("valid role group name"),
        )
        .spec
        .as_ref()
        .expect("the StatefulSet has a spec")
        .template
        .spec
        .as_ref()
        .expect("the pod template has a spec")
        .containers
        .iter()
        .find(|container| container.name == Container::Druid.name().as_ref())
        .expect("the druid container exists")
        .env
        .as_ref()
        .expect("the druid container has env vars");

        let containerdebug: Vec<_> = env
            .iter()
            .filter(|env_var| env_var.name == CONTAINERDEBUG_LOG_DIRECTORY.as_ref())
            .collect();
        assert_eq!(
            containerdebug.len(),
            1,
            "the override must replace the operator-set value, not duplicate it"
        );
        assert_eq!(containerdebug[0].value.as_deref(), Some("/custom/log/dir"));
    }

    /// A user-supplied extra volume whose name collides with an operator-managed volume must be
    /// reported as an error (the operator's own volumes are gathered first, so the collision
    /// must surface on the user-supplied side when the volumes are added to the pod, never as a
    /// panic).
    #[test]
    fn extra_volume_colliding_with_operator_volume_is_an_error() {
        let mut druid = druid_from_yaml(MINIMAL_DRUID_YAML);
        druid.spec.cluster_config.extra_volumes = vec![user_volume(LOG_VOLUME_NAME.as_ref())];
        let cluster = validated_cluster(&druid);

        let Err(error) = build(&cluster) else {
            panic!("the colliding extra volume must be rejected");
        };
        assert!(
            matches!(
                error,
                BuildError::RoleGroup {
                    source: role_group::Error::StatefulSet {
                        source: Error::AddVolume { .. },
                    },
                    ..
                }
            ),
            "unexpected error: {error:?}"
        );
    }

    fn user_volume(name: &str) -> Volume {
        Volume {
            name: name.to_owned(),
            config_map: Some(ConfigMapVolumeSource {
                name: "user-cm".to_owned(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        }
    }
}
