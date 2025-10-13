use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    kvp::{Annotations, Label, ObjectLabels},
    role_utils::RoleGroupRef,
};

use crate::crd::{
    DruidRole, METRICS_PORT, METRICS_PORT_NAME, security::DruidTlsSecurity, v1alpha1,
};

const METRICS_SERVICE_SUFFIX: &str = "metrics";
const HEADLESS_SERVICE_SUFFIX: &str = "headless";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },
}

/// The rolegroup headless [`Service`] is a service that allows direct access to the instances of a certain rolegroup
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_rolegroup_headless_service(
    druid: &v1alpha1::DruidCluster,
    druid_tls_security: &DruidTlsSecurity,
    druid_role: &DruidRole,
    role_group_ref: &RoleGroupRef<v1alpha1::DruidCluster>,
    object_labels: ObjectLabels<v1alpha1::DruidCluster>,
    selector: BTreeMap<String, String>,
) -> Result<Service, Error> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(rolegroup_headless_service_name(
                &role_group_ref.object_name(),
            ))
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(druid_tls_security.service_ports(druid_role)),
            selector: Some(selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label.
pub fn build_rolegroup_metrics_service(
    druid: &v1alpha1::DruidCluster,
    role_group_ref: &RoleGroupRef<v1alpha1::DruidCluster>,
    object_labels: ObjectLabels<v1alpha1::DruidCluster>,
    selector: BTreeMap<String, String>,
) -> Result<Service, Error> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(druid)
            .name(rolegroup_metrics_service_name(
                &role_group_ref.object_name(),
            ))
            .ownerreference_from_resource(druid, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(Label::try_from(("prometheus.io/scrape", "true")).context(LabelBuildSnafu)?)
            .with_annotations(prometheus_annotations())
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(metrics_service_ports()),
            selector: Some(selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

fn metrics_service_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: Some(METRICS_PORT_NAME.to_string()),
        port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }]
}

/// Returns the metrics rolegroup service name `<cluster>-<role>-<rolegroup>-<METRICS_SERVICE_SUFFIX>`.
fn rolegroup_metrics_service_name(role_group_ref_object_name: &str) -> String {
    format!("{role_group_ref_object_name}-{METRICS_SERVICE_SUFFIX}")
}

/// Returns the headless rolegroup service name `<cluster>-<role>-<rolegroup>-<HEADLESS_SERVICE_SUFFIX>`.
pub fn rolegroup_headless_service_name(role_group_ref_object_name: &str) -> String {
    format!("{role_group_ref_object_name}-{HEADLESS_SERVICE_SUFFIX}")
}

/// Common annotations for Prometheus
///
/// These annotations can be used in a ServiceMonitor.
///
/// see also <https://github.com/prometheus-community/helm-charts/blob/prometheus-27.32.0/charts/prometheus/values.yaml#L983-L1036>
fn prometheus_annotations() -> Annotations {
    Annotations::try_from([
        ("prometheus.io/path".to_owned(), "/metrics".to_owned()),
        ("prometheus.io/port".to_owned(), METRICS_PORT.to_string()),
        ("prometheus.io/scheme".to_owned(), "http".to_owned()),
        ("prometheus.io/scrape".to_owned(), "true".to_owned()),
    ])
    .expect("should be valid annotations")
}
