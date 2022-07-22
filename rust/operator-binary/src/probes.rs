use stackable_druid_crd::DruidRole;
use stackable_operator::{
    builder::ContainerBuilder,
    k8s_openapi::{
        api::core::v1::{HTTPGetAction, Probe},
        apimachinery::pkg::util::intstr::IntOrString,
    },
};

pub fn add_probes(container_builder: &mut ContainerBuilder, role: &DruidRole) {
    // /status/selfDiscovered:
    // Indicating whether the node has received a confirmation from the central node discovery mechanism (currently ZooKeeper) of the Druid cluster that the node has been added to the cluster.
    // Returns 200 OK response with empty body if the node has discovered itself and 503 SERVICE UNAVAILABLE if the node hasn't discovered itself yet.
    // It is recommended to not consider a Druid node "healthy" or "ready" in automated deployment/container management systems until it returns 200 OK response.
    // see https://druid.apache.org/docs/latest/operations/api-reference.html#process-information
    let startup_probe_path = "/status/selfDiscovered";
    let liveness_probe_path = "/status/selfDiscovered";

    let readiness_probe_path = match role {
        // /druid/broker/v1/readiness:
        // Returns if the Broker knows about all segments in the cluster.
        // This can be used to know when a Broker process is ready to be queried after a restart.
        // see https://druid.apache.org/docs/latest/operations/api-reference.html#broker
        DruidRole::Broker => "/druid/broker/v1/readiness",

        // /druid/historical/v1/readiness:
        // Returns if all segments in the local cache have been loaded.
        // This can be used to know when a Historical process is ready to be queried after a restart.
        // see https://druid.apache.org/docs/latest/operations/api-reference.html#historical
        DruidRole::Historical => "/druid/historical/v1/readiness",

        // For the other roles we use the normal discovery-check
        DruidRole::Coordinator | DruidRole::MiddleManager | DruidRole::Router => {
            "/status/selfDiscovered"
        }
    };

    container_builder.startup_probe(Probe {
        failure_threshold: Some(60), // 60 * 10s = 10min time to start up and register itself
        period_seconds: Some(10),
        timeout_seconds: Some(3),
        http_get: Some(HTTPGetAction {
            port: IntOrString::Int(role.get_http_port() as i32),
            path: Some(startup_probe_path.to_string()),
            ..HTTPGetAction::default()
        }),
        ..Probe::default()
    });
    container_builder.liveness_probe(Probe {
        failure_threshold: Some(6), // After not being healthy for 6 * 5s = 30s => restart
        period_seconds: Some(5),
        timeout_seconds: Some(3),
        http_get: Some(HTTPGetAction {
            port: IntOrString::Int(role.get_http_port() as i32),
            path: Some(liveness_probe_path.to_string()),
            ..HTTPGetAction::default()
        }),
        ..Probe::default()
    });
    container_builder.readiness_probe(Probe {
        failure_threshold: Some(1), // After not being healthy for 1 * 5s = 5s => take it out of the service
        period_seconds: Some(5),
        timeout_seconds: Some(3),
        http_get: Some(HTTPGetAction {
            port: IntOrString::Int(role.get_http_port() as i32),
            path: Some(readiness_probe_path.to_string()),
            ..HTTPGetAction::default()
        }),
        ..Probe::default()
    });
}
