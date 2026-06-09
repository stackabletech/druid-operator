//! Builder for the static, role-specific `runtime.properties` defaults that were
//! previously injected by product-config's `recommendedValues`.
//!
//! Only includes a recommended value for a role where the property was
//! `required: true` for that role (verified against
//! `tests/templates/kuttl/smoke/53-assert.yaml.j2`). Dynamic, cluster-derived
//! values (ZooKeeper, extensions, metadata DB, deep storage, TLS, auth, ports,
//! resource-derived sizes) are added by the controller, not here.

use std::collections::BTreeMap;

use crate::crd::DruidRole;

/// Defaults rendered for every role.
const ALL_ROLES: &[(&str, &str)] = &[
    ("druid.startup.logging.logProperties", "true"),
    (
        "druid.monitoring.monitors",
        "[\"org.apache.druid.java.util.metrics.JvmMonitor\"]",
    ),
    ("druid.emitter", "prometheus"),
    ("druid.emitter.prometheus.strategy", "exporter"),
    ("druid.emitter.prometheus.namespace", "druid"),
    (
        "druid.indexer.logs.directory",
        "/stackable/var/druid/indexing-logs",
    ),
];

const BROKER: &[(&str, &str)] = &[("druid.processing.tmpDir", "/stackable/var/druid/processing")];

const COORDINATOR: &[(&str, &str)] = &[
    ("druid.coordinator.startDelay", "PT20S"),
    ("druid.coordinator.period", "PT20S"),
    ("druid.coordinator.asOverlord.enabled", "true"),
    (
        "druid.coordinator.asOverlord.overlordService",
        "druid/overlord",
    ),
    ("druid.indexer.queue.startDelay", "PT20S"),
    ("druid.indexer.runner.type", "remote"),
    ("druid.indexer.storage.type", "metadata"),
];

const HISTORICAL: &[(&str, &str)] = &[
    ("druid.historical.cache.useCache", "true"),
    ("druid.historical.cache.populateCache", "true"),
    ("druid.processing.tmpDir", "/stackable/var/druid/processing"),
];

const MIDDLEMANAGER: &[(&str, &str)] = &[
    (
        "druid.indexer.task.hadoopWorkingPath",
        "/stackable/var/druid/hadoop-tmp",
    ),
    (
        "druid.indexer.task.baseTaskDir",
        "/stackable/var/druid/task",
    ),
    (
        "druid.indexer.runner.javaOpts",
        "-server -Xms256m -Xmx256m -XX:MaxDirectMemorySize=300m -Duser.timezone=UTC -Dfile.encoding=UTF-8 -XX:+ExitOnOutOfMemoryError -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager",
    ),
];

const ROUTER: &[(&str, &str)] = &[
    ("druid.router.managementProxy.enabled", "true"),
    ("druid.router.http.numConnections", "25"),
];

/// Static `recommendedValues` defaults for a role, as `key -> value`.
pub fn defaults(role: &DruidRole) -> BTreeMap<String, String> {
    let role_specific: &[(&str, &str)] = match role {
        DruidRole::Broker => BROKER,
        DruidRole::Coordinator => COORDINATOR,
        DruidRole::Historical => HISTORICAL,
        DruidRole::MiddleManager => MIDDLEMANAGER,
        DruidRole::Router => ROUTER,
    };
    ALL_ROLES
        .iter()
        .chain(role_specific.iter())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // All expected values below are copied verbatim from the runtime.properties
    // blocks of tests/templates/kuttl/smoke/53-assert.yaml.j2.

    #[test]
    fn common_defaults_present_for_every_role() {
        for role in [
            DruidRole::Broker,
            DruidRole::Coordinator,
            DruidRole::Historical,
            DruidRole::MiddleManager,
            DruidRole::Router,
        ] {
            let p = defaults(&role);
            assert_eq!(p["druid.emitter"], "prometheus".to_string());
            assert_eq!(p["druid.emitter.prometheus.namespace"], "druid".to_string());
            assert_eq!(
                p["druid.emitter.prometheus.strategy"],
                "exporter".to_string()
            );
            assert_eq!(
                p["druid.monitoring.monitors"],
                "[\"org.apache.druid.java.util.metrics.JvmMonitor\"]".to_string()
            );
            assert_eq!(
                p["druid.indexer.logs.directory"],
                "/stackable/var/druid/indexing-logs".to_string()
            );
            assert_eq!(p["druid.startup.logging.logProperties"], "true".to_string());
        }
    }

    #[test]
    fn processing_tmpdir_only_for_broker_and_historical() {
        // 53-assert: present for broker + historical, ABSENT for the other three.
        assert!(defaults(&DruidRole::Broker).contains_key("druid.processing.tmpDir"));
        assert!(defaults(&DruidRole::Historical).contains_key("druid.processing.tmpDir"));
        assert!(!defaults(&DruidRole::Coordinator).contains_key("druid.processing.tmpDir"));
        assert!(!defaults(&DruidRole::MiddleManager).contains_key("druid.processing.tmpDir"));
        assert!(!defaults(&DruidRole::Router).contains_key("druid.processing.tmpDir"));
    }

    #[test]
    fn coordinator_defaults_match_snapshot() {
        let p = defaults(&DruidRole::Coordinator);
        assert_eq!(
            p["druid.coordinator.asOverlord.enabled"],
            "true".to_string()
        );
        assert_eq!(
            p["druid.coordinator.asOverlord.overlordService"],
            "druid/overlord".to_string()
        );
        assert_eq!(p["druid.coordinator.period"], "PT20S".to_string());
        assert_eq!(p["druid.coordinator.startDelay"], "PT20S".to_string());
        assert_eq!(p["druid.indexer.queue.startDelay"], "PT20S".to_string());
        assert_eq!(p["druid.indexer.runner.type"], "remote".to_string());
        assert_eq!(p["druid.indexer.storage.type"], "metadata".to_string());
    }

    #[test]
    fn historical_defaults_match_snapshot() {
        let p = defaults(&DruidRole::Historical);
        assert_eq!(p["druid.historical.cache.useCache"], "true".to_string());
        assert_eq!(
            p["druid.historical.cache.populateCache"],
            "true".to_string()
        );
    }

    #[test]
    fn middlemanager_javaopts_exact() {
        let p = defaults(&DruidRole::MiddleManager);
        assert_eq!(
            p["druid.indexer.runner.javaOpts"],
            "-server -Xms256m -Xmx256m -XX:MaxDirectMemorySize=300m -Duser.timezone=UTC -Dfile.encoding=UTF-8 -XX:+ExitOnOutOfMemoryError -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager"
        );
        assert_eq!(
            p["druid.indexer.task.baseTaskDir"],
            "/stackable/var/druid/task".to_string()
        );
        assert_eq!(
            p["druid.indexer.task.hadoopWorkingPath"],
            "/stackable/var/druid/hadoop-tmp".to_string()
        );
    }

    #[test]
    fn router_defaults_match_snapshot() {
        let p = defaults(&DruidRole::Router);
        assert_eq!(
            p["druid.router.managementProxy.enabled"],
            "true".to_string()
        );
        assert_eq!(p["druid.router.http.numConnections"], "25".to_string());
    }
}
