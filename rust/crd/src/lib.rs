pub mod commands;
pub mod error;

use crate::commands::{Restart, Start, Stop};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::schemars::_serde_json::Value;
use kube::api::ApiResource;
use kube::CustomResource;
use kube::CustomResourceExt;
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::command::{CommandRef, HasCommands, HasRoleRestartOrder};
use stackable_operator::controller::HasOwned;
use stackable_operator::crd::HasApplication;
use stackable_operator::identity::PodToNodeMapping;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::Role;
use stackable_operator::status::{
    ClusterExecutionStatus, Conditions, HasClusterExecutionStatus, HasCurrentCommand, Status,
    Versioned,
};
use stackable_operator::versioning::{ProductVersion, Versioning, VersioningState};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;

pub const APP_NAME: &str = "druid";
pub const CONF_DIR: &str = "conf";

pub const JVM_CONFIG: &str = "jvm.config";
pub const RUNTIME_PROPS: &str = "runtime.properties";
pub const LOG4J2_CONFIG: &str = "log4j2.xml";

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "druid.stackable.tech",
    version = "v1alpha1",
    kind = "DruidCluster",
    plural = "druidclusters",
    shortname = "druid",
    namespaced
)]
#[kube(status = "DruidClusterStatus")]
pub struct DruidClusterSpec {
    pub version: DruidVersion,
    pub coordinators: Role<DruidConfig>,
    // TODO zookeeper reference
}

#[derive(
    Clone, Debug, Deserialize, Display, EnumIter, Eq, Hash, JsonSchema, PartialEq, Serialize, EnumString
)]
pub enum DruidRole {
    #[strum(serialize = "coordinator")]
    Coordinator,
    #[strum(serialize = "broker")]
    Broker,
    #[strum(serialize = "historical")]
    Historical,
    #[strum(serialize = "middleManager")]
    MiddleManager,
    #[strum(serialize = "router")]
    Router,
}

impl DruidRole {
    /// Returns the start commands for the different server types.
    pub fn get_command(
        &self,
        version: &DruidVersion,
    ) -> Vec<String> {
        vec![
            format!("{}/stackable/run-druid", version.package_name()),
            self.to_string(),
            format!("{{configroot}}/{}", CONF_DIR),
        ]
    }
}

impl Status<DruidClusterStatus> for DruidCluster {
    fn status(&self) -> &Option<DruidClusterStatus> {
        &self.status
    }
    fn status_mut(&mut self) -> &mut Option<DruidClusterStatus> {
        &mut self.status
    }
}

impl HasRoleRestartOrder for DruidCluster {
    fn get_role_restart_order() -> Vec<String> {
        // TODO verify if this order is correct
        vec![
            todo!(),
        ]
    }
}

impl HasCommands for DruidCluster {
    fn get_command_types() -> Vec<ApiResource> {
        vec![
            Start::api_resource(),
            Stop::api_resource(),
            Restart::api_resource(),
        ]
    }
}

impl HasOwned for DruidCluster {
    fn owned_objects() -> Vec<&'static str> {
        vec![Restart::crd_name(), Start::crd_name(), Stop::crd_name()]
    }
}

impl HasApplication for DruidCluster {
    fn get_application_name() -> &'static str {
        APP_NAME
    }
}

impl HasClusterExecutionStatus for DruidCluster {
    fn cluster_execution_status(&self) -> Option<ClusterExecutionStatus> {
        self.status
            .as_ref()
            .and_then(|status| status.cluster_execution_status.clone())
    }

    fn cluster_execution_status_patch(&self, execution_status: &ClusterExecutionStatus) -> Value {
        json!({ "clusterExecutionStatus": execution_status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidConfig {

    // misc
    pub java_home: Option<String>,  // needs to be java 8!
}

impl Configuration for DruidConfig {
    type Configurable = DruidCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Readd if we want jmx metrics gathered
        //if let Some(metrics_port) = self.metrics_port {
        //    result.insert(METRICS_PORT.to_string(), Some(metrics_port.to_string()));
        // }
        Ok(result)
    }

    fn compute_cli(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
        _file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Insert configs here

        Ok(result)
    }
}

#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
)]
pub enum DruidVersion {
    #[serde(rename = "0.22.0")]
    #[strum(serialize = "0.22.0")]
    v0_22_0,
}

impl DruidVersion {
    pub fn package_name(&self) -> String {
        format!("apache-druid-{}", self.to_string())
    }
}

impl Versioning for DruidVersion {
    fn versioning_state(&self, other: &Self) -> VersioningState {
        let from_version = match Version::parse(&self.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    self.to_string(),
                    e.to_string()
                ))
            }
        };

        let to_version = match Version::parse(&other.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    other.to_string(),
                    e.to_string()
                ))
            }
        };

        match to_version.cmp(&from_version) {
            Ordering::Greater => VersioningState::ValidUpgrade,
            Ordering::Less => VersioningState::ValidDowngrade,
            Ordering::Equal => VersioningState::NoOp,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidClusterStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ProductVersion<DruidVersion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<PodToNodeMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_command: Option<CommandRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_execution_status: Option<ClusterExecutionStatus>,
}

impl Versioned<DruidVersion> for DruidClusterStatus {
    fn version(&self) -> &Option<ProductVersion<DruidVersion>> {
        &self.version
    }
    fn version_mut(&mut self) -> &mut Option<ProductVersion<DruidVersion>> {
        &mut self.version
    }
}

impl Conditions for DruidClusterStatus {
    fn conditions(&self) -> &[Condition] {
        self.conditions.as_slice()
    }
    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }
}

impl HasCurrentCommand for DruidClusterStatus {
    fn current_command(&self) -> Option<CommandRef> {
        self.current_command.clone()
    }
    fn set_current_command(&mut self, command: CommandRef) {
        self.current_command = Some(command);
    }
    fn clear_current_command(&mut self) {
        self.current_command = None
    }
    fn tracking_location() -> &'static str {
        "/status/currentCommand"
    }
}

#[cfg(test)]
mod tests {
    use crate::DruidVersion;
    use stackable_operator::versioning::{Versioning, VersioningState};
    use std::str::FromStr;

    #[test]
    fn test_druid_version_versioning() {
        todo!();
    }

    #[test]
    #[test]
    fn test_version_conversion() {
        // TODO: Adapt to correct product version
        // DruidVersion::from_str("3.4.14").unwrap();
    }

    #[test]
    fn test_package_name() {
        assert_eq!(
            DruidVersion::v0_22_0.package_name(),
            format!("apache-druid-{}", DruidVersion::v0_22_0.to_string())
        );
    }
}
