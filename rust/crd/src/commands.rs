use crate::DruidRole;
use duplicate::duplicate;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::k8s_openapi::chrono::Utc;
use stackable_operator::kube::CustomResource;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.druid.stackable.tech",
    version = "v1alpha1",
    kind = "Restart",
    plural = "restarts",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct RestartCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<DruidRole>>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.druid.stackable.tech",
    version = "v1alpha1",
    kind = "Start",
    plural = "starts",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct StartCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<DruidRole>>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.druid.stackable.tech",
    version = "v1alpha1",
    kind = "Stop",
    plural = "stops",
    namespaced,
    kube_core = "stackable_operator::kube::core",
    k8s_openapi = "stackable_operator::k8s_openapi",
    schemars = "stackable_operator::schemars"
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct StopCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<DruidRole>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Time>,
}
