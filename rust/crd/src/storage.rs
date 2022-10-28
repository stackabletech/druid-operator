use stackable_operator::schemars::{self, JsonSchema};
use stackable_operator::{commons::resources::PvcConfig, config::merge::Merge};

use serde::{Deserialize, Serialize};

/// Storage configuration used by all roles except historical
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalStorage {
    pub segment_cache: PvcConfig,
}
