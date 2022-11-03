use stackable_operator::{
    config::merge::Merge,
    schemars::{self, JsonSchema},
};

use serde::{Deserialize, Serialize};

/// Storage configuration used by all roles except historical
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Merge, PartialEq, Serialize, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalStorage {}
