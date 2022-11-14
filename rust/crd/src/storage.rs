use stackable_operator::{
    config::{fragment::Fragment, merge::Merge},
    schemars::{self, JsonSchema},
};

use serde::{Deserialize, Serialize};

/// Storage configuration used by all roles except historical
#[derive(Clone, Debug, Default, Eq, PartialEq, Fragment, JsonSchema)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        JsonSchema,
        Merge,
        Eq,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, Eq, PartialEq, Fragment, JsonSchema)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        JsonSchema,
        Merge,
        Eq,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct HistoricalStorage {}
