use serde::{Deserialize, Serialize};
use stackable_operator::k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use stackable_operator::{
    config::{fragment::Fragment, merge::Merge},
    schemars::{self, JsonSchema},
};

/// TODO Storage configuration used by all roles except historical
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Debug, Default, PartialEq, Fragment, JsonSchema)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        JsonSchema,
        Merge,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase"),
    allow(clippy::derive_partial_eq_without_eq)
)]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, PartialEq, Fragment, JsonSchema)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        JsonSchema,
        Merge,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct HistoricalStorage {
    // TODO
    #[fragment_attrs(serde(default))]
    pub segment_cache: FreePercentageEmptyDir,
}

#[derive(Clone, Debug, Default, Fragment, PartialEq, JsonSchema)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        JsonSchema,
        Merge,
        PartialEq,
        Serialize,
    ),
    serde(rename_all = "camelCase")
)]
pub struct FreePercentageEmptyDir {
    #[fragment_attrs(serde(default, skip_serializing_if = "Option::is_none"))]
    pub free_percentage: Option<u16>,
    #[fragment_attrs(serde(default))]
    pub empty_dir: CapacityEmptyDir,
}

pub fn default_free_percentage_empty_dir() -> FreePercentageEmptyDir {
    FreePercentageEmptyDir {
        free_percentage: Some(5),
        empty_dir: CapacityEmptyDir {
            capacity: Quantity("1G".to_string()),
            medium: Some("".to_string()),
        },
    }
}

pub fn default_free_percentage_empty_dir_fragment() -> FreePercentageEmptyDirFragment {
    FreePercentageEmptyDirFragment {
        free_percentage: Some(5),
        empty_dir: CapacityEmptyDirFragment {
            capacity: Some(Quantity("1G".to_string())),
            medium: Some("".to_string()),
        },
    }
}

#[derive(Clone, Debug, Default, Fragment, PartialEq, JsonSchema)]
#[fragment_attrs(
    derive(
        Merge,
        Serialize,
        Deserialize,
        JsonSchema,
        Default,
        Debug,
        Clone,
        PartialEq
    ),
    serde(rename_all = "camelCase")
)]
pub struct CapacityEmptyDir {
    #[fragment_attrs(serde(default))]
    pub capacity: Quantity,
    #[fragment_attrs(serde(default, skip_serializing_if = "Option::is_none"))]
    pub medium: Option<String>,
}
