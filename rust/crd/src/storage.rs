use serde::{Deserialize, Serialize};
use stackable_operator::k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use stackable_operator::{
    config::{fragment::Fragment, merge::Merge},
    schemars::{self, JsonSchema},
};

/// Storage configuration used by all roles except historical
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
    #[fragment_attrs(serde(default))]
    pub segment_cache: FreePercentageEmptyDir,
}

#[derive(Clone, Debug, Fragment, PartialEq, JsonSchema)]
#[fragment_attrs(
    derive(Merge, Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq),
    serde(rename_all = "camelCase")
)]
pub struct FreePercentageEmptyDir {
    #[fragment_attrs(serde(default, skip_serializing_if = "Option::is_none"))]
    pub free_percentage: Option<u16>,
    #[fragment_attrs(serde(default))]
    pub empty_dir: CapacityEmptyDir,
}

/// Default values for the `segmentCache` property of the custom resource.
/// See also `Default` for `FreePercentageEmptyDirFragment` below.
impl Default for FreePercentageEmptyDir {
    fn default() -> Self {
        FreePercentageEmptyDir {
            free_percentage: Some(5),
            empty_dir: CapacityEmptyDir {
                capacity: Quantity("1G".to_string()),
                medium: Some("".to_string()),
            },
        }
    }
}

/// Default values for the `segmentCache` property of the custom resource.
/// See also `Default` for `FreePercentageEmptyDir` above.
impl Default for FreePercentageEmptyDirFragment {
    fn default() -> Self {
        FreePercentageEmptyDirFragment {
            free_percentage: Some(5),
            empty_dir: CapacityEmptyDirFragment {
                capacity: Some(Quantity("1G".to_string())),
                medium: Some("".to_string()),
            },
        }
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
