use serde::{Deserialize, Serialize};
use stackable_operator::{
    config::{fragment::Fragment, merge::Merge},
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    schemars::{self, JsonSchema},
};

/// This role does not have any storage settings.
/// Only the Historical role uses disk storage.
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

/// The storage settings for the Historical process.
/// Read more in the
/// [storage and resource documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/resources-and-storage#_historical_resources).
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
    /// Configure the size and backing storage type of the Druid segment cache.
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
    /// How much of the configured storage to keep free. Defaults to 5%.
    #[fragment_attrs(serde(default, skip_serializing_if = "Option::is_none"))]
    pub free_percentage: Option<u16>,
    /// Configuration settings for the empty dir volume where the cache is located.
    #[fragment_attrs(serde(default))]
    pub empty_dir: CapacityEmptyDir,
}

#[cfg(test)]
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
    /// The size of the empty dir volume.
    /// This size is also configured as the segment cache size in Druid
    /// (minus the freePercentage).
    /// Specified as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/),
    /// which means these suffixes are supported: E, P, T, G, M, k.
    /// You can also use the power-of-two equivalents: Ei, Pi, Ti, Gi, Mi, Ki.
    /// For example, the following represent roughly the same value: 128974848, 129e6, 129M, 128974848000m, 123Mi
    #[fragment_attrs(serde(default))]
    pub capacity: Quantity,
    /// The `medium` field controls where the `emptyDir` is stored.
    /// By default it is stored on the default storage backing the node the Pod is running on.
    /// Read more about [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
    /// in the Kubernetes documentation.
    #[fragment_attrs(serde(default, skip_serializing_if = "Option::is_none"))]
    pub medium: Option<String>,
}
