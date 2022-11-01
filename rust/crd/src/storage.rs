use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder, VolumeBuilder},
    config::merge::Merge,
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    schemars::{self, JsonSchema},
};

use serde::{Deserialize, Serialize};

use crate::{SC_DIRECTORY, SC_VOLUME_NAME};

/// Storage configuration used by all roles except historical
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Merge, PartialEq, Serialize, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalStorage {
    pub segment_cache_size_gb: Option<u16>,
}

impl HistoricalStorage {
    /// Update the Pod with storage for the historical segment cache.
    pub fn update_container(&self, pb: &mut PodBuilder, cb: &mut ContainerBuilder) {
        let volume_size = match self.segment_cache_size_gb {
            Some(v) => v,
            _ => 1,
        };
        cb.add_volume_mount(SC_VOLUME_NAME, SC_DIRECTORY);
        pb.add_volume(
            VolumeBuilder::new(SC_VOLUME_NAME)
                .with_empty_dir(Some(""), Some(Quantity(format!("{}G", volume_size))))
                .build(),
        );
    }

    /// This cannot fail (i.e. return Result) and must always return a valid quantity.
    /// It computes the maximum segment cache size as 90% of the volume size.
    pub fn segment_cache_max_size(&self) -> String {
        if let Some(volume_size) = self.segment_cache_size_gb {
            if volume_size > 1u16 {
                return format!("{:.0}m", volume_size as f32 * 1024.0 * 0.9);
            }
        }
        "900m".to_string()
    }
}
