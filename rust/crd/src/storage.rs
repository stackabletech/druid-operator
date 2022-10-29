use stackable_operator::builder::{ContainerBuilder, PodBuilder, VolumeBuilder};
use stackable_operator::config::merge::Merge;
use stackable_operator::k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use stackable_operator::schemars::{self, JsonSchema};

use serde::{Deserialize, Serialize};

use crate::SC_DIRECTORY;

/// Storage configuration used by all roles except historical
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidStorage {}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Merge, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalStorage {
    pub segment_cache_size: Option<Quantity>,
}

impl HistoricalStorage {
    /// Update the Pod with storage for the historical segment cache.
    pub fn update_container(&self, pb: &mut PodBuilder, cb: &mut ContainerBuilder) {
        cb.add_volume_mount("segment-cache", SC_DIRECTORY);
        pb.add_volume(
            VolumeBuilder::new("segment-cache")
                .with_empty_dir(Some(""), self.segment_cache_size.clone())
                .build(),
        );
    }

    /// This cannot fail (i.e. return Result) and must return always return a valid
    /// quantity.
    /// It computes the maximum segment cache size as xx% of the volume size.
    pub fn segment_cache_max_size(&self) -> String {
        if let Some(volume_size) = self.segment_cache_size.as_ref() {
            if let Some(start_of_unit) = volume_size.0.find(|c: char| c != '.' && !c.is_numeric()) {
                let (value, unit) = volume_size.0.split_at(start_of_unit);
                if let Ok(v) = value.parse::<f32>() {
                    return format!("{:.0}{unit}", v * 0.9);
                }
            }
        }
        "1g".to_string()
    }
}
