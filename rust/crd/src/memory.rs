use std::{collections::BTreeMap, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::resources::{NoRuntimeLimits, Resources},
    cpu::CpuQuantity,
    memory::{BinaryMultiple, MemoryQuantity},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    storage::HistoricalStorage, PROCESSING_BUFFER_SIZEBYTES, PROCESSING_NUMMERGEBUFFERS,
    PROCESSING_NUMTHREADS,
};

/// This Error cannot derive PartialEq because fragment::ValidationError doesn't derive it
#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to parse memory limits"))]
    ParsingMemoryLimitFailure {
        source: stackable_operator::error::Error,
    },
}

/// This struct takes the resource limits of the Pod and derives Druid settings from it.
/// For mentioned Druid properties, consult the
/// [Druid Configuration Reference](https://druid.apache.org/docs/latest/configuration/index.html)
/// for additional information.
/// Also have a look at the "Basic Cluster Tuning" documentation:
/// `<https://druid.apache.org/docs/latest/operations/basic-cluster-tuning.html>`
pub struct HistoricalDerivedSettings {
    total_memory: MemoryQuantity,
    cpu_millis: CpuQuantity,
    min_heap_ratio: f32,
    max_buffer_size: MemoryQuantity,
    os_reserved_memory: MemoryQuantity,
}

impl HistoricalDerivedSettings {
    pub fn new(total_memory: MemoryQuantity, cpu_millis: CpuQuantity) -> Self {
        Self {
            total_memory,
            cpu_millis,
            min_heap_ratio: 0.75,
            os_reserved_memory: MemoryQuantity::from_str("300Mi").unwrap(), // 300MB
            max_buffer_size: MemoryQuantity::from_str("2Gi").unwrap(), // 2GB, Druid recommended
        }
    }

    /// The total memory we use for druid. This is what's left after we take out the OS reserved memory.
    pub fn allocatable_memory(&self) -> MemoryQuantity {
        self.total_memory - self.os_reserved_memory
    }

    /// How much memory to set for the JVM to use.
    pub fn heap_memory(&self) -> MemoryQuantity {
        // TODO also implement max limit of 24Gi, as recommended by Druid
        self.allocatable_memory() - self.direct_access_memory()
    }

    /// The memory that is available to allocate for direct access.
    pub fn allocatable_direct_access_memory(&self) -> MemoryQuantity {
        self.allocatable_memory() * (1. - self.min_heap_ratio)
    }

    /// The max memory to allocate to direct access. This is based on the max buffer size of a single buffer.
    pub fn max_direct_access_memory(&self) -> MemoryQuantity {
        self.max_buffer_size * (self.num_merge_buffers() + self.num_threads() + 1) as f32
    }

    /// How much to allocate (or keep free) for direct access.
    /// this is the amount to configure in the JVM as the `MaxDirectMemorySize`.
    pub fn direct_access_memory(&self) -> MemoryQuantity {
        self.allocatable_direct_access_memory()
            .min(self.max_direct_access_memory())
    }

    /// The number of threads to use, based on the CPU millis.
    /// leaves at least 500m available to core functionalities.
    /// Druid Property: `druid.processing.numThreads`
    pub fn num_threads(&self) -> usize {
        (self.cpu_millis.as_cpu_count().round() - 1.).max(1.) as usize
    }

    /// Druid property: `druid.processing.numMergeBuffers`
    pub fn num_merge_buffers(&self) -> usize {
        ((self.num_threads() as f64 / 4.).floor() as usize).max(2)
    }

    /// The buffer size for intermediate result storage. By setting it ourselves, we can set it up to 2Gi.
    /// If we leave it on the `auto` default, we only get up to 1Gi.
    /// Druid property: `druid.processing.buffer.sizeBytes`
    pub fn buffer_size(&self) -> MemoryQuantity {
        self.direct_access_memory() / (self.num_threads() + self.num_merge_buffers() + 1) as f32
    }

    pub fn add_settings(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            PROCESSING_NUMTHREADS.to_owned(),
            Some(self.num_threads().to_string()),
        );
        config.insert(
            PROCESSING_NUMMERGEBUFFERS.to_owned(),
            Some(self.num_merge_buffers().to_string()),
        );
        config.insert(
            PROCESSING_BUFFER_SIZEBYTES.to_owned(),
            Some(self.buffer_size().druid_byte_format()),
        );
    }
}

impl TryFrom<&Resources<HistoricalStorage, NoRuntimeLimits>> for HistoricalDerivedSettings {
    type Error = Error;

    fn try_from(r: &Resources<HistoricalStorage, NoRuntimeLimits>) -> Result<Self, Self::Error> {
        let total_memory = MemoryQuantity::try_from(r.memory.limit.clone().unwrap())
            .context(ParsingMemoryLimitFailureSnafu)?;
        let cpu_millis = CpuQuantity::try_from(r.cpu.max.clone().unwrap()).unwrap(); // TODO no unwrap
        Ok(HistoricalDerivedSettings::new(total_memory, cpu_millis))
    }
}

/// A trait to format something as the Druid Byte format: `<https://druid.apache.org/docs/latest/configuration/human-readable-byte.html>`.
/// It supports human readable units, but only integer values, i.e. "1.5Gi" does not work, use "1536Mi" instead.
trait AsDruidByteFormat {
    fn druid_byte_format(&self) -> String;
}

impl AsDruidByteFormat for MemoryQuantity {
    fn druid_byte_format(&self) -> String {
        let k = self.scale_to(BinaryMultiple::Kibi);
        let v = k.value.round() as usize;
        format!("{v}Ki")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(1000, 1)]
    #[case(1400, 1)]
    #[case(1600, 1)]
    #[case(2000, 1)]
    #[case(2400, 1)]
    #[case(2600, 2)]
    #[case(3000, 2)]
    #[case(3400, 2)]
    #[case(3600, 3)]
    #[case(32_000, 31)]
    fn test_num_threads(#[case] cpu_millis: usize, #[case] expected_num_threads: usize) {
        let mem = MemoryQuantity::from_str("2Gi").unwrap();
        let cpu = CpuQuantity::from_millis(cpu_millis);
        let s = HistoricalDerivedSettings::new(mem, cpu);
        assert_eq!(s.num_threads(), expected_num_threads);
    }

    #[rstest]
    #[case(1000, 2)]
    #[case(2000, 2)]
    #[case(4000, 2)]
    #[case(8000, 2)]
    #[case(15_000, 3)]
    #[case(16_000, 3)]
    #[case(17_000, 4)]
    #[case(32_000, 7)]
    fn test_num_merge_buffers(
        #[case] cpu_millis: usize,
        #[case] expected_num_merge_buffers: usize,
    ) {
        let mem = MemoryQuantity::from_str("2Gi").unwrap();
        let cpu = CpuQuantity::from_millis(cpu_millis);
        let s = HistoricalDerivedSettings::new(mem, cpu);
        assert_eq!(s.num_merge_buffers(), expected_num_merge_buffers);
    }
}
