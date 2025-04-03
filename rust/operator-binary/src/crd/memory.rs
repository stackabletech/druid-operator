use std::{collections::BTreeMap, sync::LazyLock};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::resources::{NoRuntimeLimits, Resources},
    cpu::CpuQuantity,
    memory::{BinaryMultiple, MemoryQuantity},
};

use crate::crd::{
    PROCESSING_BUFFER_SIZE_BYTES, PROCESSING_NUM_MERGE_BUFFERS, PROCESSING_NUM_THREADS,
    storage::HistoricalStorage,
};

static MIN_HEAP_RATIO: f32 = 0.75;

pub static RESERVED_OS_MEMORY: LazyLock<MemoryQuantity> =
    LazyLock::new(|| MemoryQuantity::from_mebi(300.));

/// Max size for direct access buffers. This is defined in Druid to be 2GB:
/// <https://druid.apache.org/docs/latest/configuration/index.html#processing-1>
pub static MAX_DIRECT_BUFFER_SIZE: LazyLock<MemoryQuantity> =
    LazyLock::new(|| MemoryQuantity::from_gibi(2.));

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to parse memory limits"))]
    ParsingMemoryLimitFailure {
        source: stackable_operator::memory::Error,
    },
    #[snafu(display("failed to parse CPU limits"))]
    ParsingCpuLimitFailure {
        source: stackable_operator::cpu::Error,
    },
    #[snafu(display("could not derive memory distribution, no memory limits defined"))]
    NoMemoryLimitsDefined,
    #[snafu(display("could not derive memory distribution, no CPU limits defined"))]
    NoCpuLimitsDefined,
}

/// This struct takes the resource limits of the Pod and derives Druid settings from it.
/// For mentioned Druid properties, consult the
/// [Druid Configuration Reference](https://druid.apache.org/docs/latest/configuration/index.html)
/// for additional information.
/// Also have a look at the documentation for
/// [Basic Cluster Tuning](https://druid.apache.org/docs/latest/operations/basic-cluster-tuning.html).
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
            min_heap_ratio: MIN_HEAP_RATIO,
            os_reserved_memory: *RESERVED_OS_MEMORY,
            max_buffer_size: *MAX_DIRECT_BUFFER_SIZE,
        }
    }

    /// The total memory we use for druid. This is what's left after we take out the OS reserved memory.
    fn allocatable_memory(&self) -> MemoryQuantity {
        self.total_memory - self.os_reserved_memory
    }

    /// How much memory to set for the JVM to use. The minimum ratio can be defined in the struct.
    /// Once the direct memory is maxed out, all the remaining allocatable memory will be assigned
    /// as heap memory.
    pub fn heap_memory(&self) -> MemoryQuantity {
        // TODO also implement max limit of 24Gi, as recommended by Druid
        self.allocatable_memory() - self.direct_access_memory()
    }

    /// The memory that is available to allocate for direct access.
    fn allocatable_direct_access_memory(&self) -> MemoryQuantity {
        self.allocatable_memory() * (1. - self.min_heap_ratio)
    }

    /// The max memory to allocate to direct access. This is based on the max buffer size of a single buffer.
    fn max_direct_access_memory(&self) -> MemoryQuantity {
        self.max_buffer_size * self.total_num_buffers() as f32
    }

    /// How much to allocate (or keep free) for direct access.
    /// this is the amount to configure in the JVM as the `MaxDirectMemorySize`.
    pub fn direct_access_memory(&self) -> MemoryQuantity {
        if self.max_direct_access_memory() < self.allocatable_direct_access_memory() {
            self.max_direct_access_memory()
        } else {
            self.allocatable_direct_access_memory()
        }
    }

    /// The number of threads to use, based on the CPU millis.
    /// leaves at least 500m available to core functionalities.
    /// Druid Property: `druid.processing.numThreads`
    fn num_threads(&self) -> usize {
        (self.cpu_millis.as_cpu_count().round() - 1.).max(1.) as usize
    }

    /// Druid property: `druid.processing.numMergeBuffers`
    fn num_merge_buffers(&self) -> usize {
        ((self.num_threads() as f64 / 4.).floor() as usize).max(2)
    }

    fn total_num_buffers(&self) -> usize {
        self.num_merge_buffers() + self.num_threads() + 1
    }

    /// The buffer size for intermediate result storage. By setting it ourselves, we can set it up to 2Gi.
    /// If we leave it on the `auto` default, we only get up to 1Gi.
    /// Druid property: `druid.processing.buffer.sizeBytes`
    fn buffer_size(&self) -> MemoryQuantity {
        self.direct_access_memory() / self.total_num_buffers() as f32
    }

    /// Adds derived runtime settings to the given config
    pub fn add_settings(&self, config: &mut BTreeMap<String, Option<String>>) {
        config.insert(
            PROCESSING_NUM_THREADS.to_owned(),
            Some(self.num_threads().to_string()),
        );
        config.insert(
            PROCESSING_NUM_MERGE_BUFFERS.to_owned(),
            Some(self.num_merge_buffers().to_string()),
        );
        config.insert(
            PROCESSING_BUFFER_SIZE_BYTES.to_owned(),
            Some(format_for_druid(&self.buffer_size())),
        );
    }
}

impl TryFrom<&Resources<HistoricalStorage, NoRuntimeLimits>> for HistoricalDerivedSettings {
    type Error = Error;

    fn try_from(r: &Resources<HistoricalStorage, NoRuntimeLimits>) -> Result<Self, Self::Error> {
        let total_memory = MemoryQuantity::try_from(
            r.memory
                .limit
                .as_ref()
                .context(NoMemoryLimitsDefinedSnafu)?,
        )
        .context(ParsingMemoryLimitFailureSnafu)?;
        let cpu_millis =
            CpuQuantity::try_from(r.cpu.max.as_ref().context(NoCpuLimitsDefinedSnafu)?)
                .context(ParsingCpuLimitFailureSnafu)?;
        Ok(HistoricalDerivedSettings::new(total_memory, cpu_millis))
    }
}

/// A function to format something as the Druid Byte format:
/// `<https://druid.apache.org/docs/latest/configuration/human-readable-byte.html>`.
/// Only KiB precision is supported. Upd to 1KiB will be rounded away.
fn format_for_druid(memory_quantity: &MemoryQuantity) -> String {
    let k = memory_quantity.scale_to(BinaryMultiple::Kibi);
    // floor instead of round so we don't accidently make the memory quantity
    // bigger than it should be
    let v = k.value.floor() as usize;
    format!("{v}Ki")
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;

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
        let mem = MemoryQuantity::from_gibi(2.);
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
        let mem = MemoryQuantity::from_gibi(2.);
        let cpu = CpuQuantity::from_millis(cpu_millis);
        let s = HistoricalDerivedSettings::new(mem, cpu);
        assert_eq!(s.num_merge_buffers(), expected_num_merge_buffers);
    }
}
