//! Calculate how much memory to allocate where

pub struct RuntimeSettings {
    total_memory: usize,
    cpu_millis: usize,
    min_heap_ratio: f64,
    max_buffer_size: usize,
    os_reserved_memory: usize,
}

impl RuntimeSettings {
    pub fn new(total_memory: usize, cpu_millis: usize) -> Self {
        Self {
            total_memory,
            cpu_millis,
            min_heap_ratio: 0.75,
            os_reserved_memory: 300_000_000, // 300MB
            max_buffer_size: 2_000_000_000,  // 2GB, Druid recommended
        }
    }

    /// The total memory we use for druid. This is what's left after we take out the OS reserved memory.
    pub fn allocatable_memory(&self) -> usize {
        self.total_memory - self.os_reserved_memory
    }

    pub fn heap_memory(&self) -> usize {
        self.allocatable_memory() - self.direct_access_memory()
    }

    /// The memory that is available to allocate for direct access.
    pub fn allocatable_direct_access_memory(&self) -> usize {
        ((self.allocatable_memory() as f64) * (1. - self.min_heap_ratio)).round() as usize
    }

    /// The max memory to allocate to direct access. This is based on the max buffer size of a single buffer.
    pub fn max_direct_access_memory(&self) -> usize {
        self.max_buffer_size * (self.num_merge_buffers() + self.num_threads() + 1)
    }

    /// How much to allocate (or keep free) for direct access.
    pub fn direct_access_memory(&self) -> usize {
        self.allocatable_direct_access_memory()
            .min(self.max_direct_access_memory())
    }

    /// The number of threads to use, based on the CPU millis.
    /// leaves at least 500m available to core functionalities.
    pub fn num_threads(&self) -> usize {
        (((self.cpu_millis as f64) / 1000.).round() as usize - 1).max(1)
    }

    pub fn num_merge_buffers(&self) -> usize {
        ((self.num_threads() as f64 / 4.).floor() as usize).max(2)
    }

    pub fn buffer_size(&self) -> usize {
        ((self.direct_access_memory() as f64)
            / (self.num_threads() + self.num_merge_buffers() + 1) as f64)
            .round() as usize
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
        let s = RuntimeSettings::new(2_000_000_000, cpu_millis);
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
        let s = RuntimeSettings::new(2_000_000_000, cpu_millis);
        assert_eq!(s.num_merge_buffers(), expected_num_merge_buffers);
    }
}
