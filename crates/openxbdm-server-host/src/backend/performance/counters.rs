//! Simulated performance counter directory and sampler.

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::performance::COUNTER_NAME_CAPACITY;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::counters;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::commands::performance::counters::CounterObject;
use openxbdm_server::commands::performance::counters::CounterRegistration;
use openxbdm_server::commands::performance::counters::Evaluation;

/// Source word layout: eight page counts, then per-processor idle, DPC,
/// and ISR time pairs (time, tick count) directly after them, then the GPU
/// pairs.
pub const PAGES: usize = 0;
pub const THREADS: usize = 8;
pub const GPU: usize = THREADS + 36;
const SOURCE_WORDS: usize = GPU + 8;

/// Header bytes simulated before each counter object.
const OBJECT_HEADER: usize = 0x10;
/// Number of sampler buckets.
const BUCKETS: u32 = 10;

/// Where a simulated counter reads its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A value and rate word pair starting at this source word.
    Words(usize),
    /// The title's frame counter.
    Frames,
    /// The title's frame tick counter.
    FrameTicks,
}

/// A simulated counter object.
#[derive(Debug, Clone)]
pub struct Counter {
    pub name: Vec<u8>,
    pub source: Source,

    image: [u8; OBJECT_HEADER + counters::OBJECT_SIZE],
    /// Sampler bucket of the next visit.
    bucket: Option<u32>,
}

impl Counter {
    pub fn registration(&self) -> CounterRegistration {
        CounterRegistration(u32::from_be_bytes(
            self.image[OBJECT_HEADER + 8..OBJECT_HEADER + 12]
                .try_into()
                .unwrap(),
        ))
    }
}

/// Simulated counter directory and its sources.
#[derive(Debug, Clone)]
pub struct Counters {
    /// The counter directory exists.
    pub directory: bool,
    /// Objects in directory order.
    pub objects: Vec<Counter>,
    /// Counters named here exist but cannot be opened.
    pub locked: Vec<Vec<u8>>,

    pub sources: [u32; SOURCE_WORDS],
    /// Frame counter registered by the title's graphics runtime.
    pub frame_counter: Option<u32>,
    pub frame_ticks: Option<u32>,

    bucket: u32,
}

impl Default for Counters {
    fn default() -> Self {
        /// One counter the console registers at startup.
        struct BuiltIn {
            name: &'static str,
            registration: u32,
            source: Source,
        }

        /// Built-in counters in the order the counter directory enumerates
        /// them.
        const BUILT_IN_COUNTERS: &[BuiltIn] = &[
            BuiltIn {
                name: "%Thread5 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 16),
            },
            BuiltIn {
                name: "Debugger Pages",
                registration: 0x0002_0001,
                source: Source::Words(7),
            },
            BuiltIn {
                name: "Contiguous Pages",
                registration: 0x0002_0001,
                source: Source::Words(6),
            },
            BuiltIn {
                name: "%Thread3 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 11),
            },
            BuiltIn {
                name: "% GPU Frontend",
                registration: 0x0002_0021,
                source: Source::Words(GPU + 2),
            },
            BuiltIn {
                name: "%Thread2 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 7),
            },
            BuiltIn {
                name: "VM Pages",
                registration: 0x0002_0001,
                source: Source::Words(5),
            },
            BuiltIn {
                name: "Pool Pages",
                registration: 0x0002_0001,
                source: Source::Words(3),
            },
            BuiltIn {
                name: "%Thread0 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 2),
            },
            BuiltIn {
                name: "Frame Ticks",
                registration: 0x0001_0001,
                source: Source::FrameTicks,
            },
            BuiltIn {
                name: "Image Pages",
                registration: 0x0002_0001,
                source: Source::Words(2),
            },
            BuiltIn {
                name: "%Thread4 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 14),
            },
            BuiltIn {
                name: "Frames",
                registration: 0x0001_0011,
                source: Source::Frames,
            },
            BuiltIn {
                name: "%Thread1 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 5),
            },
            BuiltIn {
                name: "%Thread0 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2),
            },
            BuiltIn {
                name: "Cache Pages",
                registration: 0x0002_0001,
                source: Source::Words(1),
            },
            BuiltIn {
                name: "%Thread3 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 10),
            },
            BuiltIn {
                name: "% GPU Backend",
                registration: 0x0002_0021,
                source: Source::Words(GPU + 4),
            },
            BuiltIn {
                name: "Stack Pages",
                registration: 0x0002_0001,
                source: Source::Words(4),
            },
            BuiltIn {
                name: "% GPU",
                registration: 0x0002_0021,
                source: Source::Words(GPU),
            },
            BuiltIn {
                name: "%Thread2 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 8),
            },
            BuiltIn {
                name: "%Thread5 ISR",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 17),
            },
            BuiltIn {
                name: "%Thread4 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 13),
            },
            BuiltIn {
                name: "%Thread2 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 6),
            },
            BuiltIn {
                name: "%Thread1 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 3),
            },
            BuiltIn {
                name: "% GPU Swap Stall",
                registration: 0x0002_0021,
                source: Source::Words(GPU + 6),
            },
            BuiltIn {
                name: "Free Pages",
                registration: 0x0002_0001,
                source: Source::Words(0),
            },
            BuiltIn {
                name: "%Thread5 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 15),
            },
            BuiltIn {
                name: "%Thread4 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 12),
            },
            BuiltIn {
                name: "%Thread3 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 9),
            },
            BuiltIn {
                name: "%Thread1 DPC",
                registration: 0x0002_0021,
                source: Source::Words(THREADS + 2 * 4),
            },
            BuiltIn {
                name: "%Thread0 Idle",
                registration: 0x0002_0021,
                source: Source::Words(THREADS),
            },
        ];

        let mut counters = Self {
            directory: true,
            objects: Vec::new(),
            locked: Vec::new(),
            sources: [0; SOURCE_WORDS],
            frame_counter: None,
            frame_ticks: None,
            bucket: 0,
        };

        for counter in BUILT_IN_COUNTERS {
            counters.register(
                counter.name.as_bytes(),
                CounterRegistration(counter.registration),
                counter.source,
            );
        }

        counters
    }
}

impl Counters {
    /// Create a counter object; periods above ten are rejected.
    pub fn register(
        &mut self,
        name: &[u8],
        registration: CounterRegistration,
        source: Source,
    ) -> bool {
        let period = registration.period();
        if period > counters::MAX_PERIOD {
            return false;
        }

        let mut counter = Counter {
            name: name.to_vec(),
            source,
            image: [0; OBJECT_HEADER + counters::OBJECT_SIZE],
            bucket: (period != 0).then(|| (self.bucket + period) % BUCKETS),
        };
        counters::initialize(
            &mut View {
                counter: &mut counter,
                sources: &self.snapshot(),
            },
            registration,
        );
        self.objects.push(counter);

        true
    }

    /// One sampler tick: visit the counters due in the current bucket.
    pub fn tick(&mut self, tick_count: u32) {
        let sources = self.snapshot();
        let frame_number = self.frame_counter.unwrap_or(0);

        for counter in &mut self.objects {
            if counter.bucket != Some(self.bucket) {
                continue;
            }

            let period = counter.registration().period();
            // SAFETY: `register` initializes every object and only `sample`
            // writes its history index.
            unsafe {
                counters::sample(
                    &mut View {
                        counter,
                        sources: &sources,
                    },
                    tick_count,
                    frame_number,
                )
            };
            counter.bucket = Some((self.bucket + period) % BUCKETS);
        }

        self.bucket = (self.bucket + 1) % BUCKETS;
    }

    /// Directory entry at `context`, which advances past it.
    pub(super) fn next(
        &self,
        context: &mut u32,
        name: &mut [u8; COUNTER_NAME_CAPACITY],
    ) -> Result<CounterEntry, CounterError> {
        if !self.directory {
            return Err(CounterError::End);
        }

        let Some(counter) = self.objects.get(*context as usize) else {
            return Err(CounterError::End);
        };
        *context += 1;

        if counter.name.len() >= COUNTER_NAME_CAPACITY {
            return Err(CounterError::NameTooLong);
        }

        name[..counter.name.len()].copy_from_slice(&counter.name);

        Ok(CounterEntry {
            name_len: counter.name.len(),
            counter_type: counter.registration().counter_type(),
        })
    }

    /// Evaluate the counter `name`, matched without regard to case.
    pub(super) fn query(
        &mut self,
        name: &[u8],
        query: counters::CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        if !self.directory {
            return Err(CounterError::NoDirectory);
        }

        let sources = self.snapshot();
        let locked = self
            .locked
            .iter()
            .any(|locked| locked.eq_ignore_ascii_case(name));
        let Some(counter) = self
            .objects
            .iter_mut()
            .find(|counter| counter.name.eq_ignore_ascii_case(name))
        else {
            return Err(CounterError::NotFound);
        };
        if locked {
            return Err(CounterError::NotFound);
        }

        // SAFETY: `register` initializes every object and only `sample`
        // writes its history index.
        unsafe {
            counters::query(
                &mut View {
                    counter,
                    sources: &sources,
                },
                query,
                out,
            )
        }
    }

    fn snapshot(&self) -> Sources {
        Sources {
            words: self.sources,
            frame_counter: self.frame_counter,
            frame_ticks: self.frame_ticks,
        }
    }
}

/// Snapshot of the counter sources for one evaluation.
#[derive(Clone, Copy)]
struct Sources {
    words: [u32; SOURCE_WORDS],
    frame_counter: Option<u32>,
    frame_ticks: Option<u32>,
}

/// A counter object as the shared counter code accesses it.
struct View<'a> {
    counter: &'a mut Counter,
    sources: &'a Sources,
}

impl View<'_> {
    fn at(offset: i32) -> usize {
        (offset + OBJECT_HEADER as i32) as usize
    }
}

impl CounterObject for View<'_> {
    unsafe fn read_u32(&self, offset: i32) -> u32 {
        let start = Self::at(offset);
        u32::from_be_bytes(self.counter.image[start..start + 4].try_into().unwrap())
    }

    unsafe fn read_u64(&self, offset: i32) -> u64 {
        let start = Self::at(offset);
        u64::from_be_bytes(self.counter.image[start..start + 8].try_into().unwrap())
    }

    unsafe fn write_u32(&mut self, offset: i32, value: u32) {
        let start = Self::at(offset);
        self.counter.image[start..start + 4].copy_from_slice(&value.to_be_bytes());
    }

    unsafe fn write_u64(&mut self, offset: i32, value: u64) {
        let start = Self::at(offset);
        self.counter.image[start..start + 8].copy_from_slice(&value.to_be_bytes());
    }

    unsafe fn source_u32(&self, offset: u32) -> u32 {
        match self.counter.source {
            Source::Words(index) => self
                .sources
                .words
                .get(index + offset as usize / 4)
                .copied()
                .unwrap_or(0),
            Source::Frames | Source::FrameTicks => 0,
        }
    }

    unsafe fn source_u64(&self, offset: u32) -> u64 {
        // SAFETY: the caller upholds the same contract.
        unsafe {
            (u64::from(self.source_u32(offset)) << 32) | u64::from(self.source_u32(offset + 4))
        }
    }

    unsafe fn call_reader(
        &mut self,
        value: &mut u64,
        _rate: Option<&mut u64>,
    ) -> Result<(), CounterError> {
        let reading = match self.counter.source {
            Source::Frames => self.sources.frame_counter,
            Source::FrameTicks => self.sources.frame_ticks,
            Source::Words(_) => None,
        };
        let reading = reading.ok_or(CounterError::DataNotAvailable)?;

        *value = u64::from(reading);

        Ok(())
    }

    unsafe fn call_handler(
        &mut self,
        _query: counters::CounterQuery,
        _out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        Err(CounterError::Routine(Hresult::FAIL))
    }

    // The simulated sampler runs only between commands.
    fn exclude_sampler(&mut self) {}

    fn allow_sampler(&mut self) {}
}
