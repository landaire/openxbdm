//! Performance counter objects: the registration word, the sample history
//! kept by the periodic sampler, and the `querypc` evaluation.
//!
//! A counter object is 0xc8 bytes:
//!
//! | offset | content |
//! | --- | --- |
//! | 0x00 | sampler bucket links |
//! | 0x08 | registration word: source kind (high half), counter type (low half) |
//! | 0x0c | source pointer or reader routine |
//! | 0x10 | 11 sample values (u64) |
//! | 0x68 | 11 sample rates (u32) |
//! | 0x94 | 11 frame numbers (u32) |
//! | 0xc0 | history index (i32), -1 when no sample is valid |
//!
//! The monitor addresses the history relative to the object, so queries
//! that reach past the history read neighbouring fields. Evaluation goes
//! through [`CounterObject`] byte offsets to keep that behavior.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;

use crate::reply::CommandError;

/// Size of a counter object.
pub const OBJECT_SIZE: usize = 0xc8;
/// Samples in the history.
pub const HISTORY_LENGTH: i32 = 11;
/// Longest sampling period, in sampler ticks.
pub const MAX_PERIOD: u32 = 10;
/// Sampler tick, in milliseconds.
pub const SAMPLER_INTERVAL_MS: u32 = 100;

const REGISTRATION_OFFSET: i32 = 0x08;
const VALUES_OFFSET: i32 = 0x10;
const RATES_OFFSET: i32 = 0x68;
const FRAMES_OFFSET: i32 = 0x94;
const INDEX_OFFSET: i32 = 0xc0;

/// Registration flag: the source holds a complete sample that is copied.
const COPIES_SAMPLE: u32 = 0x8_0000;
/// Registration flag: the source is a query routine.
const HAS_HANDLER: u32 = 0x10_0000;
/// Counter class bits of the type.
const CLASS_MASK: u32 = 0x30;
const CLASS_RATE: u32 = 0x10;
const CLASS_RATIO: u32 = 0x20;

/// The `querypc type=` word: counter class bits, history selectors, and a
/// sample count in the low nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterQuery(pub u32);

impl CounterQuery {
    /// Selector bits that request history evaluation.
    const HISTORY: u32 = 0xfc0;

    const fn class(self) -> u32 {
        self.0 & CLASS_MASK
    }

    /// Samples to evaluate; 0 selects the default.
    const fn count(self) -> i32 {
        (self.0 & 0xf) as i32
    }

    const fn history(self) -> bool {
        self.0 & Self::HISTORY != 0
    }

    const fn contains(self, bits: u32) -> bool {
        self.0 & bits != 0
    }
}

/// A successful counter evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Sampled,
    /// Success result of the counter's query routine.
    Routine(Hresult),
}

/// A failed counter enumeration, open, or query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// The query does not match the counter type.
    TypeInvalid,
    /// No sample is available.
    DataNotAvailable,
    /// Failure result of the counter's reader or query routine.
    Routine(Hresult),
    /// The process has no counter directory.
    NoDirectory,
    /// The counter cannot be opened.
    NotFound,
    /// The counter object cannot be referenced.
    Kernel(KernelError),
    /// The end of the counter directory.
    End,
    /// A directory entry does not fit the enumeration buffer.
    NameTooLong,
    /// An enumerated counter cannot be opened.
    Unexpected,
}

impl From<Evaluation> for Hresult {
    fn from(evaluation: Evaluation) -> Self {
        match evaluation {
            Evaluation::Sampled => Hresult::OK,
            Evaluation::Routine(result) => result,
        }
    }
}

impl From<CounterError> for CommandError {
    fn from(error: CounterError) -> Self {
        match error {
            CounterError::Kernel(error) => CommandError::from_kernel(error, CommandError::Fail),
            CounterError::End => CommandError::EndOfData,
            CounterError::Unexpected => CommandError::Unexpected,
            error => CommandError::Counter(error),
        }
    }
}

impl From<CounterError> for Hresult {
    #[inline(never)]
    fn from(error: CounterError) -> Self {
        match error {
            CounterError::TypeInvalid => Hresult::error(0x11),
            CounterError::DataNotAvailable => Hresult::error(0x12),
            CounterError::Routine(result) => result,
            CounterError::NoDirectory => Hresult::error(0x02),
            CounterError::NotFound => Hresult::error(0x0e),
            CounterError::NameTooLong => Hresult::error(0x105),
            CounterError::Kernel(_) | CounterError::End | CounterError::Unexpected => {
                CommandError::from(error).into()
            }
        }
    }
}

/// The typed form of the result word of a counter's reader or query
/// routine.
pub const fn routine_result(result: Hresult) -> Result<Evaluation, CounterError> {
    if result.is_failure() {
        Err(CounterError::Routine(result))
    } else {
        Ok(Evaluation::Routine(result))
    }
}

/// Registration word of a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterRegistration(pub u32);

impl CounterRegistration {
    /// Source kind: 1 reader routine, 2 and 3 a u32 value and rate, 4 a
    /// u64 value and rate.
    pub const fn kind(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Counter type reported by `pclist`.
    pub const fn counter_type(self) -> u16 {
        self.0 as u16
    }

    /// Sampling period in sampler ticks; zero means never sampled.
    pub const fn period(self) -> u32 {
        self.0 & 0xf
    }
}

/// The 0x18-byte sample `querypc` reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterSample {
    pub value: u64,
    pub rate: u64,
    pub sample_type: u32,
}

impl CounterSample {
    pub const ZERO: Self = Self {
        value: 0,
        rate: 0,
        sample_type: 0,
    };
}

/// Access to one counter object and its source.
pub trait CounterObject {
    /// Big-endian read at a signed offset from the object start.
    fn read_u32(&self, offset: i32) -> u32;
    fn read_u64(&self, offset: i32) -> u64;
    fn write_u32(&mut self, offset: i32, value: u32);
    fn write_u64(&mut self, offset: i32, value: u64);
    /// Read from the source the object points at.
    fn source_u32(&self, offset: u32) -> u32;
    fn source_u64(&self, offset: u32) -> u64;
    /// Call the reader routine of a kind 1 counter.
    fn call_reader(&mut self, value: &mut u64, rate: Option<&mut u64>) -> Result<(), CounterError>;
    /// Call the query routine of a counter registered with a handler.
    fn call_handler(
        &mut self,
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError>;
    /// Keep the sampler away from the object until `allow_sampler`; stock
    /// raises the IRQL around the history and copied-sample reads only.
    fn exclude_sampler(&mut self);
    fn allow_sampler(&mut self);
}

fn registration(object: &impl CounterObject) -> CounterRegistration {
    CounterRegistration(object.read_u32(REGISTRATION_OFFSET))
}

fn history_index(object: &impl CounterObject) -> i32 {
    object.read_u32(INDEX_OFFSET) as i32
}

fn value_at(object: &impl CounterObject, index: i32) -> u64 {
    object.read_u64(VALUES_OFFSET + index * 8)
}

fn rate_at(object: &impl CounterObject, index: i32) -> u32 {
    object.read_u32(RATES_OFFSET + index * 4)
}

fn frame_at(object: &impl CounterObject, index: i32) -> u32 {
    object.read_u32(FRAMES_OFFSET + index * 4)
}

/// Initialize a new object: registration word and an empty history.
pub fn initialize(object: &mut impl CounterObject, registration: CounterRegistration) {
    object.write_u32(REGISTRATION_OFFSET, registration.0);
    object.write_u32(INDEX_OFFSET, u32::MAX);
}

/// Instantaneous read by source kind. Returns false when the source fails.
/// Kinds above 4 succeed without writing anything.
fn read_source(object: &mut impl CounterObject, value: &mut u64, rate: Option<&mut u64>) -> bool {
    match registration(object).kind() {
        0 => false,
        1 => object.call_reader(value, rate).is_ok(),
        2 | 3 => {
            *value = u64::from(object.source_u32(0));
            if let Some(rate) = rate {
                *rate = u64::from(object.source_u32(4));
            }
            true
        }
        4 => {
            *value = object.source_u64(0);
            if let Some(rate) = rate {
                *rate = object.source_u64(8);
            }
            true
        }
        _ => true,
    }
}

/// One sampler visit of a counter without a handler. The history index is
/// never advanced: every visit rewrites the current slot `period` times, and
/// the first valid sample fills it eleven times.
pub fn sample(object: &mut impl CounterObject, tick_count: u32, frame_number: u32) {
    let word = registration(object);
    let mut value = 0u64;
    let (valid, rate) = if word.0 & CLASS_MASK != CLASS_RATIO {
        (read_source(object, &mut value, None), tick_count)
    } else {
        let mut rate = 0u64;
        let valid = read_source(object, &mut value, Some(&mut rate));
        (valid && rate >> 32 == 0, rate as u32)
    };
    if !valid {
        object.write_u32(INDEX_OFFSET, u32::MAX);
        return;
    }
    let count = if history_index(object) < 0 {
        object.write_u32(INDEX_OFFSET, 0);
        HISTORY_LENGTH as u32
    } else {
        word.period()
    };
    for _ in 0..count {
        if history_index(object) == HISTORY_LENGTH {
            object.write_u32(INDEX_OFFSET, 0);
        }
        let index = history_index(object);
        object.write_u64(VALUES_OFFSET + index * 8, value);
        object.write_u32(RATES_OFFSET + index * 4, rate);
        object.write_u32(FRAMES_OFFSET + index * 4, frame_number);
    }
}

/// Evaluate `querypc type=<query>` into `out`. Fields the evaluation does
/// not produce keep their previous content.
pub fn query(
    object: &mut impl CounterObject,
    query: CounterQuery,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    let word = registration(object).0;
    let class = word & CLASS_MASK;
    if word & COPIES_SAMPLE != 0 {
        object.exclude_sampler();
        out.value = object.source_u64(0);
        out.rate = object.source_u64(8);
        out.sample_type = object.source_u32(0x10);
        object.allow_sampler();
        return Ok(Evaluation::Sampled);
    }
    if word & HAS_HANDLER != 0 {
        return object.call_handler(query, out);
    }
    if word & CLASS_MASK != query.class() {
        return Err(CounterError::TypeInvalid);
    }
    let mut count = query.count();
    if !query.history() && class != CLASS_RATIO {
        if !read_source(object, &mut out.value, None) {
            return Err(CounterError::DataNotAvailable);
        }
        out.sample_type = class;
        return Ok(Evaluation::Sampled);
    }
    if class == 0 {
        if count == 0 {
            count = 1;
        }
        out.value = 0;
        out.rate = count as u64;
        object.exclude_sampler();
        let result = history_sum(object, count, out);
        object.allow_sampler();
        return result;
    }
    if count == 0 {
        count = 10;
    }
    object.exclude_sampler();
    let result = history_difference(object, query, count, out);
    object.allow_sampler();
    result
}

/// Sum of the last `count` values (class 0 history query).
fn history_sum(
    object: &impl CounterObject,
    count: i32,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    let mut index = history_index(object);
    if index < 0 {
        return Err(CounterError::DataNotAvailable);
    }
    for _ in 0..count {
        if index < 0 {
            index += HISTORY_LENGTH;
        }
        out.value = out.value.wrapping_add(value_at(object, index));
        index -= 1;
    }
    out.sample_type = u32::from(registration(object).counter_type());
    Ok(Evaluation::Sampled)
}

/// Value and rate change over the last `count` samples (rate and ratio
/// history queries).
fn history_difference(
    object: &impl CounterObject,
    query: CounterQuery,
    count: i32,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    let class = registration(object).0 & CLASS_MASK;
    let index = history_index(object);
    if index < 0 {
        return Err(CounterError::DataNotAvailable);
    }
    let mut back = index - count;
    if back < 0 {
        back += HISTORY_LENGTH;
    }
    out.value = value_at(object, index).wrapping_sub(value_at(object, back));
    if query.0 & 0x130 == 0x110 {
        out.sample_type = 0x110;
        out.rate = u64::from(frame_at(object, index).wrapping_sub(frame_at(object, back)));
    } else {
        out.rate = u64::from(rate_at(object, index).wrapping_sub(rate_at(object, back)));
        out.sample_type = if class == CLASS_RATE {
            if query.contains(0x200) {
                0x210
            } else if query.contains(0x40) {
                out.value = out.value.wrapping_mul(1000);
                0x50
            } else {
                0x90
            }
        } else if class == CLASS_RATIO {
            0x20
        } else {
            0x210
        };
    }
    out.sample_type |= count as u32;
    if out.rate == 0 {
        Err(CounterError::DataNotAvailable)
    } else {
        Ok(Evaluation::Sampled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Object image with a zeroed 0x10-byte header before it and a u32
    /// value/rate source.
    struct Image {
        bytes: [u8; 0x10 + OBJECT_SIZE],
        source: [u32; 2],
    }

    impl Image {
        fn new(registration: u32, source: [u32; 2]) -> Self {
            let mut image = Self {
                bytes: [0; 0x10 + OBJECT_SIZE],
                source,
            };
            initialize(&mut image, CounterRegistration(registration));
            image
        }

        fn at(offset: i32) -> usize {
            (offset + 0x10) as usize
        }
    }

    impl CounterObject for Image {
        fn read_u32(&self, offset: i32) -> u32 {
            let start = Self::at(offset);
            u32::from_be_bytes(self.bytes[start..start + 4].try_into().unwrap())
        }
        fn read_u64(&self, offset: i32) -> u64 {
            let start = Self::at(offset);
            u64::from_be_bytes(self.bytes[start..start + 8].try_into().unwrap())
        }
        fn write_u32(&mut self, offset: i32, value: u32) {
            let start = Self::at(offset);
            self.bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
        }
        fn write_u64(&mut self, offset: i32, value: u64) {
            let start = Self::at(offset);
            self.bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        fn source_u32(&self, offset: u32) -> u32 {
            self.source[offset as usize / 4]
        }
        fn source_u64(&self, _offset: u32) -> u64 {
            unreachable!()
        }
        fn call_reader(
            &mut self,
            _value: &mut u64,
            _rate: Option<&mut u64>,
        ) -> Result<(), CounterError> {
            unreachable!()
        }
        fn call_handler(
            &mut self,
            _query: CounterQuery,
            _out: &mut CounterSample,
        ) -> Result<Evaluation, CounterError> {
            unreachable!()
        }
        fn exclude_sampler(&mut self) {}
        fn allow_sampler(&mut self) {}
    }

    #[test]
    fn instantaneous_query_keeps_the_previous_rate() {
        let mut object = Image::new(0x0002_0001, [5, 9]);
        let mut out = CounterSample {
            value: 1,
            rate: 0x1234,
            sample_type: 7,
        };
        assert_eq!(
            query(&mut object, CounterQuery(1), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 5,
                rate: 0x1234,
                sample_type: 0
            }
        );
    }

    #[test]
    fn history_queries_see_only_the_current_slot() {
        let mut object = Image::new(0x0002_0011, [5, 9]);
        let mut out = CounterSample::default();
        assert_eq!(
            query(&mut object, CounterQuery(0x51), &mut out),
            Err(CounterError::DataNotAvailable)
        );
        sample(&mut object, 1000, 3);
        object.source = [8, 9];
        sample(&mut object, 1100, 4);
        // Both samples land in slot 0; the other slots stay zero.
        assert_eq!(
            query(&mut object, CounterQuery(0x51), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 8000,
                rate: 1100,
                sample_type: 0x51
            }
        );
        assert_eq!(
            query(&mut object, CounterQuery(0x313), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 8,
                rate: 4,
                sample_type: 0x113
            }
        );
        assert_eq!(
            query(&mut object, CounterQuery(0x90), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 8,
                rate: 1100,
                sample_type: 0x9a
            }
        );
        assert_eq!(
            query(&mut object, CounterQuery(0x20), &mut out),
            Err(CounterError::TypeInvalid)
        );
    }

    #[test]
    fn ratio_counters_sample_the_source_rate() {
        let mut object = Image::new(0x0002_0021, [40, 100]);
        let mut out = CounterSample::default();
        sample(&mut object, 0, 0);
        assert_eq!(
            query(&mut object, CounterQuery(0x21), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 40,
                rate: 100,
                sample_type: 0x21
            }
        );
        // Eleven samples back is the current slot again.
        assert_eq!(
            query(&mut object, CounterQuery(0x2b), &mut out),
            Err(CounterError::DataNotAvailable)
        );
    }

    #[test]
    fn class_zero_history_sums_samples() {
        let mut object = Image::new(0x0002_0001, [6, 0]);
        let mut out = CounterSample::default();
        sample(&mut object, 0, 0);
        assert_eq!(
            query(&mut object, CounterQuery(0x43), &mut out),
            Ok(Evaluation::Sampled)
        );
        assert_eq!(
            out,
            CounterSample {
                value: 6,
                rate: 3,
                sample_type: 1
            }
        );
    }
}
