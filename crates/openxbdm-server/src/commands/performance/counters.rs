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

// CounterObject accesses raw counter object memory.
#![allow(unsafe_code)]

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

pub use super::error::CounterError;

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

xbox360_sys::flags! {
    /// Source bits of a [`CounterRegistration`] word.
    pub struct RegistrationFlags(u32) {
        /// The source holds a complete sample that is copied.
        COPIES_SAMPLE = 0x8_0000,
        /// The source is a query routine.
        HAS_HANDLER = 0x10_0000,
    }
}

xbox360_sys::flags! {
    /// Rate units of a history query and of a rate sample type, as the
    /// xbdm.h `DMCOUNT_PER*` bits.
    pub struct RateUnit(u32) {
        PER_SECOND = 0x40,
        PER_MILLISECOND = 0x80,
        PER_FRAME = 0x100,
        PER_TICK = 0x200,
    }
}

/// The `querypc type=` word: counter class bits, history selectors, and a
/// sample count in the low nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterQuery(pub u32);

impl CounterQuery {
    /// Selector bits that request history evaluation.
    const HISTORY: u32 = 0xfc0;

    const fn class(self) -> CounterClass {
        CounterClass::of(self.0)
    }

    /// Samples to evaluate; 0 selects the default.
    const fn count(self) -> i32 {
        (self.0 & 0xf) as i32
    }

    const fn history(self) -> bool {
        self.0 & Self::HISTORY != 0
    }

    const fn unit(self) -> RateUnit {
        RateUnit::from_bits_retain(self.0)
    }
}

/// A successful counter evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Sampled,
    /// Success result of the counter's query routine.
    Routine(Hresult),
}

impl From<Evaluation> for Hresult {
    fn from(evaluation: Evaluation) -> Self {
        match evaluation {
            Evaluation::Sampled => Hresult::OK,
            Evaluation::Routine(result) => result,
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

    pub const fn flags(self) -> RegistrationFlags {
        RegistrationFlags::from_bits_retain(self.0)
    }

    const fn class(self) -> CounterClass {
        CounterClass::of(self.0)
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

/// Access to one counter object and its source. The object has the layout
/// above and is preceded by 0x10 readable bytes.
pub trait CounterObject {
    /// Big-endian read at a signed offset from the object start.
    ///
    /// # Safety
    ///
    /// The 4 bytes at `offset` must lie within the object or the 0x10
    /// bytes before it: `-0x10 <= offset <= OBJECT_SIZE - 4`.
    unsafe fn read_u32(&self, offset: i32) -> u32;
    /// # Safety
    ///
    /// As [`CounterObject::read_u32`], for 8 bytes:
    /// `-0x10 <= offset <= OBJECT_SIZE - 8`.
    unsafe fn read_u64(&self, offset: i32) -> u64;
    /// # Safety
    ///
    /// The 4 bytes at `offset` must lie within the object:
    /// `0 <= offset <= OBJECT_SIZE - 4`.
    unsafe fn write_u32(&mut self, offset: i32, value: u32);
    /// # Safety
    ///
    /// The 8 bytes at `offset` must lie within the object:
    /// `0 <= offset <= OBJECT_SIZE - 8`.
    unsafe fn write_u64(&mut self, offset: i32, value: u64);
    /// Read from the source the object points at.
    ///
    /// # Safety
    ///
    /// The registration word must name a source that holds the 4 bytes at
    /// `offset`: a copied sample (u64 value, u64 rate, u32 type) when it
    /// has the copied-sample flag, else a u32 value and rate for kinds 2
    /// and 3 and a u64 value and rate for kind 4.
    unsafe fn source_u32(&self, offset: u32) -> u32;
    /// # Safety
    ///
    /// As [`CounterObject::source_u32`], for 8 bytes.
    unsafe fn source_u64(&self, offset: u32) -> u64;
    /// Call the reader routine of a kind 1 counter.
    ///
    /// # Safety
    ///
    /// The registration word must name source kind 1.
    unsafe fn call_reader(
        &mut self,
        value: &mut u64,
        rate: Option<&mut u64>,
    ) -> Result<(), CounterError>;
    /// Call the query routine of a counter registered with a handler.
    ///
    /// # Safety
    ///
    /// The registration word must have the handler flag.
    unsafe fn call_handler(
        &mut self,
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError>;
    /// Keep the sampler away from the object until `allow_sampler`; stock
    /// raises the IRQL around the history and copied-sample reads only.
    fn exclude_sampler(&mut self);
    fn allow_sampler(&mut self);
}

/// Counter class: bits 4 and 5 of a counter type or query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CounterClass(u32);

impl CounterClass {
    const VALUE: Self = Self(0);
    const RATE: Self = Self(0x10);
    const RATIO: Self = Self(0x20);
    const MASK: u32 = 0x30;

    const fn of(word: u32) -> Self {
        Self(word & Self::MASK)
    }
}

fn registration(object: &impl CounterObject) -> CounterRegistration {
    // SAFETY: the registration word lies within the object.
    CounterRegistration(unsafe { object.read_u32(REGISTRATION_OFFSET) })
}

fn history_index(object: &impl CounterObject) -> i32 {
    // SAFETY: the history index lies within the object.
    unsafe { object.read_u32(INDEX_OFFSET) as i32 }
}

/// # Safety
///
/// `index` must be in `-4..HISTORY_LENGTH`. Slot -4, 0x10 bytes before the
/// object, is the furthest a history query reaches back.
unsafe fn value_at(object: &impl CounterObject, index: i32) -> u64 {
    // SAFETY: slots -4 to 10 span offsets -0x10 to 0x68.
    unsafe { object.read_u64(VALUES_OFFSET + index * 8) }
}

/// # Safety
///
/// As [`value_at`].
unsafe fn rate_at(object: &impl CounterObject, index: i32) -> u32 {
    // SAFETY: slots -4 to 10 span offsets 0x58 to 0x94.
    unsafe { object.read_u32(RATES_OFFSET + index * 4) }
}

/// # Safety
///
/// As [`value_at`].
unsafe fn frame_at(object: &impl CounterObject, index: i32) -> u32 {
    // SAFETY: slots -4 to 10 span offsets 0x84 to 0xc0.
    unsafe { object.read_u32(FRAMES_OFFSET + index * 4) }
}

/// Sample type word of a history evaluation: `class` with `unit`.
const fn sample_type(class: CounterClass, unit: RateUnit) -> u32 {
    class.0 | unit.bits()
}

/// Initialize a new object: registration word and an empty history.
pub fn initialize(object: &mut impl CounterObject, registration: CounterRegistration) {
    // SAFETY: both words lie within the object.
    unsafe {
        object.write_u32(REGISTRATION_OFFSET, registration.0);
        object.write_u32(INDEX_OFFSET, u32::MAX);
    }
}

/// Instantaneous read by source kind. Returns false when the source fails.
/// Kinds above 4 succeed without writing anything.
fn read_source(object: &mut impl CounterObject, value: &mut u64, rate: Option<&mut u64>) -> bool {
    match registration(object).kind() {
        0 => false,
        // SAFETY: the registration names kind 1.
        1 => unsafe { object.call_reader(value, rate) }.is_ok(),
        2 | 3 => {
            // SAFETY: kinds 2 and 3 name a u32 value and rate.
            unsafe {
                *value = u64::from(object.source_u32(0));
                if let Some(rate) = rate {
                    *rate = u64::from(object.source_u32(4));
                }
            }
            true
        }
        4 => {
            // SAFETY: kind 4 names a u64 value and rate.
            unsafe {
                *value = object.source_u64(0);
                if let Some(rate) = rate {
                    *rate = object.source_u64(8);
                }
            }
            true
        }
        _ => true,
    }
}

/// One sampler visit of a counter without a handler. The history index is
/// never advanced: every visit rewrites the current slot `period` times, and
/// the first valid sample fills it eleven times.
///
/// # Safety
///
/// `object` must have been set up by [`initialize`], with its history
/// index written since only by `sample`; the index is then -1 or a slot
/// of the history.
pub unsafe fn sample(object: &mut impl CounterObject, tick_count: u32, frame_number: u32) {
    let word = registration(object);

    let mut value = 0u64;
    let (valid, rate) = if word.class() != CounterClass::RATIO {
        (read_source(object, &mut value, None), tick_count)
    } else {
        let mut rate = 0u64;
        let valid = read_source(object, &mut value, Some(&mut rate));
        (valid && rate >> 32 == 0, rate as u32)
    };
    if !valid {
        // SAFETY: the history index lies within the object.
        unsafe { object.write_u32(INDEX_OFFSET, u32::MAX) };
        return;
    }

    let count = if history_index(object) < 0 {
        // SAFETY: as above.
        unsafe { object.write_u32(INDEX_OFFSET, 0) };
        HISTORY_LENGTH as u32
    } else {
        word.period()
    };

    for _ in 0..count {
        if history_index(object) == HISTORY_LENGTH {
            // SAFETY: as above.
            unsafe { object.write_u32(INDEX_OFFSET, 0) };
        }

        let index = history_index(object);
        // SAFETY: by the contract and the resets above, `index` is a slot
        // from 0 to 10, whose words lie within the object.
        unsafe {
            object.write_u64(VALUES_OFFSET + index * 8, value);
            object.write_u32(RATES_OFFSET + index * 4, rate);
            object.write_u32(FRAMES_OFFSET + index * 4, frame_number);
        }
    }
}

/// Evaluate `querypc type=<query>` into `out`. Fields the evaluation does
/// not produce keep their previous content.
///
/// # Safety
///
/// As [`sample`].
pub unsafe fn query(
    object: &mut impl CounterObject,
    query: CounterQuery,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    let word = registration(object);
    let class = word.class();

    if word.flags().contains(RegistrationFlags::COPIES_SAMPLE) {
        object.exclude_sampler();
        // SAFETY: the registration has the copied-sample flag.
        unsafe {
            out.value = object.source_u64(0);
            out.rate = object.source_u64(8);
            out.sample_type = object.source_u32(0x10);
        }
        object.allow_sampler();

        return Ok(Evaluation::Sampled);
    }

    if word.flags().contains(RegistrationFlags::HAS_HANDLER) {
        // SAFETY: the registration has the handler flag.
        return unsafe { object.call_handler(query, out) };
    }

    if class != query.class() {
        return Err(CounterError::TypeInvalid);
    }

    if !query.history() && class != CounterClass::RATIO {
        if !read_source(object, &mut out.value, None) {
            return Err(CounterError::DataNotAvailable);
        }

        out.sample_type = class.0;

        return Ok(Evaluation::Sampled);
    }

    if class == CounterClass::VALUE {
        let count = match query.count() {
            0 => 1,
            count => count,
        };
        out.value = 0;
        out.rate = count as u64;

        object.exclude_sampler();
        // SAFETY: the caller upholds the same contract; `count` is 1 to 15.
        let result = unsafe { history_sum(object, count, out) };
        object.allow_sampler();

        return result;
    }

    let count = match query.count() {
        0 => 10,
        count => count,
    };

    object.exclude_sampler();
    // SAFETY: the caller upholds the same contract; `count` is 1 to 15.
    let result = unsafe { history_difference(object, query, count, out) };
    object.allow_sampler();

    result
}

/// Sum of the last `count` values (class 0 history query).
///
/// # Safety
///
/// As [`sample`].
unsafe fn history_sum(
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

        // SAFETY: by the contract `index` started as a slot from 0 to 10
        // and wraps to stay in that range.
        out.value = out.value.wrapping_add(unsafe { value_at(object, index) });
        index -= 1;
    }

    out.sample_type = u32::from(registration(object).counter_type());

    Ok(Evaluation::Sampled)
}

/// Value and rate change over the last `count` samples (rate and ratio
/// history queries).
///
/// # Safety
///
/// As [`sample`], and `count` must be 1 to 15.
unsafe fn history_difference(
    object: &impl CounterObject,
    query: CounterQuery,
    count: i32,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    // A rate class per-frame query, tested with one mask as stock does.
    const PER_FRAME_RATE: u32 = sample_type(CounterClass::RATE, RateUnit::PER_FRAME);

    let class = registration(object).class();
    let index = history_index(object);
    if index < 0 {
        return Err(CounterError::DataNotAvailable);
    }

    let back = match index - count {
        back if back < 0 => back + HISTORY_LENGTH,
        back => back,
    };

    // SAFETY: by the contract `index` is a slot from 0 to 10; with `count`
    // from 1 to 15, `back` is from -4 to 10.
    out.value = unsafe { value_at(object, index).wrapping_sub(value_at(object, back)) };

    if query.0 & (CounterClass::MASK | RateUnit::PER_FRAME.bits()) == PER_FRAME_RATE {
        out.sample_type = PER_FRAME_RATE;
        // SAFETY: as above.
        out.rate =
            u64::from(unsafe { frame_at(object, index).wrapping_sub(frame_at(object, back)) });
    } else {
        // SAFETY: as above.
        out.rate = u64::from(unsafe { rate_at(object, index).wrapping_sub(rate_at(object, back)) });
        out.sample_type = if class == CounterClass::RATE {
            if query.unit().contains(RateUnit::PER_TICK) {
                sample_type(CounterClass::RATE, RateUnit::PER_TICK)
            } else if query.unit().contains(RateUnit::PER_SECOND) {
                out.value = out.value.wrapping_mul(1000);
                sample_type(CounterClass::RATE, RateUnit::PER_SECOND)
            } else {
                sample_type(CounterClass::RATE, RateUnit::PER_MILLISECOND)
            }
        } else if class == CounterClass::RATIO {
            sample_type(CounterClass::RATIO, RateUnit::empty())
        } else {
            // Stock reports a rate-per-tick type for any other class.
            sample_type(CounterClass::RATE, RateUnit::PER_TICK)
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
        unsafe fn read_u32(&self, offset: i32) -> u32 {
            let start = Self::at(offset);
            u32::from_be_bytes(self.bytes[start..start + 4].try_into().unwrap())
        }
        unsafe fn read_u64(&self, offset: i32) -> u64 {
            let start = Self::at(offset);
            u64::from_be_bytes(self.bytes[start..start + 8].try_into().unwrap())
        }
        unsafe fn write_u32(&mut self, offset: i32, value: u32) {
            let start = Self::at(offset);
            self.bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
        }
        unsafe fn write_u64(&mut self, offset: i32, value: u64) {
            let start = Self::at(offset);
            self.bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        unsafe fn source_u32(&self, offset: u32) -> u32 {
            self.source[offset as usize / 4]
        }
        unsafe fn source_u64(&self, _offset: u32) -> u64 {
            unreachable!()
        }
        unsafe fn call_reader(
            &mut self,
            _value: &mut u64,
            _rate: Option<&mut u64>,
        ) -> Result<(), CounterError> {
            unreachable!()
        }
        unsafe fn call_handler(
            &mut self,
            _query: CounterQuery,
            _out: &mut CounterSample,
        ) -> Result<Evaluation, CounterError> {
            unreachable!()
        }
        fn exclude_sampler(&mut self) {}
        fn allow_sampler(&mut self) {}
    }

    fn query(
        object: &mut Image,
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        // SAFETY: `Image::new` initializes the object and only `sample`
        // writes its history index.
        unsafe { super::query(object, query, out) }
    }

    fn sample(object: &mut Image, tick_count: u32, frame_number: u32) {
        // SAFETY: as in `query`.
        unsafe { super::sample(object, tick_count, frame_number) }
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
