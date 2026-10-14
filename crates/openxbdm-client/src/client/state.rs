//! Typestate markers for [`super::Client`].
//!
//! The types are zero-sized. Callers cannot construct them directly;
//! transitions happen only through the typed `Client` methods.

#[derive(Debug, Default)]
pub struct Fresh;

#[derive(Debug, Default)]
pub struct Connected;
