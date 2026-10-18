//! FinTS segment definitions.
//!
//! Each module provides builder functions that produce `Vec<DEG>` for serialization,
//! and parser functions that extract typed data from `RawSegment`.

pub mod builder;
pub mod mt535;
pub mod response;
