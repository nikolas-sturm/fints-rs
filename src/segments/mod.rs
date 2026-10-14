//! FinTS segment definitions.
//!
//! Each module provides builder functions that produce `Vec<DEG>` for serialization,
//! and parser functions that extract typed data from `RawSegment`.

pub mod builder;
pub mod response;
pub mod mt535;
