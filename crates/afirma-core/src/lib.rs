//! Signature formats, keystores and signing logic for autofirma-rs.
//!
//! This crate has no browser dependencies so it can be tested natively with
//! `cargo test`. The web UI (`afirma-web`) and the Web Worker (`afirma-worker`)
//! build on top of it.

#![warn(
    rust_2018_idioms,
    missing_docs,
    missing_debug_implementations,
    unused_extern_crates
)]

pub mod algorithm;
pub mod asic;
pub mod batch;
pub mod cades;
pub mod cert;
pub mod digest;
pub mod error;
pub mod facturae;
pub mod format;
pub mod job;
pub mod keystore;
pub mod massive;
pub mod multisign;
pub mod odf;
pub mod ooxml;
pub mod package;
pub mod pades;
pub mod params;
pub mod policy;
mod random;
mod time;
pub mod triphase;
pub mod tsp;
pub mod validation;
pub mod xades;
mod xml;

pub use error::{Error, Result};
