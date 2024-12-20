#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]

//! Utilities for working with hyper.
//!
//! This crate is less-stable than [`hyper`](https://docs.rs/hyper). However,
//! does respect Rust's semantic version regarding breaking changes.

pub mod client;
mod common;
pub mod ext;
pub mod rt;
pub mod service;
