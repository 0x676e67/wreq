//! A runtime for Wreq that provides an async I/O interface and a task scheduler.
#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod rt;
