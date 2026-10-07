#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

extern crate self as idp_service;

pub mod oauth2;
mod password_config;
#[cfg(feature = "replica")]
pub mod replica;
pub mod repo;
pub mod security_sync;

mod util;

pub use password_config::PasswordConfig;
pub use util::{encrypt_password, generate_random_string};
