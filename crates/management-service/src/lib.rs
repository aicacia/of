#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "replica")]
pub mod replica;

#[cfg(feature = "std")]
mod device_enrollment;
mod device_repo;
mod error;
#[cfg(feature = "std")]
mod hosted_control_plane;
#[cfg(feature = "std")]
mod permission_client;
mod permission_repo;

mod role_repo;
mod service;

#[cfg(feature = "std")]
pub use device_enrollment::DeviceEnrollmentService;
pub use device_repo::DeviceRepo;
pub use error::{ManagementError, ManagementResult};
#[cfg(feature = "std")]
pub use hosted_control_plane::HostedControlPlane;
#[cfg(feature = "std")]
pub use permission_client::PermissionClient;
pub use permission_repo::PermissionRepo;

pub use role_repo::RoleRepo;
pub use service::{MANAGEMENT_APPLICATION_URI, ManagementService};
