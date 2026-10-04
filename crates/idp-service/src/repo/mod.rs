mod appliccation_repo;
mod client_repo;

mod error;
mod key_repo;
mod key_service;
mod oauth2_authorization_code_repo;
mod oauth2_refresh_token_repo;
mod oauth2_user_consent_repo;

#[cfg(feature = "std")]
mod private_key_keyring_repo;
mod private_key_repo;
#[cfg(feature = "std")]
mod raw_keyring_repo;

mod user_repo;

pub use appliccation_repo::ApplicationRepo;
pub use client_repo::ClientRepo;

pub use error::{RepoError, RepoResult};
pub use key_repo::KeyRepo;
pub use key_service::KeyService;
pub use oauth2_authorization_code_repo::OAuth2AuthorizationCodeRepo;
pub use oauth2_refresh_token_repo::{OAuth2RefreshToken, OAuth2RefreshTokenRepo};
pub use oauth2_user_consent_repo::OAuth2UserConsentRepo;

#[cfg(feature = "std")]
pub use private_key_keyring_repo::PrivateKeyKeyringRepo;
pub use private_key_repo::PrivateKeyRepo;
#[cfg(feature = "std")]
pub use raw_keyring_repo::RawKeyringRepo;

pub use user_repo::UserRepo;
