/// Platform-specific unlock implementations
///
/// This module provides platform abstractions for biometric and hardware-backed authentication.

pub mod ctap2;

#[cfg(target_os = "macos")]
pub mod macos;
