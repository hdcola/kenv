pub mod ctap2;
pub mod password;
#[cfg(target_os = "macos")]
pub mod touchid;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Unique identifier for an unlock slot
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SlotType {
    Password = 1,
    Ctap2 = 2,
    TouchId = 3,
}

impl SlotType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Password),
            2 => Some(Self::Ctap2),
            3 => Some(Self::TouchId),
            _ => None,
        }
    }
}

/// Metadata for password-based unlock
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordSlotData {
    pub salt: [u8; 32],
    pub kdf_m_cost: u32,
    pub kdf_t_cost: u32,
    pub kdf_p_cost: u32,
    pub nonce: [u8; 12],
    pub encrypted_dek: Vec<u8>,
    pub tag: [u8; 16],
}

/// Metadata for CTAP2/YubiKey unlock (future)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ctap2SlotData {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub challenge: Vec<u8>,
    pub counter: u32,
    pub algorithm: i32,
    pub device_serial: Option<String>,
    pub attestation_data: Option<Vec<u8>>,
    pub nonce: [u8; 12],
    pub encrypted_dek: Vec<u8>,
    pub tag: [u8; 16],
    pub requires_pin: bool,
    pub requires_uv: bool,
    pub requires_touch: bool,
}

/// Metadata for Touch ID unlock (future)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TouchIdSlotData {
    pub keychain_ref: Vec<u8>,
    pub nonce: [u8; 12],
    pub encrypted_dek: Vec<u8>,
    pub tag: [u8; 16],
    pub biometric_type: String,
}

/// Complete unlock slot with all variants
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlockSlot {
    pub slot_id: u8,
    pub slot_type: SlotType,
    pub label: String,
    pub created_at: SystemTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<PasswordSlotData>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctap2: Option<Ctap2SlotData>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub touchid: Option<TouchIdSlotData>,

    pub requires_pin: bool,
    pub requires_touch: bool,
    pub pin_attempts_left: Option<u8>,
    pub last_used: Option<SystemTime>,
    pub disabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_type_conversion() {
        assert_eq!(SlotType::Password.as_u8(), 1);
        assert_eq!(SlotType::Ctap2.as_u8(), 2);
        assert_eq!(SlotType::TouchId.as_u8(), 3);

        assert_eq!(SlotType::from_u8(1), Some(SlotType::Password));
        assert_eq!(SlotType::from_u8(2), Some(SlotType::Ctap2));
        assert_eq!(SlotType::from_u8(3), Some(SlotType::TouchId));
        assert_eq!(SlotType::from_u8(99), None);
    }
}
