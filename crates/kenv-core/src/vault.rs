pub mod tlv;

use crate::{crypto::KdfParams, KenvError, slots, ssh};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const MAGIC: &[u8; 4] = b"KENV";
pub const FILE_VERSION_V1: u8 = 1;
pub const FILE_VERSION_V2: u8 = 2;

// V1 format constants
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const SALT_OFFSET: usize = 18;
pub const SALT_SIZE: usize = 32;
pub const NONCE_OFFSET: usize = 50;
pub const NONCE_SIZE: usize = 12;
pub const CIPHERTEXT_OFFSET: usize = 62;
pub const MIN_FILE_SIZE: usize = 91;

// V2 format header constants
pub const V2_HEADER_SIZE: usize = 62; // Same header as V1, followed by slots
pub const V2_SLOTS_OFFSET: usize = 62;

/// Key data parsed from a V2 cleartext slot record.
///
/// Each variant holds the minimum fields needed to perform that slot type's unlock
/// operation without decrypting the vault payload first.
pub enum ParsedSlotKeyData {
    Password(slots::PasswordSlotData),
    /// CTAP2 fields needed to call `slots::ctap2::assert_and_unwrap_dek`.
    Ctap2 {
        credential_id: Vec<u8>,
        challenge: Vec<u8>,
        counter: u32,
        nonce: [u8; 12],
        encrypted_dek: Vec<u8>,
        tag: [u8; 16],
    },
    /// TouchID fields needed to call `slots::touchid::unwrap_dek`.
    TouchId {
        keychain_ref: Vec<u8>,
        nonce: [u8; 12],
        encrypted_dek: Vec<u8>,
        tag: [u8; 16],
    },
    /// Unknown slot type — skipped during unlock, present for format forward-compatibility.
    Unknown,
}

/// Cleartext slot record parsed from the V2 file header.
pub struct ParsedSlotRecord {
    pub slot_id: u8,
    pub slot_type: u8,
    pub key_data: ParsedSlotKeyData,
}

/// Encode all unlock slots that have real key material into the V2 cleartext slot section.
///
/// Format: `[slot_count_u8][record_0][record_1]...`
/// Each record: `[slot_id_u8][slot_type_u8][data_len_u16_be][data_bytes...]`
///
/// The length-prefixed record layout supports variable-length key material across
/// all slot types and allows unknown future types to be skipped during parsing.
pub fn build_cleartext_slot_records(slot_list: &[slots::UnlockSlot]) -> Vec<u8> {
    let eligible: Vec<_> = slot_list
        .iter()
        .filter(|s| slot_has_key_material(s))
        .take(255)
        .collect();

    let mut out = vec![eligible.len() as u8];
    for slot in &eligible {
        let payload = encode_slot_key_payload(slot);
        let payload_len = payload.len().min(u16::MAX as usize) as u16;
        out.push(slot.slot_id);
        out.push(slot.slot_type.as_u8());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&payload[..payload_len as usize]);
    }
    out
}

fn slot_has_key_material(slot: &slots::UnlockSlot) -> bool {
    match slot.slot_type {
        slots::SlotType::Password => slot.password.is_some(),
        slots::SlotType::Ctap2 => slot.ctap2.is_some(),
        slots::SlotType::TouchId => slot.touchid.is_some(),
    }
}

fn encode_slot_key_payload(slot: &slots::UnlockSlot) -> Vec<u8> {
    match slot.slot_type {
        slots::SlotType::Password => {
            slot.password.as_ref().map(encode_password_payload).unwrap_or_default()
        }
        slots::SlotType::Ctap2 => {
            slot.ctap2.as_ref().map(encode_ctap2_payload).unwrap_or_default()
        }
        slots::SlotType::TouchId => {
            slot.touchid.as_ref().map(encode_touchid_payload).unwrap_or_default()
        }
    }
}

// Password payload (always 104 bytes):
//   [32] salt  [4] m_cost  [4] t_cost  [4] p_cost  [12] nonce  [32] enc_dek  [16] tag
fn encode_password_payload(pwd: &slots::PasswordSlotData) -> Vec<u8> {
    let mut d = Vec::with_capacity(104);
    d.extend_from_slice(&pwd.salt);
    d.extend_from_slice(&pwd.kdf_m_cost.to_be_bytes());
    d.extend_from_slice(&pwd.kdf_t_cost.to_be_bytes());
    d.extend_from_slice(&pwd.kdf_p_cost.to_be_bytes());
    d.extend_from_slice(&pwd.nonce);
    d.extend_from_slice(&pwd.encrypted_dek);
    d.extend_from_slice(&pwd.tag);
    d
}

// CTAP2 payload (variable):
//   [2] cred_id_len  [*] cred_id  [2] challenge_len  [*] challenge
//   [4] counter  [12] nonce  [32] enc_dek  [16] tag
fn encode_ctap2_payload(c: &slots::Ctap2SlotData) -> Vec<u8> {
    let mut d = Vec::new();
    let cid_len = c.credential_id.len().min(u16::MAX as usize) as u16;
    d.extend_from_slice(&cid_len.to_be_bytes());
    d.extend_from_slice(&c.credential_id[..cid_len as usize]);
    let ch_len = c.challenge.len().min(u16::MAX as usize) as u16;
    d.extend_from_slice(&ch_len.to_be_bytes());
    d.extend_from_slice(&c.challenge[..ch_len as usize]);
    d.extend_from_slice(&c.counter.to_be_bytes());
    d.extend_from_slice(&c.nonce);
    d.extend_from_slice(&c.encrypted_dek);
    d.extend_from_slice(&c.tag);
    d
}

// TouchID payload (variable):
//   [2] ref_len  [*] keychain_ref  [12] nonce  [32] enc_dek  [16] tag
fn encode_touchid_payload(t: &slots::TouchIdSlotData) -> Vec<u8> {
    let mut d = Vec::new();
    let ref_len = t.keychain_ref.len().min(u16::MAX as usize) as u16;
    d.extend_from_slice(&ref_len.to_be_bytes());
    d.extend_from_slice(&t.keychain_ref[..ref_len as usize]);
    d.extend_from_slice(&t.nonce);
    d.extend_from_slice(&t.encrypted_dek);
    d.extend_from_slice(&t.tag);
    d
}

/// Parse V2 cleartext slot records.
///
/// Returns `(records, ciphertext_start_offset)`. The ciphertext begins immediately
/// after the last slot record. Unknown slot types are included as `ParsedSlotKeyData::Unknown`
/// so they can be skipped while still advancing the offset correctly.
pub fn parse_cleartext_slot_records(
    data: &[u8],
) -> Result<(Vec<ParsedSlotRecord>, usize), KenvError> {
    if data.len() <= V2_SLOTS_OFFSET {
        return Err(KenvError::InvalidVaultFormat);
    }

    let slot_count = data[V2_SLOTS_OFFSET] as usize;
    let mut offset = V2_SLOTS_OFFSET + 1;
    let mut records = Vec::with_capacity(slot_count);

    for _ in 0..slot_count {
        // Each record header: slot_id (1) + slot_type (1) + data_len (2)
        if offset + 4 > data.len() {
            return Err(KenvError::InvalidVaultFormat);
        }
        let slot_id = data[offset];
        let slot_type_byte = data[offset + 1];
        let data_len = u16::from_be_bytes(
            data[offset + 2..offset + 4]
                .try_into()
                .map_err(|_| KenvError::InvalidVaultFormat)?,
        ) as usize;
        offset += 4;

        if offset + data_len > data.len() {
            return Err(KenvError::InvalidVaultFormat);
        }
        let payload = &data[offset..offset + data_len];
        offset += data_len;

        let key_data = match slots::SlotType::from_u8(slot_type_byte) {
            Some(slots::SlotType::Password) => {
                ParsedSlotKeyData::Password(parse_password_payload(payload)?)
            }
            Some(slots::SlotType::Ctap2) => parse_ctap2_payload(payload)
                .map(|(cid, ch, counter, nonce, enc_dek, tag)| ParsedSlotKeyData::Ctap2 {
                    credential_id: cid,
                    challenge: ch,
                    counter,
                    nonce,
                    encrypted_dek: enc_dek,
                    tag,
                })
                .unwrap_or(ParsedSlotKeyData::Unknown),
            Some(slots::SlotType::TouchId) => parse_touchid_payload(payload)
                .map(|(keychain_ref, nonce, enc_dek, tag)| ParsedSlotKeyData::TouchId {
                    keychain_ref,
                    nonce,
                    encrypted_dek: enc_dek,
                    tag,
                })
                .unwrap_or(ParsedSlotKeyData::Unknown),
            None => ParsedSlotKeyData::Unknown,
        };

        records.push(ParsedSlotRecord { slot_id, slot_type: slot_type_byte, key_data });
    }

    Ok((records, offset))
}

fn parse_password_payload(data: &[u8]) -> Result<slots::PasswordSlotData, KenvError> {
    // [32] salt  [4] m_cost  [4] t_cost  [4] p_cost  [12] nonce  [32] enc_dek  [16] tag = 104
    if data.len() < 104 {
        return Err(KenvError::InvalidVaultFormat);
    }
    let salt: [u8; 32] = data[0..32].try_into().map_err(|_| KenvError::InvalidVaultFormat)?;
    let kdf_m_cost =
        u32::from_be_bytes(data[32..36].try_into().map_err(|_| KenvError::InvalidVaultFormat)?);
    let kdf_t_cost =
        u32::from_be_bytes(data[36..40].try_into().map_err(|_| KenvError::InvalidVaultFormat)?);
    let kdf_p_cost =
        u32::from_be_bytes(data[40..44].try_into().map_err(|_| KenvError::InvalidVaultFormat)?);
    let nonce: [u8; 12] = data[44..56].try_into().map_err(|_| KenvError::InvalidVaultFormat)?;
    let encrypted_dek = data[56..88].to_vec();
    let tag: [u8; 16] = data[88..104].try_into().map_err(|_| KenvError::InvalidVaultFormat)?;
    Ok(slots::PasswordSlotData { salt, kdf_m_cost, kdf_t_cost, kdf_p_cost, nonce, encrypted_dek, tag })
}

fn parse_ctap2_payload(
    data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, u32, [u8; 12], Vec<u8>, [u8; 16]), KenvError> {
    let mut o = 0;
    let cid_len = read_u16(data, &mut o)? as usize;
    let cid = read_bytes(data, &mut o, cid_len)?;
    let ch_len = read_u16(data, &mut o)? as usize;
    let ch = read_bytes(data, &mut o, ch_len)?;
    let counter = read_u32(data, &mut o)?;
    let nonce: [u8; 12] = read_fixed(data, &mut o)?;
    let enc_dek = read_bytes(data, &mut o, 32)?;
    let tag: [u8; 16] = read_fixed(data, &mut o)?;
    Ok((cid, ch, counter, nonce, enc_dek, tag))
}

fn parse_touchid_payload(
    data: &[u8],
) -> Result<(Vec<u8>, [u8; 12], Vec<u8>, [u8; 16]), KenvError> {
    let mut o = 0;
    let ref_len = read_u16(data, &mut o)? as usize;
    let keychain_ref = read_bytes(data, &mut o, ref_len)?;
    let nonce: [u8; 12] = read_fixed(data, &mut o)?;
    let enc_dek = read_bytes(data, &mut o, 32)?;
    let tag: [u8; 16] = read_fixed(data, &mut o)?;
    Ok((keychain_ref, nonce, enc_dek, tag))
}

// --- parsing helpers ---

fn read_u16(data: &[u8], o: &mut usize) -> Result<u16, KenvError> {
    if *o + 2 > data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }
    let v = u16::from_be_bytes(data[*o..*o + 2].try_into().map_err(|_| KenvError::InvalidVaultFormat)?);
    *o += 2;
    Ok(v)
}

fn read_u32(data: &[u8], o: &mut usize) -> Result<u32, KenvError> {
    if *o + 4 > data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }
    let v = u32::from_be_bytes(data[*o..*o + 4].try_into().map_err(|_| KenvError::InvalidVaultFormat)?);
    *o += 4;
    Ok(v)
}

fn read_bytes(data: &[u8], o: &mut usize, len: usize) -> Result<Vec<u8>, KenvError> {
    if *o + len > data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }
    let v = data[*o..*o + len].to_vec();
    *o += len;
    Ok(v)
}

fn read_fixed<const N: usize>(data: &[u8], o: &mut usize) -> Result<[u8; N], KenvError> {
    if *o + N > data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }
    let v: [u8; N] = data[*o..*o + N].try_into().map_err(|_| KenvError::InvalidVaultFormat)?;
    *o += N;
    Ok(v)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultPayload {
    pub version: u32,
    pub slots: Vec<slots::UnlockSlot>,
    pub ssh_keys: Vec<ssh::SshKey>,
}

impl VaultPayload {
    pub fn new() -> Self {
        Self {
            version: 1,
            slots: Vec::new(),
            ssh_keys: Vec::new(),
        }
    }
}

impl Zeroize for VaultPayload {
    fn zeroize(&mut self) {
        // Zeroize the slots
        for slot in &mut self.slots {
            // Zeroize sensitive data in each slot
            if let Some(ref mut pwd_data) = slot.password {
                pwd_data.salt.zeroize();
                pwd_data.nonce.zeroize();
                pwd_data.encrypted_dek.zeroize();
                pwd_data.tag.zeroize();
            }
            if let Some(ref mut ctap2_data) = slot.ctap2 {
                ctap2_data.challenge.zeroize();
                ctap2_data.nonce.zeroize();
                ctap2_data.encrypted_dek.zeroize();
                ctap2_data.tag.zeroize();
            }
            if let Some(ref mut touchid_data) = slot.touchid {
                touchid_data.keychain_ref.zeroize();
                touchid_data.nonce.zeroize();
                touchid_data.encrypted_dek.zeroize();
                touchid_data.tag.zeroize();
            }
        }
        self.slots.clear();

        // Zeroize SSH key material. private_key holds sensitive bytes; public_key is
        // wiped too for thoroughness. VaultState::drop and lock() rely on this pass.
        for key in &mut self.ssh_keys {
            key.private_key.zeroize();
            key.public_key.zeroize();
        }
        self.ssh_keys.clear();
    }
}

// Thread-local storage for test vault path overrides
// Each test thread gets its own isolated path, preventing interference in concurrent test execution
thread_local! {
    static TEST_VAULT_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
}

/// Set vault path for testing (truly isolated to calling thread)
pub fn set_test_vault_path(path: std::path::PathBuf) {
    TEST_VAULT_PATH.with(|p| {
        *p.lock().unwrap() = Some(path);
    });
}

/// Clear vault path for testing
pub fn clear_test_vault_path() {
    TEST_VAULT_PATH.with(|p| {
        *p.lock().unwrap() = None;
    });
}

pub fn vault_path() -> Result<std::path::PathBuf, KenvError> {
    // Check for test-injected path first (each thread has its own isolated thread-local value)
    if let Some(path) = TEST_VAULT_PATH.with(|p| p.lock().unwrap().clone()) {
        return Ok(path);
    }

    let home = dirs::home_dir().ok_or(KenvError::FileOperationFailed)?;
    Ok(home.join(".kenv").join("vault.kenv"))
}

/// Serialize the vault header + optional cleartext slot records + ciphertext into the on-disk
/// byte layout.
///
/// `slot_records` is the pre-encoded cleartext slot section (from
/// `build_cleartext_slot_records`) for V2, or empty for V1. For V2, the KDF params
/// in the 62-byte fixed header are zeroed — the real per-slot KDF params live in
/// `slot_records`.
fn encode_vault_bytes(
    salt: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: &KdfParams,
    version: u8,
    slot_records: &[u8],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(CIPHERTEXT_OFFSET + slot_records.len() + ciphertext.len());
    buf.extend_from_slice(MAGIC);
    buf.push(version);
    buf.push(KDF_ID_ARGON2ID);
    if version == FILE_VERSION_V2 {
        // KDF params are per-slot in V2; write zeros in the shared header.
        buf.extend_from_slice(&[0u8; 12]);
    } else {
        buf.extend_from_slice(&params.m_cost.to_be_bytes());
        buf.extend_from_slice(&params.t_cost.to_be_bytes());
        buf.extend_from_slice(&params.p_cost.to_be_bytes());
    }
    buf.extend_from_slice(salt);
    buf.extend_from_slice(nonce);
    if version == FILE_VERSION_V2 {
        buf.extend_from_slice(slot_records);
    }
    buf.extend_from_slice(ciphertext);
    buf
}

/// fsync the directory containing `path` so the rename/create is durable.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent).and_then(|d| d.sync_all())?;
    }
    Ok(())
}

/// Create a brand-new vault file. Fails with `VaultAlreadyExists` if one is already present.
///
/// Use [`overwrite_vault_file`] to persist changes to an existing vault.
///
/// `slot_records` is the pre-encoded cleartext slot section for V2 (from
/// `build_cleartext_slot_records`), or empty for V1.
pub fn write_vault_file(
    path: &Path,
    salt: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: &KdfParams,
    slot_records: &[u8],
    version: u8,
) -> Result<(), KenvError> {
    let buf = encode_vault_bytes(salt, nonce, ciphertext, params, version, slot_records);

    #[cfg(unix)]
    let open_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);

    #[cfg(not(unix))]
    return Err(KenvError::PlatformCapabilityUnavailable);

    let mut file = open_result.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KenvError::VaultAlreadyExists
        } else {
            KenvError::FileOperationFailed
        }
    })?;
    file.write_all(&buf).map_err(|_| {
        let _ = std::fs::remove_file(path);
        KenvError::FileOperationFailed
    })?;
    file.sync_all().map_err(|_| {
        let _ = std::fs::remove_file(path);
        KenvError::FileOperationFailed
    })?;

    if sync_parent_dir(path).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(KenvError::FileOperationFailed);
    }

    Ok(())
}

/// Atomically overwrite an existing vault file with new contents.
///
/// Writes to a sibling temp file (mode 0600), fsyncs it, then renames it over `path`. A crash
/// at any point leaves either the old vault or the new one intact — never a truncated file.
///
/// `slot_records` is the pre-encoded cleartext slot section for V2 (from
/// `build_cleartext_slot_records`), or empty for V1.
pub fn overwrite_vault_file(
    path: &Path,
    salt: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    params: &KdfParams,
    slot_records: &[u8],
    version: u8,
) -> Result<(), KenvError> {
    let buf = encode_vault_bytes(salt, nonce, ciphertext, params, version, slot_records);

    #[cfg(not(unix))]
    return Err(KenvError::PlatformCapabilityUnavailable);

    #[cfg(unix)]
    {
        // Randomized tmp suffix so two concurrent persists never collide on the same
        // sibling file — defense in depth on top of the PERSIST_MUTEX in lib.rs.
        let tmp_rand: u64 = rand::random();
        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(format!(".tmp.{:016x}", tmp_rand));
        let tmp_path = std::path::PathBuf::from(tmp_os);

        let write_tmp = || -> Result<(), KenvError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|_| KenvError::FileOperationFailed)?;
            file.write_all(&buf).map_err(|_| KenvError::FileOperationFailed)?;
            file.sync_all().map_err(|_| KenvError::FileOperationFailed)?;
            Ok(())
        };

        if let Err(e) = write_tmp() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        if std::fs::rename(&tmp_path, path).is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(KenvError::FileOperationFailed);
        }

        // Best-effort durability of the rename itself; the data is already fsynced.
        let _ = sync_parent_dir(path);

        Ok(())
    }
}

pub fn validate_vault_header(data: &[u8]) -> Result<u8, KenvError> {
    if data.len() < MIN_FILE_SIZE {
        return Err(KenvError::InvalidVaultFormat);
    }
    if &data[0..4] != MAGIC.as_slice() {
        return Err(KenvError::InvalidVaultFormat);
    }

    let version = data[4];
    if version != FILE_VERSION_V1 && version != FILE_VERSION_V2 {
        return Err(KenvError::InvalidVaultFormat);
    }

    // V2 uses same header as V1, so check KDF ID only for V1
    if version == FILE_VERSION_V1 && data[5] != KDF_ID_ARGON2ID {
        return Err(KenvError::InvalidVaultFormat);
    }

    let m_cost = u32::from_be_bytes(
        data[6..10]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );
    let t_cost = u32::from_be_bytes(
        data[10..14]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );
    let p_cost = u32::from_be_bytes(
        data[14..18]
            .try_into()
            .map_err(|_| KenvError::InvalidVaultFormat)?,
    );

    // V2 stores KDF params per-slot in the cleartext slot section, so the shared header
    // fields are intentionally zero. Only enforce non-zero for V1.
    if version == FILE_VERSION_V1 && (m_cost == 0 || t_cost == 0 || p_cost == 0) {
        return Err(KenvError::InvalidVaultFormat);
    }

    let salt = &data[SALT_OFFSET..SALT_OFFSET + SALT_SIZE];
    if salt.iter().all(|&b| b == 0) {
        return Err(KenvError::InvalidVaultFormat);
    }

    let nonce = &data[NONCE_OFFSET..NONCE_OFFSET + NONCE_SIZE];
    if nonce.iter().all(|&b| b == 0) {
        return Err(KenvError::InvalidVaultFormat);
    }

    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn zeroize_clears_ssh_key_material() {
        let mut payload = VaultPayload::new();
        payload.ssh_keys.push(ssh::SshKey {
            key_id: "ed25519".to_string(),
            name: "test".to_string(),
            public_key: vec![1u8; 32],
            private_key: vec![2u8; 64],
            key_type: ssh::SshKeyType::Ed25519,
            created_at: SystemTime::now(),
            last_used: None,
            disabled: false,
            require_reauthentication: false,
        });

        payload.zeroize();

        assert!(payload.ssh_keys.is_empty());
    }
}
