mod handlers;
mod socket_server;

use kenv_core::{SlotInfo, SshKeyInfo, VaultStatus};
use zeroize::Zeroize;

#[tauri::command]
fn get_vault_status() -> Result<VaultStatus, String> {
    kenv_core::get_vault_status().map_err(|error| error.to_string())
}

#[tauri::command]
fn get_vault_slots() -> Result<Vec<SlotInfo>, String> {
    kenv_core::list_slots().map_err(|error| error.to_string())
}

#[tauri::command]
fn create_vault(mut password: String) -> Result<(), String> {
    let result = kenv_core::create_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    result
}

#[tauri::command]
fn unlock(mut password: String) -> Result<VaultStatus, String> {
    let result = kenv_core::unlock(&password).map_err(|e| e.to_string());
    password.zeroize();
    result
}

#[tauri::command]
fn lock() -> Result<(), String> {
    kenv_core::lock().map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_vault_slot(slot_id: u8) -> Result<bool, String> {
    match kenv_core::remove_slot(slot_id) {
        Ok(()) => Ok(true),
        Err(kenv_core::KenvError::UnlockFailed) => {
            // HIGH-RISK operation detected, return indicator that reauthentication is needed
            Err("reauthentication_required".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn reauthenticate(mut password: String) -> Result<(), String> {
    let result = kenv_core::reauth_password(&password).map_err(|e| e.to_string());
    password.zeroize();
    result
}

#[tauri::command]
fn get_ssh_keys() -> Result<Vec<SshKeyInfo>, String> {
    kenv_core::list_ssh_keys().map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            socket_server::start_socket_server(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_vault_status,
            get_vault_slots,
            create_vault,
            unlock,
            lock,
            remove_vault_slot,
            reauthenticate,
            get_ssh_keys
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::get_vault_status;
    use kenv_core::VaultStatus;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn command_returns_vault_status_successfully() {
        let status = get_vault_status().expect("command should return vault status");
        assert!(
            matches!(
                status,
                VaultStatus::Missing | VaultStatus::Locked | VaultStatus::Corrupted | VaultStatus::Unlocked
            ),
            "unexpected status: {}",
            status.as_script_value()
        );
    }

    #[test]
    fn capability_does_not_enable_opener_permission() {
        let capabilities_path = project_root().join("capabilities/default.json");
        let content = fs::read_to_string(&capabilities_path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", capabilities_path.display())
        });
        let json: Value = serde_json::from_str(&content).unwrap_or_else(|error| {
            panic!("failed to parse {}: {error}", capabilities_path.display())
        });
        let permissions = json["permissions"].as_array().unwrap_or_else(|| {
            panic!(
                "permissions must be an array in {}",
                capabilities_path.display()
            )
        });

        assert!(
            !permissions.iter().any(|item| item == "opener:default"),
            "unexpected opener permission found in {}",
            capabilities_path.display()
        );
    }

    #[test]
    fn csp_keeps_required_sources() {
        let config_path = project_root().join("tauri.conf.json");
        let content = fs::read_to_string(&config_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", config_path.display()));
        let json: Value = serde_json::from_str(&content)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", config_path.display()));
        let csp = json["app"]["security"]["csp"]
            .as_str()
            .unwrap_or_else(|| panic!("csp must be a string in {}", config_path.display()));

        assert!(
            csp.contains("default-src 'self'"),
            "missing default-src directive in {}",
            config_path.display()
        );
        assert!(
            csp.contains("connect-src ipc: http://ipc.localhost"),
            "missing IPC connect-src directive in {}",
            config_path.display()
        );
    }

    #[test]
    fn core_create_vault_at_errors_on_duplicate() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kenv");
        let params = kenv_core::crypto::KdfParams::recommended();

        kenv_core::create_vault_at(&path, "password", &params).unwrap();
        let result = kenv_core::create_vault_at(&path, "password", &params);

        assert!(
            matches!(result, Err(kenv_core::KenvError::VaultAlreadyExists)),
            "expected VaultAlreadyExists, got {result:?}"
        );
        assert!(!result.unwrap_err().to_string().is_empty());
    }
}
