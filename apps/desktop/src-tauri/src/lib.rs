use kenv_core::VaultStatus;

#[tauri::command]
fn get_vault_status() -> Result<VaultStatus, String> {
    kenv_core::get_vault_status().map_err(|error| error.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_vault_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::get_vault_status;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn command_returns_vault_status_successfully() {
        let status = get_vault_status().expect("command should return vault status");
        assert_eq!(status.as_script_value(), "missing");
    }

    #[test]
    fn capability_does_not_enable_opener_permission() {
        let capabilities_path = project_root().join("capabilities/default.json");
        let content = fs::read_to_string(&capabilities_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", capabilities_path.display()));
        let json: Value = serde_json::from_str(&content)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", capabilities_path.display()));
        let permissions = json["permissions"]
            .as_array()
            .unwrap_or_else(|| panic!("permissions must be an array in {}", capabilities_path.display()));

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
}
