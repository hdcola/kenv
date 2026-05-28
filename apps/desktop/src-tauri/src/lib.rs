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
