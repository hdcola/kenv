mod ipc;

use clap::{Parser, Subcommand};
use kenv_core::{
    create_vault, get_vault_status, list_slots, list_ssh_keys, lock, reauth_password,
    remove_slot, sign_ssh_key, KenvError, VaultStatus,
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "kenv")]
#[command(about = "Context-aware environment security manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print the current vault status in a script-friendly format.
    Status,
    /// Create a new encrypted vault with a master password.
    Create,
    /// Unlock the vault with the master password.
    Unlock,
    /// Lock the vault.
    Lock,
    /// List all unlock slots with metadata.
    Slots,
    /// Remove an unlock slot (requires interactive confirmation).
    RemoveSlot {
        /// Slot ID to remove
        slot_id: u8,
    },
    /// List all SSH keys stored in vault.
    Keys,
    /// Sign data with an SSH key (requires reauthentication if key requires it).
    Sign {
        /// SSH key ID to use for signing
        key_id: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Status => print_status(),
        Commands::Create => create_new_vault(),
        Commands::Unlock => unlock_vault(),
        Commands::Lock => lock_vault(),
        Commands::Slots => print_slots(),
        Commands::RemoveSlot { slot_id } => remove_unlock_slot(slot_id),
        Commands::Keys => print_ssh_keys(),
        Commands::Sign { key_id } => sign_with_key(&key_id),
    };

    if let Err(error) = result {
        eprintln!("{}", format_cli_error(&*error));
        std::process::exit(1);
    }
}

fn print_status() -> Result<(), Box<dyn std::error::Error>> {
    let output = render_status(get_vault_status)?;
    println!("{output}");
    Ok(())
}

fn create_new_vault() -> Result<(), Box<dyn std::error::Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("Enter master password: ")?);
    let confirm = Zeroizing::new(rpassword::prompt_password("Confirm master password: ")?);

    if *password != *confirm {
        return Err("passwords do not match".into());
    }

    // Try IPC first; only fallback to local create if socket is unavailable
    let create_result = match ipc::IpcClient::create(&password) {
        Ok(()) => Ok(()),
        Err(ipc::IpcError::SocketUnavailable(_)) => {
            // Desktop app not running, safe to create locally
            create_vault(&password).map_err(|e| e.to_string())
        }
        Err(ipc::IpcError::RemoteError(e)) => {
            // Server returned an error (e.g., vault already exists)
            // Do NOT retry: error is intentional
            Err(e)
        }
        Err(ipc::IpcError::RequestFailed(e)) => {
            // Request transmission failed; desktop has not processed
            // Do NOT retry for create (non-idempotent operation)
            Err(e)
        }
        Err(ipc::IpcError::ResponseFailed(e)) => {
            // Response transmission/parsing failed; desktop likely processed request
            // CRITICAL: Do NOT retry — vault may have been created
            Err(e)
        }
    };

    match create_result {
        Ok(_) => {
            println!("vault_status=locked");
            Ok(())
        }
        Err(e) => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e,
        ))),
    }
}

fn unlock_vault() -> Result<(), Box<dyn std::error::Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);

    // Unlock is only meaningful against the desktop app, which holds the long-lived
    // VAULT_STATE. A local in-process unlock would die with this CLI process and print a
    // false `vault_status=unlocked` that the next command can't observe, so we never fall
    // back: require the desktop to be running, consistent with list_slots/list_keys.
    match ipc::IpcClient::unlock(&password) {
        Ok(()) => {
            println!("vault_status=unlocked");
            Ok(())
        }
        Err(ipc::IpcError::SocketUnavailable(_)) => {
            eprintln!("Error: desktop app not running");
            eprintln!("Hint: Start the desktop app to use this command");
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "desktop app not running",
            )))
        }
        Err(ipc::IpcError::RemoteError(e))
        | Err(ipc::IpcError::RequestFailed(e))
        | Err(ipc::IpcError::ResponseFailed(e)) => {
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
        }
    }
}

fn lock_vault() -> Result<(), Box<dyn std::error::Error>> {
    // Try IPC first. Only fall back to local lock when the socket is unavailable
    // (desktop not running). Any other IPC error must surface: a live desktop that
    // failed to lock must NOT be masked by a local in-process lock, which would print
    // a false `vault_status=locked` while the desktop stays unlocked.
    let lock_result = match ipc::IpcClient::lock() {
        Ok(()) => Ok(()),
        Err(ipc::IpcError::SocketUnavailable(_)) => lock().map_err(|e| e.to_string()),
        Err(ipc::IpcError::RemoteError(e))
        | Err(ipc::IpcError::RequestFailed(e))
        | Err(ipc::IpcError::ResponseFailed(e)) => Err(e),
    };

    match lock_result {
        Ok(_) => {
            println!("vault_status=locked");
            Ok(())
        }
        Err(e) => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))),
    }
}

fn print_slots() -> Result<(), Box<dyn std::error::Error>> {
    match ipc::IpcClient::list_slots() {
        Ok(slots) => {
            println!("slot_count={}", slots.len());
            for slot in slots {
                println!(
                    "slot_id={} type={} label={}",
                    slot.slot_id, slot.slot_type, slot.label
                );
            }
            Ok(())
        }
        Err(e) => {
            if e.contains("not running") {
                eprintln!("Error: desktop app not running");
                eprintln!("Hint: Start the desktop app to use this command");
            } else {
                eprintln!("Error: {}", e);
            }
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e,
            )))
        }
    }
}

fn remove_unlock_slot(slot_id: u8) -> Result<(), Box<dyn std::error::Error>> {
    match ipc::IpcClient::remove_slot(slot_id) {
        Ok(()) => {
            println!("slot_removed=true");
            Ok(())
        }
        Err(e) if e.contains("reauthentication_required") => {
            // HIGH-RISK operation detected, request reauthentication
            eprintln!("Removing this slot requires password reauthentication");
            let password =
                Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
            ipc::IpcClient::reauth_password(&password)?;
            ipc::IpcClient::remove_slot(slot_id)?;
            println!("slot_removed=true");
            Ok(())
        }
        Err(e) => {
            if e.contains("not running") {
                eprintln!("Error: desktop app not running");
                eprintln!("Hint: Start the desktop app to use this command");
            } else {
                eprintln!("Error: {}", e);
            }
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e,
            )))
        }
    }
}

/// Translate KenvError to CLI error string, applying context-aware conversions.
/// UnlockFailed becomes "reauthentication_required" when it comes from operations
/// that require reauthentication (sign, remove_slot).
fn error_to_string(error: KenvError, operation: &str) -> String {
    match error {
        KenvError::UnlockFailed if operation == "sign" || operation == "remove_slot" => {
            "reauthentication_required".to_string()
        }
        e => e.to_string(),
    }
}

fn print_ssh_keys() -> Result<(), Box<dyn std::error::Error>> {
    match ipc::IpcClient::list_keys() {
        Ok(keys) => {
            println!("key_count={}", keys.len());
            for key in keys {
                println!("key_id={} name={}", key.key_id, key.name);
            }
            Ok(())
        }
        Err(e) => {
            if e.contains("not running") {
                eprintln!("Error: desktop app not running");
                eprintln!("Hint: Start the desktop app to use this command");
            } else {
                eprintln!("Error: {}", e);
            }
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e,
            )))
        }
    }
}

fn sign_with_key(key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read data to sign from stdin
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;

    // Try IPC first; only fallback to local sign if socket is unavailable.
    // Sign is non-idempotent, so we should NOT retry if communication fails mid-stream.
    let sign_result = match ipc::IpcClient::sign(key_id, &data) {
        Ok(sig) => Ok(sig),
        Err(ipc::IpcError::SocketUnavailable(_)) => {
            // Desktop app not running, safe to sign locally
            sign_ssh_key(key_id, &data)
                .map(|sig| sig.signature)
                .map_err(|e| error_to_string(e, "sign"))
        }
        Err(ipc::IpcError::RemoteError(e)
            | ipc::IpcError::RequestFailed(e)
            | ipc::IpcError::ResponseFailed(e)) => {
            // Do NOT retry: key may have been signed or communication failed mid-stream
            Err(e)
        }
    };

    match sign_result {
        Ok(signature) => {
            println!("key_id={}", key_id);
            println!("signature={}", ipc::base64_encode(&signature));
            Ok(())
        }
        Err(e) if e.contains("reauthentication_required") => {
            // Reauthentication required
            eprintln!("This SSH key requires password reauthentication");
            let password =
                Zeroizing::new(rpassword::prompt_password("Vault password: ")?);

            // Try IPC first, fallback to local if desktop not running
            let reauth_result = ipc::IpcClient::reauth_password(&password)
                .or_else(|ipc_err| {
                    if ipc_err.is_socket_unavailable() {
                        // Desktop not running, use local reauth
                        reauth_password(&password).map_err(|e| e.to_string())
                    } else {
                        // Other IPC error, propagate
                        Err(ipc_err.to_string())
                    }
                });

            reauth_result?;

            // Retry sign with same pattern: IPC first, then local fallback
            let signature = match ipc::IpcClient::sign(key_id, &data) {
                Ok(sig) => sig,
                Err(ipc::IpcError::SocketUnavailable(_)) => {
                    sign_ssh_key(key_id, &data)
                        .map(|sig| sig.signature)
                        .map_err(|e| error_to_string(e, "sign"))?
                }
                Err(e) => Err(e.to_string())?,
            };

            println!("key_id={}", key_id);
            println!("signature={}", ipc::base64_encode(&signature));
            Ok(())
        }
        Err(e) => {
            if e.contains("not running") {
                eprintln!("Error: desktop app not running");
                eprintln!("Hint: Start the desktop app to use this command");
            }
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e,
            )))
        }
    }
}

fn render_status<F>(status_provider: F) -> Result<String, KenvError>
where
    F: FnOnce() -> Result<VaultStatus, KenvError>,
{
    let status = status_provider()?;
    Ok(format!("vault_status={}", status.as_script_value()))
}

fn format_cli_error(error: &dyn std::fmt::Display) -> String {
    format!("error={error}")
}

#[cfg(test)]
mod tests {
    use super::render_status;
    use kenv_core::{KenvError, VaultStatus};

    #[test]
    fn render_status_formats_success_output() {
        let output = render_status(|| Ok(VaultStatus::Unlocked)).unwrap();
        assert_eq!(output, "vault_status=unlocked");
    }

    #[test]
    fn render_status_returns_core_error() {
        let error = render_status(|| Err(KenvError::UnlockFailed)).unwrap_err();
        assert_eq!(error.to_string(), "unlock failed");
    }

    #[test]
    fn format_cli_error_uses_expected_prefix() {
        let message = super::format_cli_error(&KenvError::UnlockFailed);
        assert_eq!(message, "error=unlock failed");
    }

    #[test]
    fn create_vault_outputs_locked_status() {
        let output = render_status(|| Ok(VaultStatus::Locked)).unwrap();
        assert_eq!(output, "vault_status=locked");
    }
}
