mod ipc;

use clap::{Parser, Subcommand};
use kenv_core::{create_vault, get_vault_status, KenvError, VaultStatus};
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
    };

    if let Err(error) = result {
        eprintln!("{}", format_cli_error(&*error));
        std::process::exit(1);
    }
}

fn print_status() -> Result<(), Box<dyn std::error::Error>> {
    // Try the desktop IPC first — it holds the long-lived VAULT_STATE that reflects real
    // unlock/lock operations. Fall back to the local get_vault_status() only when the
    // desktop is not running; in that case the vault can only be missing or locked.
    let output = match ipc::IpcClient::status() {
        Ok(status_str) => format!("vault_status={}", status_str),
        Err(ipc::IpcError::SocketUnavailable(_)) => render_status(get_vault_status)?,
        Err(e) => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
    };
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
        Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
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
    // Lock is only meaningful against the desktop app, which holds the long-lived
    // VAULT_STATE. A local in-process lock would die with this CLI process and print a
    // false `vault_status=locked` while the desktop stays unlocked, so we never fall
    // back: require the desktop to be running, consistent with unlock/list_slots/list_keys.
    match ipc::IpcClient::lock() {
        Ok(()) => {
            println!("vault_status=locked");
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

fn print_slots() -> Result<(), Box<dyn std::error::Error>> {
    match ipc::IpcClient::list_slots() {
        Ok(slots) => {
            println!("slot_count={}", slots.len());
            for slot in slots {
                println!("slot_id={}", slot.slot_id);
                println!("slot_type={}", slot.slot_type);
                println!("slot_label={}", escape_value(&slot.label));
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
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
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
            let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
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
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
        }
    }
}

fn print_ssh_keys() -> Result<(), Box<dyn std::error::Error>> {
    match ipc::IpcClient::list_keys() {
        Ok(keys) => {
            println!("key_count={}", keys.len());
            for key in keys {
                println!("key_id={}", key.key_id);
                println!("key_name={}", escape_value(&key.name));
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
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)))
        }
    }
}

/// Escape a value for script-safe key=value output.
///
/// Replaces `\` with `\\`, `\n` with `\n`, and `\r` with `\r` so every field
/// occupies exactly one line regardless of the stored string's content.
fn escape_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
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
    use super::{escape_value, render_status};
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

    #[test]
    fn escape_value_handles_newline_and_backslash() {
        assert_eq!(escape_value("plain"), "plain");
        assert_eq!(escape_value("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_value("a\r\nb"), "a\\r\\nb");
        assert_eq!(escape_value("back\\slash"), "back\\\\slash");
        assert_eq!(escape_value("mix\n\\end"), "mix\\n\\\\end");
    }
}
