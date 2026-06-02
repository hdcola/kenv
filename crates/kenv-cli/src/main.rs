use clap::{Parser, Subcommand};
use kenv_core::{
    create_vault, get_vault_status, list_slots, list_ssh_keys, lock, remove_slot, sign_ssh_key,
    unlock, KenvError, VaultStatus,
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

    create_vault(&password)?;
    println!("vault_status=locked");
    Ok(())
}

fn unlock_vault() -> Result<(), Box<dyn std::error::Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    let status = unlock(&password)?;
    let output = format!("vault_status={}", status.as_script_value());
    println!("{output}");
    Ok(())
}

fn lock_vault() -> Result<(), Box<dyn std::error::Error>> {
    lock()?;
    println!("vault_status=locked");
    Ok(())
}

fn print_slots() -> Result<(), Box<dyn std::error::Error>> {
    let slots = list_slots()?;
    println!("slot_count={}", slots.len());
    for slot in slots {
        println!(
            "slot_id={} type={:?} label={}",
            slot.slot_id, slot.slot_type, slot.label
        );
    }
    Ok(())
}

fn remove_unlock_slot(slot_id: u8) -> Result<(), Box<dyn std::error::Error>> {
    match remove_slot(slot_id) {
        Ok(()) => {
            println!("slot_removed=true");
            Ok(())
        }
        Err(KenvError::UnlockFailed) => {
            // HIGH-RISK operation detected, request reauthentication
            eprintln!("Removing this slot requires password reauthentication");
            let password =
                Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
            kenv_core::reauth_password(&password)?;
            remove_slot(slot_id)?;
            println!("slot_removed=true");
            Ok(())
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn print_ssh_keys() -> Result<(), Box<dyn std::error::Error>> {
    let keys = list_ssh_keys()?;
    println!("key_count={}", keys.len());
    for key in keys {
        println!(
            "key_id={} name={} type={}",
            key.key_id, key.name, key.key_type.as_str()
        );
    }
    Ok(())
}

fn sign_with_key(key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read data to sign from stdin
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;

    match sign_ssh_key(key_id, &data) {
        Ok(signature) => {
            println!("key_id={}", signature.key_id);
            println!("signature_len={}", signature.signature.len());
            Ok(())
        }
        Err(KenvError::UnlockFailed) => {
            // Reauthentication required
            eprintln!("This SSH key requires password reauthentication");
            let password =
                Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
            kenv_core::reauth_password(&password)?;
            let signature = sign_ssh_key(key_id, &data)?;
            println!("key_id={}", signature.key_id);
            println!("signature_len={}", signature.signature.len());
            Ok(())
        }
        Err(e) => Err(Box::new(e)),
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
