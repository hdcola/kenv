use clap::{Parser, Subcommand};
use kenv_core::{create_vault, get_vault_status, KenvError, VaultStatus};
use zeroize::Zeroize;

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
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Status => print_status(),
        Commands::Create => create_new_vault(),
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
    let mut password = rpassword::prompt_password("Enter master password: ")?;
    let mut confirm = rpassword::prompt_password("Confirm master password: ")?;

    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err("passwords do not match".into());
    }

    let result = create_vault(&password);
    password.zeroize();
    confirm.zeroize();

    result?;
    println!("vault_status=created");
    Ok(())
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
}
