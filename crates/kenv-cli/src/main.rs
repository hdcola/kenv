use clap::{Parser, Subcommand};
use kenv_core::get_vault_status;

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
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Status => print_status(),
    };

    if let Err(error) = result {
        eprintln!("error={error}");
        std::process::exit(1);
    }
}

fn print_status() -> Result<(), Box<dyn std::error::Error>> {
    let status = get_vault_status()?;
    println!("vault_status={}", status.as_script_value());
    Ok(())
}
