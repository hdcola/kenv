# kenv

`kenv` is a context-aware environment security manager for developers. Its goal is to manage environment variables and SSH keys together in a local encrypted vault, making credential switching across projects, terminals, and tools safer and smoother.

This project is currently in the documentation initialization stage. The repository describes the product direction, MVP scope, and architecture plan; the desktop app and CLI have not been implemented yet.

Chinese documentation is available in [README_zh.md](README_zh.md).

## Why kenv Exists

Modern development credentials are often scattered across many places:

- `.env` files get copied between projects and can easily end up in Git, chats, or backups.
- Terminals, IDEs, GUI apps, and CI configuration often drift out of sync.
- SSH private keys depend on `ssh-agent`, Keychain, or repeated passphrase entry, with unclear UX and security boundaries.
- Cloud drives are convenient, but syncing plaintext credentials is unacceptable.

`kenv` addresses one core problem: developers need a local credential vault that works by context. It should store, unlock, inject, and audit credentials without giving plaintext to sync providers.

## Product Positioning

`kenv` is a macOS-first Rust + Tauri 2.0 desktop tool with companion CLI/shell integrations.

Core directions:

- **Environment variable vault**: store API tokens, database URLs, project secrets, and similar values encrypted by context.
- **SSH key vault**: register or import SSH keys and prepare the foundation for local unlock and signing workflows.
- **Desktop management entrypoint**: manage vaults, contexts, variables, keys, and basic status through a Tauri UI.
- **CLI/shell workflow**: inject an unlocked context into a terminal session from the command line.
- **macOS secure unlock UX**: use Secure Enclave/Touch ID on macOS to improve local unlock experience.
- **Zero-knowledge sync direction**: vault files can live in iCloud, WebDAV, or another sync folder, while sync providers only see ciphertext.

## MVP Status

The first MVP should prove two narrow working loops:

1. A developer can create and unlock a local encrypted vault, store environment variables by context, and activate those variables from the terminal.
2. A developer can store SSH key material or SSH key references in the vault and trigger a local unlock flow for SSH-related usage.

The MVP must include both desktop and CLI entrypoints, but it will not promise a complete `ssh-agent` replacement, GUI app environment injection, cloud sync, team collaboration, or cross-platform releases.

See [docs/MVP.md](docs/MVP.md) for the full scope.

## Architecture Direction

`kenv` will keep its core logic in Rust core, shared by both the desktop app and CLI. This avoids maintaining two separate security implementations.

Planned boundaries:

- Rust core: vault, crypto, context, environment variables, and SSH key metadata.
- Tauri desktop: UI, command bridge, status display, and user operation entrypoint.
- CLI helper: shell activation, SSH workflow entrypoint, and script-friendly output.
- macOS platform adapter: Secure Enclave/Touch ID and related platform capabilities.
- Storage/sync boundary: local ciphertext file format and future sync adapter boundary.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for more detail.

## Security Model

`kenv` uses a hybrid security model:

- Vault data is encrypted locally by kenv, with AES-256-GCM as the target algorithm.
- On macOS, Secure Enclave/Touch ID can protect local unlock material.
- kenv avoids strong lock-in to macOS Keychain, while still allowing Apple Security APIs to improve local unlock UX.
- Cloud drives or sync services should only sync ciphertext and should not see plaintext credentials or usable key material.

See [docs/SECURITY.md](docs/SECURITY.md) for security boundaries.

## Non-Goals

The current stage does not promise:

- A runnable Tauri desktop application.
- Full `ssh-agent` protocol compatibility.
- Environment variable injection into GUI apps launched from Finder/Spotlight/Dock.
- iCloud/WebDAV sync implementation.
- Team vaults, permission models, or organization-level audit.
- Windows/Linux usable releases.

## Technology Direction

- Rust
- Tauri 2.0
- macOS first
- CLI/shell integration
- Planned AES-256-GCM encrypted local vault
- Planned Secure Enclave/Touch ID unlock support on macOS

## License

MIT
