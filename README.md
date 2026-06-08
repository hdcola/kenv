# kenv

`kenv` is a context-aware environment security manager for developers. Its goal is to manage environment variables and SSH keys together in a local encrypted vault, making credential switching across projects, terminals, and tools safer and smoother.

This project is currently in an early MVP stage. The repository now includes the product direction, MVP scope, architecture plan, a shared Rust core, a script-friendly CLI, and a Tauri + Vue desktop app with local encrypted vault creation, status reporting, and basic vault lock/unlock flows. Credential management and broader workflows are still in progress.

Chinese documentation is available in [README_zh.md](README_zh.md).

## Why kenv Exists

Modern development credentials are often scattered across many places:

- `.env` files get copied between projects and can easily end up in Git, chats, or backups.
- Terminals, IDEs, GUI apps, and CI configuration often drift out of sync.
- SSH private keys depend on `ssh-agent`, Keychain, or repeated passphrase entry, with unclear UX and security boundaries.
- Cloud drives are convenient, but syncing plaintext credentials is unacceptable.

`kenv` addresses one core problem: developers need a local credential vault that works by context. It should store, unlock, inject, and audit credentials without giving plaintext to sync providers.

## Product Positioning

`kenv` currently supports macOS and Linux as a Rust + Tauri 2.0 desktop tool with companion CLI/shell integrations. Windows support is planned for a later phase.

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

The MVP must include both desktop and CLI entrypoints, but it will not promise a complete `ssh-agent` replacement, GUI app environment injection, cloud sync, team collaboration, or a Windows release.

The checklist below tracks implemented repository status today, not just the intended MVP target state.

## MVP Progress Checklist

### Foundation

- [x] Rust workspace is split into shared core, CLI, and desktop app
- [x] Desktop app and CLI both call the same Rust core crate
- [x] Basic vault status types and shared error types are defined
- [x] Minimal tests cover current vault status behavior

### Vault

- [x] Vault status can be reported as `missing`
- [x] Local encrypted vault file format is implemented
- [x] Vault creation flow is implemented
- [x] Vault unlock flow is implemented
- [x] Vault lock flow is implemented

### Contexts And Environment Variables

- [ ] Context data model is implemented
- [ ] Context create/list/detail flows are implemented
- [ ] Environment variable storage is implemented
- [ ] Environment variable create/edit/delete flows are implemented
- [ ] Plaintext values stay memory-only after unlock

### CLI Workflow

- [x] `kenv status` prints a script-friendly vault status
- [x] `kenv create`, `kenv unlock`, and `kenv lock` are implemented
- [x] `kenv slots`, `kenv keys`, and `kenv remove-slot` are implemented
- [ ] `kenv sign` is implemented (CLI subcommand not yet added; core returns `SshSigningNotImplemented`)
- [ ] Context listing command is implemented
- [ ] Context activation command is implemented
- [ ] Shell-consumable env export output is implemented

### SSH Key Workflow

- [ ] SSH key material records are implemented
- [ ] SSH key reference records are implemented
- [x] SSH key list/status commands are implemented
- [ ] Local unlock flow for SSH-related usage is implemented

### Desktop App

- [x] Tauri desktop shell is running with shared-core status wiring
- [x] Vault status is shown in the UI
- [x] Vault creation is implemented in the UI
- [ ] Vault unlock/lock actions are implemented in the UI
- [ ] Context management UI is implemented
- [ ] Environment variable management UI is implemented
- [ ] SSH key management UI is implemented
- [ ] Security settings and platform capability UI are implemented

### macOS Security Integration

- [ ] Secure Enclave integration is implemented
- [ ] Touch ID unlock flow is implemented
- [ ] Apple Security API adapter is implemented

See [docs/MVP.md](docs/MVP.md) for the full scope.

## Architecture Direction

`kenv` will keep its core logic in Rust core, shared by both the desktop app and CLI. This avoids maintaining two separate security implementations.

Planned boundaries:

- Rust core: vault, crypto, context, environment variables, and SSH key metadata.
- Tauri desktop: UI, command bridge, status display, and user operation entrypoint.
- CLI helper: shell activation, SSH workflow entrypoint, and script-friendly output.
- platform adapters: current macOS Secure Enclave/Touch ID integration, with room to extend Linux and Windows-specific capabilities later.
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

- A production-ready desktop experience beyond the initial runnable shell.
- Full `ssh-agent` protocol compatibility.
- Environment variable injection into GUI apps launched from Finder/Spotlight/Dock.
- iCloud/WebDAV sync implementation.
- Team vaults, permission models, or organization-level audit.
- A usable Windows release.

## Technology Direction

- Rust
- Tauri 2.0
- Currently supported on macOS and Linux
- CLI/shell integration
- Planned AES-256-GCM encrypted local vault
- Planned Secure Enclave/Touch ID unlock support on macOS

## Development

The repository is initialized as a split Rust and pnpm workspace:

- `crates/kenv-core`: shared core for vault status, security errors, and future vault logic.
- `crates/kenv-cli`: terminal entrypoint for script-friendly workflows.
- `apps/desktop`: Tauri 2 + Vue TypeScript desktop app.

Install dependencies and run the current verification suite:

```sh
pnpm install
cargo test --workspace
```

Current platform support:

- macOS: supported for current development and testing.
- Linux: supported for current development and testing.
- Windows: not implemented yet.

Useful commands:

```sh
pnpm dev:desktop
pnpm build:frontend
pnpm test
pnpm lint
cargo run -p kenv-cli -- create
cargo run -p kenv-cli -- status
cargo run -p kenv-cli -- unlock
cargo run -p kenv-cli -- lock
cargo run -p kenv-cli -- slots
cargo run -p kenv-cli -- keys
```

Today the app reports real vault status, including the initial `vault_status=missing` state before a vault is created. Do not commit `.env` files or plaintext credential fixtures.

## License

MIT
