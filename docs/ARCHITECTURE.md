# kenv Architecture

This document describes the high-level architecture direction for `kenv`. It does not create code modules yet; it is meant to guide the future Rust + Tauri 2.0 implementation.

Chinese documentation is available in [ARCHITECTURE_zh.md](ARCHITECTURE_zh.md).

## Architecture Principles

The core principle of `kenv` is: write the security logic once.

Both the desktop app and CLI should call shared Rust core. The UI, command line, and platform adapters can differ, but vault unlock, encryption, context parsing, environment variable reads, and SSH key metadata management must come from the same core library.

## Planned Modules

### Rust core

Rust core is the business and security core of kenv.

It is responsible for:

- Reading and writing vault files.
- Orchestrating encryption and decryption flows.
- Managing contexts.
- Managing environment variable records.
- Managing SSH key material and references.
- Representing vault status, errors, and audit events consistently.

Rust core does not directly care about Tauri windows, frontend components, or shell output formats.

### Tauri desktop

Tauri desktop is the main graphical entrypoint.

It is responsible for:

- Starting the desktop window.
- Exposing Tauri commands to the frontend.
- Displaying vault, context, variable, and SSH key status.
- Receiving user operations and calling Rust core.
- Handling desktop lifecycle concerns such as lock state, unlock prompts, and error display.

The desktop app should not keep an independent data model. It should display state returned by Rust core.

### CLI helper

The CLI helper is the terminal and scripting entrypoint.

It is responsible for:

- Outputting shell-consumable context activation scripts.
- Querying vault and context status.
- Supporting local command entrypoints needed by SSH workflows.
- Returning clear exit codes and script-friendly error messages.

The CLI helper shares the same vault file and Rust core as the desktop app.

### macOS platform adapter

The macOS platform adapter wraps platform capabilities.

It is responsible for:

- Secure Enclave/Touch ID unlock capabilities.
- Interacting with Apple Security APIs.
- Detecting platform capability availability.
- Translating platform errors into error types the core can understand.

This module keeps current macOS support and future Windows support from leaking platform-specific behavior into core logic, while Linux continues to use the shared core path.

### Storage and sync boundary

The MVP only implements a local vault file.

The long-term direction is to let vault files be synced through iCloud, WebDAV, Syncthing, or another user-chosen sync tool. The sync layer only handles ciphertext files. It does not participate in decryption and should never receive plaintext credentials.

If built-in sync is implemented later, it should remain an independent boundary instead of leaking into vault and crypto logic.

## Data Flow

### Environment variable activation

1. The user asks the CLI to activate a context.
2. The CLI calls Rust core to open the vault.
3. Rust core checks whether the vault is unlocked.
4. If unlock is required, Rust core completes unlock through the platform adapter or master password flow.
5. Rust core returns the environment variable set for that context.
6. The CLI outputs declarations that the current shell can consume.

### Desktop management

1. The user performs an action in the Tauri UI.
2. The frontend calls a Tauri command.
3. The Tauri command calls Rust core.
4. Rust core returns state, data, or an error.
5. The frontend updates the UI.

### SSH key usage

1. An SSH-related helper receives a request to use a key.
2. The helper calls Rust core to query key metadata.
3. Rust core decides whether unlock is required.
4. On macOS, the platform adapter can trigger Touch ID/Secure Enclave unlock.
5. After authorization succeeds, the helper completes signing or key usage inside a controlled window.

The MVP only requires this path to have clear boundaries. It does not require full `ssh-agent` protocol compatibility.

## Error Handling Direction

Errors should be represented by scenario, not just returned as strings.

Planned error categories include:

- Vault does not exist or uses an unsupported format.
- Vault is locked.
- Unlock failed or the user cancelled it.
- Context does not exist.
- Environment variable name is invalid.
- SSH key does not exist, is invalid, or is unsupported.
- Platform capability is unavailable.
- File read/write failed.

The desktop app should translate errors into user-readable prompts. The CLI should return clear exit codes and concise error messages.

## Suggested Implementation Order

1. Define Rust core data models for vaults, contexts, environment variables, and SSH keys.
2. Implement local vault file read/write and the encryption shell.
3. Implement the minimal CLI context activation path.
4. Implement Tauri desktop management for vaults, contexts, and variables.
5. Integrate the macOS unlock adapter.
6. Extend the SSH helper boundary.

This order proves core security and developer workflow first, then gradually adds desktop UX and platform capabilities.
