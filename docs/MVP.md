# kenv MVP

This document defines the scope of the first usable `kenv` product. The MVP is not meant to implement the full vision at once. Its job is to prove that `kenv` can manage environment variables and SSH keys inside one secure context model, while connecting to real developer workflows through both the desktop app and CLI.

Chinese documentation is available in [MVP_zh.md](MVP_zh.md).

## MVP Goals

The MVP must prove that developers can:

- Create and unlock a local encrypted kenv vault.
- Create named contexts in the vault, such as projects, clients, environments, or workspaces.
- Store environment variables under a context.
- Activate a context from the terminal and inject its variables into the current shell session.
- Store SSH key material or SSH key references in the vault.
- Trigger a local unlock flow for SSH-related usage.
- Manage the vault, contexts, variables, and SSH keys through the Tauri desktop app.

## Environment Variable Loop

Environment variables are the first MVP loop.

Users should be able to create contexts in the desktop app and add key/value environment variables to them. Plaintext values should only appear briefly in memory after the user unlocks the vault; persisted data must remain encrypted.

The CLI needs to provide a shell-consumable activation flow. The target experience is similar to:

```sh
eval "$(kenv env activate <context>)"
```

The exact command syntax may change during implementation, but the MVP must preserve three behaviors:

- Activate the requested context.
- Output environment variable declarations that the current shell can consume.
- Avoid writing plaintext variables to unnecessary persistent files.

## SSH Key Loop

SSH keys are the second MVP loop.

Users should be able to import or register SSH keys through the desktop app. The MVP may support two record types:

- key material: the private key contents are encrypted and stored by kenv.
- key reference: kenv stores metadata such as the key path, fingerprint, purpose, and notes.

The MVP needs to define the local unlock flow for SSH usage, but it does not need to fully replace the `ssh-agent` protocol. The first version should give future agent helpers or signing helpers a clear boundary: when `ssh` or `git` needs a protected key, kenv can trigger local unlock and complete the required operation inside an authorized window.

## Desktop Entrypoint

The Tauri desktop app is the main management entrypoint.

The MVP desktop app should cover:

- Vault creation, unlock, and lock status.
- Context list and context details.
- Environment variable creation, editing, deletion, and visibility state.
- SSH key creation, import, or registration.
- Basic security settings and current platform capability status.

The desktop app should not duplicate core security logic. It should call shared Rust core through Tauri commands.

## CLI Entrypoint

The CLI is the developer workflow entrypoint.

The MVP CLI should cover:

- Vault status checks.
- Context listing.
- Context activation output.
- SSH key listing or status checks.
- Shared use of the same vault and Rust core as the desktop app.

CLI output should be script-friendly. Commands involving plaintext credentials must avoid logging and extra persistence by default.

## Explicitly Out Of Scope

The MVP does not promise:

- Full `ssh-agent` protocol compatibility.
- Environment variable injection into GUI apps launched from Finder, Spotlight, or Dock.
- Implementation of iCloud, WebDAV, or other sync services.
- Team sharing, organization permissions, approval flows, or audit backends.
- Windows/Linux usable releases.
- CI/CD integrations.
- Browser extensions or IDE plugins.

## Success Criteria

When the MVP is complete, a developer should be able to follow this path:

1. Open the kenv desktop app.
2. Create a local encrypted vault.
3. Create a project context.
4. Add several environment variables.
5. Activate that context in the terminal and run commands that depend on those variables.
6. Import or register an SSH key.
7. Trigger a local unlock flow in an SSH-related scenario.

If this path works, kenv has proven its core value: credentials are centrally managed by context, ciphertext is safe to persist, and the developer experience connects to real tools.
