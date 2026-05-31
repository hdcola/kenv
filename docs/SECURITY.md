# kenv Security Model

This document explains the security goals, MVP boundaries, and security commitments for `kenv`. The project has not implemented these capabilities yet; this document constrains future design and implementation.

Chinese documentation is available in [SECURITY_zh.md](SECURITY_zh.md).

## Security Goals

`kenv` aims to let developers store and use development credentials safely on their own machines.

Primary goals:

- Credentials must be encrypted when persisted.
- Vault files can live inside user-chosen sync tools, but sync providers must not be able to read plaintext.
- After unlock, plaintext should only exist briefly inside necessary memory and process boundaries.
- The desktop app and CLI must share the same security logic.
- On macOS, Secure Enclave/Touch ID can improve the unlock experience.
- The current implementation target is macOS and Linux. Windows support is deferred for a later phase.

## Hybrid Unlock Model

`kenv` uses a hybrid security model:

- Vault ciphertext is managed by kenv.
- The target data encryption algorithm is AES-256-GCM.
- The user has a master password or equivalent master unlock material.
- On macOS, Secure Enclave/Touch ID can protect local unlock material.
- Apple Security APIs can participate in the local unlock experience, but they should not become the only prerequisite for vault ciphertext usability.

This means kenv is not trying to hand all secrets directly to macOS Keychain for custody. The more precise statement is that kenv avoids strong Keychain lock-in while still allowing macOS security capabilities to improve local UX.

## Zero-Knowledge Sync Principle

kenv's long-term sync model is zero-knowledge sync.

If a user places a vault file in iCloud, WebDAV, Dropbox, Syncthing, or another sync tool, the sync service should only see ciphertext, file size, modification time, and other external metadata. The sync service must not obtain:

- Plaintext environment variables.
- Plaintext SSH private keys.
- Key material that can directly unlock the vault.
- Local unlock material protected by Touch ID or Secure Enclave.

The MVP does not implement built-in sync, but the vault file format and security model need to leave room for future sync.

## MVP Threat Model

The MVP mainly protects against these risks:

- `.env` files, SSH keys, or tokens scattered as plaintext across project directories.
- Credentials accidentally committed to Git.
- Cloud drives or backup systems reading plaintext credentials in synced directories.
- Incorrect credentials used because terminal contexts were mixed up.
- A locked vault being directly readable when the user briefly steps away from the machine.

The MVP does not promise protection against:

- Malware that already has full control of the user's machine.
- Attackers that can read current process memory.
- Users intentionally copying plaintext credentials to unsafe locations.
- Compromise of the operating system, firmware, or Secure Enclave itself.
- Tampered kenv binaries or supply-chain attacks.
- Malicious members or permission abuse in multi-user collaboration.

## Plaintext Handling Principles

Future implementation should follow these principles:

- Plaintext credentials only appear after explicit user unlock.
- The CLI should not write plaintext to logs, shell history, or temporary files by default.
- The desktop app should not show plaintext while locked.
- Error messages must not contain plaintext credentials.
- Debug logs must not contain environment variable values or private key contents by default.
- Shell activation output should only be sent to the standard output requested by the caller.

## SSH Key Security Boundary

The MVP may store SSH key material or SSH key references.

If kenv stores key material, private key contents must be encrypted by the vault. If kenv stores a key reference, it should at minimum store metadata such as fingerprint, purpose, notes, and path, and clearly tell the user where the actual key material comes from when it is used.

A complete `ssh-agent` replacement is a future goal. The MVP only defines the local unlock and controlled usage boundary; it does not promise support for every agent protocol detail.

## Platform Capabilities

macOS and Linux are the current target platforms. Windows support is deferred for a later phase.

On macOS, kenv may use:

- Secure Enclave.
- Touch ID.
- LocalAuthentication.
- Apple Security APIs.

These capabilities improve unlock UX and protect local unlock material. They do not change the zero-knowledge sync principle: synced vault files must remain ciphertext managed by kenv.

Future Windows support should be added through platform adapters rather than embedding macOS logic in Rust core.

## Security Documentation Boundaries

Before implementation is complete, project documentation should not claim that:

- kenv has passed a security audit.
- kenv can fully replace `ssh-agent`.
- kenv has implemented end-to-end cloud sync.
- kenv can resist attackers after the local machine is fully compromised.
- kenv never uses any Apple Security API.

The documentation may commit to the design direction: local encryption, ciphertext sync, macOS secure unlock, shared Rust core, and explicit MVP scope.
