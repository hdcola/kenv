# kenv Development

This repository uses a split workspace:

- `crates/kenv-core`: shared Rust security and product core.
- `crates/kenv-cli`: script-friendly CLI entrypoint.
- `apps/desktop`: Tauri 2 desktop app with a Vue TypeScript frontend.

## Prerequisites

- Rust and Cargo.
- Node.js >= 22.
- pnpm.
- Xcode Command Line Tools on macOS.
- Linux desktop dependencies required by Tauri/WebKitGTK when developing on Linux.

## Platform Support

- macOS: currently supported.
- Linux: currently supported.
- Windows: not implemented yet.

## Setup

```sh
pnpm install
cargo test --workspace
```

## Common Commands

```sh
pnpm dev:desktop
pnpm build:frontend
pnpm test
pnpm lint
cargo run -p kenv-cli -- status
```

## Security Notes

- Do not commit `.env` files or plaintext credential fixtures.
- Do not log environment variable values, private key contents, or unlock material.
- Desktop and CLI features must call `kenv-core` for vault state and security behavior.
- The current implementation reports real vault state, including the initial missing state before a vault is created.
