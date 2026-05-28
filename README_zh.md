# kenv

`kenv` 是一款面向开发者的上下文环境安全管理工具。它的目标是把环境变量和 SSH key 统一放进一个本地加密保险箱中管理，让开发者在不同项目、终端和工具之间切换凭证时更安全、更顺滑。

本项目当前处于文档初始化阶段。这里记录的是产品方向、MVP 范围和后续架构设计；桌面应用和 CLI 代码尚未开始实现。

## 为什么需要 kenv

现代开发环境里，凭证通常散落在多个地方：

- `.env` 文件复制来复制去，容易进入 Git、聊天记录或备份目录。
- 终端、IDE、GUI 应用和 CI 配置里的环境变量经常不同步。
- SSH private key 依赖 `ssh-agent`、Keychain 或手动输入密码，体验和安全边界都不够清晰。
- 云盘同步很方便，但直接同步明文凭证不可接受。

`kenv` 希望解决的是同一个问题：开发者需要一个按上下文工作的本地凭证保险箱。它应该能保存、解锁、注入和审计凭证，同时不把明文交给同步服务。

## 产品定位

`kenv` 是一个 macOS first 的 Rust + Tauri 2.0 桌面工具，并配套 CLI/shell 集成。

核心方向：

- **环境变量保险箱**：把 API token、数据库连接串、项目密钥等按 context 加密保存。
- **SSH key 保险箱**：统一登记或导入 SSH key，并为后续本地解锁和签名工作流打基础。
- **桌面管理入口**：通过 Tauri UI 管理 vault、context、变量、key 和基础状态。
- **CLI/shell 工作流**：通过命令行把已解锁的 context 注入终端会话。
- **macOS 安全解锁体验**：在 macOS 上利用 Secure Enclave/Touch ID 提升本机解锁体验。
- **零知识同步方向**：vault 文件可以放进 iCloud、WebDAV 或其他同步盘，但同步方只能看到密文。

## MVP 状态

第一版 MVP 要证明两个最小闭环：

1. 开发者可以创建并解锁本地加密 vault，按 context 保存环境变量，并从终端激活这些变量。
2. 开发者可以在 vault 中保存 SSH key material 或 key reference，并为 SSH 相关操作触发本地解锁流程。

MVP 必须包含桌面端和 CLI 两个入口，但不会承诺完整替代 `ssh-agent`、实现 GUI app 环境注入、云同步、团队协作或跨平台发布。

更多范围说明见 [docs/MVP.md](docs/MVP.md)。

## 架构方向

`kenv` 的核心逻辑会放在 Rust core 中，桌面应用和 CLI 都调用同一套能力，避免出现两套安全逻辑。

计划中的主要边界：

- Rust core：vault、crypto、context、环境变量和 SSH key metadata。
- Tauri desktop：桌面 UI、命令桥接、状态展示和用户操作入口。
- CLI helper：shell 激活、SSH 工作流入口和脚本友好的输出。
- macOS platform adapter：Secure Enclave/Touch ID 等平台能力封装。
- Storage/sync boundary：本地密文文件格式，以及未来同步适配边界。

更多架构说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 安全模型

`kenv` 采用混合安全模型：

- vault 数据由 kenv 本地加密保存，目标算法为 AES-256-GCM。
- macOS 上可使用 Secure Enclave/Touch ID 保护本机解锁材料。
- kenv 避免对 macOS Keychain 形成强绑定，但可以使用 Apple Security APIs 改善本机解锁体验。
- 云盘或同步服务只同步密文，不应看到明文凭证或可直接使用的密钥。

更多安全边界见 [docs/SECURITY.md](docs/SECURITY.md)。

## 非目标

当前阶段不做这些承诺：

- 已经可以运行的 Tauri 桌面应用。
- 完整 `ssh-agent` 协议兼容。
- Finder/Spotlight 启动的 GUI 应用环境变量注入。
- iCloud/WebDAV 同步实现。
- 团队 vault、权限模型或组织级审计。
- Windows/Linux 可用版本。

## 技术方向

- Rust
- Tauri 2.0
- macOS first
- CLI/shell integration
- Planned AES-256-GCM encrypted local vault
- Planned Secure Enclave/Touch ID unlock support on macOS

## 开发

本仓库已初始化为拆分式 Rust 和 pnpm workspace：

- `crates/kenv-core`：共享核心，用于 vault 状态、安全错误和后续 vault 逻辑。
- `crates/kenv-cli`：面向终端的入口，用于脚本友好的工作流。
- `apps/desktop`：Tauri 2 + Vue TypeScript 桌面应用。

安装依赖并运行当前验证套件：

```sh
pnpm install
cargo test --workspace
```

常用命令：

```sh
pnpm dev:desktop
pnpm build:frontend
pnpm test
pnpm lint
cargo run -p kenv-cli -- status
```

在加密 vault 存储实现之前，初始应用会有意报告 `vault_status=missing`。不要提交 `.env` 文件或包含明文凭证的测试 fixture。

## License

MIT
