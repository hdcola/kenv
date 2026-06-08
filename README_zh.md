# kenv

`kenv` 是一款面向开发者的上下文环境安全管理工具。它的目标是把环境变量和 SSH key 统一放进一个本地加密保险箱中管理，让开发者在不同项目、终端和工具之间切换凭证时更安全、更顺滑。

本项目当前处于早期 MVP 阶段。仓库中已经包含产品方向、MVP 范围、架构设计、共享 Rust core、脚本友好的 CLI，以及一个支持本地加密 vault 创建、状态查询和基础锁定/解锁流程的 Tauri + Vue 桌面应用。凭证管理和更完整的工作流仍在持续实现中。

## 为什么需要 kenv

现代开发环境里，凭证通常散落在多个地方：

- `.env` 文件复制来复制去，容易进入 Git、聊天记录或备份目录。
- 终端、IDE、GUI 应用和 CI 配置里的环境变量经常不同步。
- SSH private key 依赖 `ssh-agent`、Keychain 或手动输入密码，体验和安全边界都不够清晰。
- 云盘同步很方便，但直接同步明文凭证不可接受。

`kenv` 希望解决的是同一个问题：开发者需要一个按上下文工作的本地凭证保险箱。它应该能保存、解锁、注入和审计凭证，同时不把明文交给同步服务。

## 产品定位

`kenv` 当前是一个支持 macOS 和 Linux 的 Rust + Tauri 2.0 桌面工具，并配套 CLI/shell 集成。Windows 支持会在后续阶段补上。

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

MVP 必须包含桌面端和 CLI 两个入口，但不会承诺完整替代 `ssh-agent`、实现 GUI app 环境注入、云同步、团队协作或 Windows 版本发布。

下面的清单用于跟踪仓库当前已经实现的状态，不只是 MVP 目标描述。

## MVP 进度清单

### 基础骨架

- [x] Rust workspace 已拆分为共享 core、CLI 和桌面应用
- [x] 桌面端和 CLI 都已接入同一个 Rust core crate
- [x] 已定义基础 vault 状态类型和共享错误类型
- [x] 已有最小测试覆盖当前 vault 状态行为

### Vault

- [x] 当前可以报告 `missing` 状态的 vault 状态
- [x] 本地加密 vault 文件格式已实现
- [x] vault 创建流程已实现
- [x] vault 解锁流程已实现
- [x] vault 锁定流程已实现

### Context 与环境变量

- [ ] context 数据模型已实现
- [ ] context 创建、列表、详情流程已实现
- [ ] 环境变量存储已实现
- [ ] 环境变量新增、编辑、删除流程已实现
- [ ] 解锁后明文值仅保留在内存中

### CLI 工作流

- [x] `kenv status` 可输出适合脚本消费的 vault 状态
- [x] `kenv create`、`kenv unlock` 和 `kenv lock` 已实现
- [x] `kenv slots`、`kenv keys` 和 `kenv remove-slot` 已实现
- [ ] `kenv sign` 已实现（CLI 子命令已接入，核心仍返回 `SshSigningNotImplemented`）
- [ ] context 列表命令已实现
- [ ] context 激活命令已实现
- [ ] shell 可消费的环境变量导出输出已实现

### SSH Key 工作流

- [ ] SSH key material 记录已实现
- [ ] SSH key reference 记录已实现
- [x] SSH key 列表或状态命令已实现
- [ ] SSH 相关使用时的本地解锁流程已实现

### 桌面端

- [x] Tauri 桌面壳已跑通，并接入共享 core 状态
- [x] UI 中已展示 vault 状态
- [x] UI 中的 vault 创建操作已实现
- [x] UI 中的 vault 解锁、锁定操作已实现
- [ ] context 管理 UI 已实现
- [ ] 环境变量管理 UI 已实现
- [ ] SSH key 管理 UI 已实现
- [ ] 安全设置和平台能力 UI 已实现

### macOS 安全集成

- [ ] Secure Enclave 集成已实现
- [ ] Touch ID 解锁流程已实现
- [ ] Apple Security API adapter 已实现

更多范围说明见 [docs/MVP.md](docs/MVP.md)。

## 架构方向

`kenv` 的核心逻辑会放在 Rust core 中，桌面应用和 CLI 都调用同一套能力，避免出现两套安全逻辑。

计划中的主要边界：

- Rust core：vault、crypto、context、环境变量和 SSH key metadata。
- Tauri desktop：桌面 UI、命令桥接、状态展示和用户操作入口。
- CLI helper：shell 激活、SSH 工作流入口和脚本友好的输出。
- platform adapter：当前聚焦 macOS 的 Secure Enclave/Touch ID 等平台能力，并为后续 Linux/Windows 扩展保留边界。
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

- 超出初始可运行壳之外的生产级桌面体验。
- 完整 `ssh-agent` 协议兼容。
- Finder/Spotlight 启动的 GUI 应用环境变量注入。
- iCloud/WebDAV 同步实现。
- 团队 vault、权限模型或组织级审计。
- 可用的 Windows 版本。

## 技术方向

- Rust
- Tauri 2.0
- 当前支持 macOS 和 Linux
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

当前平台支持：

- macOS：当前开发和测试已支持。
- Linux：当前开发和测试已支持。
- Windows：暂未实现。

常用命令：

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

当前应用会按真实状态报告 vault，包括创建前的初始 `vault_status=missing` 状态。不要提交 `.env` 文件或包含明文凭证的测试 fixture。

## License

MIT
