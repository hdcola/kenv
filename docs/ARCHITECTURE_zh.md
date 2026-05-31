# kenv Architecture

本文描述 `kenv` 的高层架构方向。当前阶段不创建代码模块，本文用于指导后续 Rust + Tauri 2.0 实现。

## 架构原则

`kenv` 的核心原则是：安全逻辑只写一套。

桌面端和 CLI 都应该调用共享 Rust core。UI、命令行和平台适配层可以不同，但 vault 解锁、加密、context 解析、环境变量读取、SSH key metadata 管理等行为必须来自同一个核心库。

## 计划模块

### Rust core

Rust core 是 kenv 的业务和安全核心。

它负责：

- vault 文件读取和写入。
- 加密和解密流程编排。
- context 管理。
- 环境变量记录管理。
- SSH key material/reference 管理。
- vault 状态、错误和审计事件的统一表达。

Rust core 不直接关心 Tauri 窗口、前端组件或 shell 输出格式。

### Tauri desktop

Tauri desktop 是主要图形入口。

它负责：

- 启动桌面窗口。
- 暴露 Tauri commands 给前端。
- 展示 vault、context、变量和 SSH key 状态。
- 接收用户操作并调用 Rust core。
- 处理桌面端生命周期，例如锁定、解锁提示和错误展示。

桌面端不保存独立数据模型。它展示 Rust core 返回的状态。

### CLI helper

CLI helper 是终端和脚本入口。

它负责：

- 输出 shell 可消费的 context 激活脚本。
- 查询 vault 和 context 状态。
- 支持 SSH 工作流所需的本地命令入口。
- 返回明确的退出码和脚本友好的错误信息。

CLI helper 与桌面端共享同一个 vault 文件和 Rust core。

### macOS platform adapter

macOS platform adapter 封装平台能力。

它负责：

- Secure Enclave/Touch ID 解锁能力。
- 与 Apple Security APIs 交互。
- 平台能力探测。
- 把平台错误转换为 core 可以理解的错误类型。

该模块的存在是为了让当前 macOS 支持与未来 Windows 支持保持清晰边界，同时 Linux 继续走共享 core 路径，不把平台差异写死在核心逻辑里。

### Storage and sync boundary

MVP 只实现本地 vault 文件。

长期方向是让 vault 文件可以被 iCloud、WebDAV、Syncthing 或其他用户自选同步工具同步。同步层只处理密文文件，不参与解密，也不应获得明文凭证。

后续如果实现内置同步，也应作为独立边界，而不是侵入 vault 和 crypto 逻辑。

## 数据流

### 环境变量激活

1. 用户在 CLI 中请求激活某个 context。
2. CLI 调用 Rust core 打开 vault。
3. Rust core 检查 vault 是否已解锁。
4. 如果需要解锁，Rust core 通过平台 adapter 或主密码流程完成解锁。
5. Rust core 返回该 context 的环境变量集合。
6. CLI 输出当前 shell 可以消费的声明。

### 桌面端管理

1. 用户在 Tauri UI 中执行操作。
2. 前端调用 Tauri command。
3. Tauri command 调用 Rust core。
4. Rust core 返回状态、数据或错误。
5. 前端更新界面。

### SSH key 使用

1. SSH 相关 helper 收到使用某个 key 的请求。
2. helper 调用 Rust core 查询 key metadata。
3. Rust core 判断是否需要解锁。
4. macOS 上可通过 platform adapter 触发 Touch ID/Secure Enclave 解锁。
5. 授权成功后，helper 在受控窗口内完成签名或 key 使用流程。

MVP 只要求这条链路有清晰边界，不要求完整 `ssh-agent` 协议兼容。

## 错误处理方向

错误需要按场景表达，而不是只返回字符串。

计划中的错误类别包括：

- vault 不存在或格式不受支持。
- vault 已锁定。
- 解锁失败或用户取消。
- context 不存在。
- 环境变量名称无效。
- SSH key 不存在、格式无效或不受支持。
- 平台能力不可用。
- 文件读写失败。

桌面端应把错误翻译成用户可理解的提示。CLI 应返回明确退出码和简洁错误信息。

## 后续实现顺序建议

1. 定义 Rust core 的 vault、context、env var 和 SSH key 数据模型。
2. 实现本地 vault 文件读写和加密外壳。
3. 实现 CLI 的 context 激活最小链路。
4. 实现 Tauri 桌面端的 vault/context/变量管理。
5. 接入 macOS 解锁 adapter。
6. 扩展 SSH helper 边界。

这个顺序优先证明核心安全和开发工作流，再逐步增加桌面体验和平台能力。
