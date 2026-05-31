# kenv Security Model

本文说明 `kenv` 的安全目标、MVP 边界和安全承诺。当前项目尚未实现这些能力，本文用于约束后续设计和实现。

## 安全目标

`kenv` 的目标是让开发者可以安全地本地保存和使用开发凭证。

主要目标：

- 凭证落盘时必须加密。
- vault 文件可以放进用户自己的同步工具中，但同步方不能读取明文。
- 解锁后的明文只应在必要的内存和进程边界中短暂存在。
- 桌面端和 CLI 必须共享同一套安全逻辑。
- macOS 上可以使用 Secure Enclave/Touch ID 改善解锁体验。
- 当前实现目标平台是 macOS 和 Linux。Windows 支持延后到后续阶段处理。

## 混合解锁模型

`kenv` 采用混合安全模型：

- vault 密文由 kenv 自己管理。
- 数据加密目标算法为 AES-256-GCM。
- 用户拥有主密码或等价的主解锁材料。
- macOS 上可使用 Secure Enclave/Touch ID 保护本机解锁材料。
- Apple Security APIs 可以参与本机解锁体验，但不应成为 vault 密文可用性的唯一前提。

这意味着 kenv 的目标不是把所有秘密直接交给 macOS Keychain 托管。更准确的表述是：kenv 避免对 Keychain 的强绑定，同时允许使用 macOS 安全能力提升本机体验。

## 零知识同步原则

kenv 的长期同步模型是零知识同步。

如果用户把 vault 文件放入 iCloud、WebDAV、Dropbox、Syncthing 或其他同步工具，同步服务只能看到密文、文件大小、修改时间等外部元数据。同步服务不应获得：

- 环境变量明文。
- SSH private key 明文。
- 可直接解锁 vault 的密钥材料。
- Touch ID 或 Secure Enclave 保护的本机解锁材料。

MVP 不实现内置同步，但 vault 文件格式和安全模型需要为未来同步保留空间。

## MVP 威胁模型

MVP 主要防护这些风险：

- `.env` 文件、SSH key 或 token 以明文散落在项目目录。
- 凭证被意外提交到 Git。
- 云盘或备份系统读取同步目录中的明文凭证。
- 不同终端上下文混用错误凭证。
- 本机短暂离开时，已锁定 vault 不应被直接读取。

MVP 不承诺防护这些风险：

- 已经完全控制用户机器的恶意软件。
- 已经能读取当前进程内存的攻击者。
- 用户主动复制明文凭证到不安全位置。
- 操作系统、固件或 Secure Enclave 本身被攻破。
- 被篡改的 kenv 二进制或供应链攻击。
- 多人协作中的恶意成员或权限滥用。

## 明文处理原则

后续实现应遵守这些原则：

- 明文凭证只在用户明确解锁后出现。
- CLI 不应默认把明文写入日志、历史记录或临时文件。
- 桌面端不应在锁定状态展示明文。
- 错误信息不得包含凭证明文。
- 调试日志默认不得包含环境变量值或 private key 内容。
- shell 激活输出应只发送到调用方请求的标准输出。

## SSH Key 安全边界

MVP 可以保存 SSH key material 或 key reference。

如果保存 key material，private key 内容必须由 vault 加密保护。如果保存 key reference，kenv 至少应保存 fingerprint、用途、备注和路径等 metadata，并在使用时明确告诉用户实际 key material 的来源。

完整 `ssh-agent` 替代是后续目标。MVP 阶段只定义本地解锁和受控使用边界，不承诺支持所有 agent protocol 细节。

## 平台能力

macOS 和 Linux 是当前目标平台。Windows 支持会在后续阶段处理。

macOS 上，kenv 可以使用：

- Secure Enclave。
- Touch ID。
- LocalAuthentication。
- Apple Security APIs。

这些能力用于改善解锁体验和保护本机解锁材料。它们不改变零知识同步原则：同步出去的 vault 文件仍然必须是 kenv 自己管理的密文。

未来 Windows 支持需要通过平台 adapter 扩展，而不是把 macOS 逻辑写进 Rust core。

## 安全文档承诺边界

在实现完成前，项目文档不应声称：

- kenv 已经通过安全审计。
- kenv 已经可以完全替代 `ssh-agent`。
- kenv 已经实现端到端云同步。
- kenv 可以抵御本机完全沦陷后的攻击者。
- kenv 完全不使用任何 Apple Security API。

文档可以承诺的是设计方向：本地加密、密文同步、macOS 安全解锁、共享 Rust core，以及明确的 MVP 范围。
