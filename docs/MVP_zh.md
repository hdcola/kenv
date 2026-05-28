# kenv MVP

本文定义 `kenv` 第一版可用产品的范围。MVP 的目标不是一次实现完整愿景，而是证明 `kenv` 能把环境变量和 SSH key 放进同一个安全上下文模型里管理，并通过桌面端和 CLI 连接真实开发工作流。

## MVP 目标

MVP 必须证明开发者可以：

- 创建并解锁一个本地加密 kenv vault。
- 在 vault 中创建命名 context，例如项目、客户、环境或工作区。
- 在 context 下保存环境变量。
- 从终端激活某个 context，并把变量注入当前 shell 会话。
- 在 vault 中保存 SSH key material 或 SSH key reference。
- 为 SSH 相关使用触发本地解锁流程。
- 通过 Tauri 桌面应用管理 vault、context、变量和 SSH key。

## 环境变量闭环

环境变量能力是 MVP 的第一条闭环。

用户应能在桌面端创建 context，并向其中添加 key/value 形式的环境变量。变量明文只在用户解锁 vault 后短暂出现在内存中，落盘内容必须保持加密。

CLI 需要提供 shell 可消费的激活方式。目标体验类似：

```sh
eval "$(kenv env activate <context>)"
```

该命令的具体语法可以在实现阶段调整，但 MVP 必须保留三个行为：

- 激活指定 context。
- 输出当前 shell 可以消费的环境变量声明。
- 不把明文变量写入非必要的持久化文件。

## SSH Key 闭环

SSH key 能力是 MVP 的第二条闭环。

用户应能通过桌面端导入或登记 SSH key。MVP 可以支持两类记录：

- key material：private key 内容由 kenv 加密保存。
- key reference：kenv 保存 key 的路径、fingerprint、用途和备注等 metadata。

MVP 需要定义 SSH 使用时的本地解锁流程，但不要求完整实现 `ssh-agent` 协议替代。第一版目标是让后续 agent helper 或 signing helper 有清晰边界：当 `ssh` 或 `git` 需要使用受保护 key 时，kenv 能触发本机解锁，并在授权窗口内完成必要操作。

## 桌面端入口

Tauri 桌面端是主要管理入口。

MVP 桌面端应覆盖：

- vault 创建、解锁和锁定状态。
- context 列表和 context 详情。
- 环境变量新增、编辑、删除和查看状态。
- SSH key 新增、导入或登记。
- 基础安全设置和当前平台能力状态。

桌面端不直接复制核心安全逻辑。它通过 Tauri command 调用共享 Rust core。

## CLI 入口

CLI 是开发者工作流入口。

MVP CLI 应覆盖：

- vault 状态检查。
- context 列表。
- context 激活输出。
- SSH key 列表或状态检查。
- 与桌面端共享同一个 vault 和 Rust core。

CLI 输出要适合脚本消费。涉及明文凭证的命令必须默认避免日志化和额外持久化。

## 明确不包含

MVP 不承诺以下能力：

- 完整 `ssh-agent` 协议兼容。
- Finder、Spotlight 或 Dock 启动的 GUI 应用环境变量注入。
- iCloud、WebDAV 或其他同步服务的实现。
- 团队共享、组织权限、审批或审计后台。
- Windows/Linux 可用版本。
- CI/CD 集成。
- 浏览器扩展或 IDE 插件。

## 成功标准

MVP 完成时，一个开发者应能完成这条路径：

1. 打开 kenv 桌面应用。
2. 创建本地加密 vault。
3. 创建一个项目 context。
4. 添加几个环境变量。
5. 在终端激活该 context，并运行依赖这些变量的命令。
6. 导入或登记一个 SSH key。
7. 在 SSH 相关场景中触发本地解锁流程。

如果这条路径跑通，kenv 的核心价值就已经被证明：凭证按上下文集中管理，密文可安全落盘，开发体验连接到真实开发工具。
