export const zhCN = {
  sidebar: {
    ariaLabel: "kenv 分区",
    eyebrow: "本地保险库",
  },
  nav: {
    vault: "保险库",
    contexts: "上下文",
    ssh: "SSH 密钥",
    security: "安全",
  },
  topbar: {
    eyebrow: "面向 macOS 和 Linux 的开发者凭据管理",
    title: "安全上下文，准备好迎接第一个保险库。",
    refresh: "刷新保险库状态",
    languageLabel: "语言",
  },
  status: {
    eyebrow: "保险库状态",
    missing: "缺失",
    locked: "已锁定",
    unlocked: "已解锁",
    unknown: "未知",
    corrupted: "已损坏",
    needs_recreation: "需要重建",
    locked_description: "已加密，完整性将在解锁时验证。",
    needs_recreation_description:
      "您的保险库使用的是不再受支持的旧格式。请备份已存储的凭据，然后运行：kenv create",
    copy: "共享的 Rust 核心已经接通。保险库创建现已可用，解锁与凭证工作流是接下来的 MVP 重点。",
  },
  panels: {
    contexts: {
      eyebrow: "上下文",
      title: "还没有上下文",
      copy: "项目、客户和环境上下文会在保险库存储落地后显示在这里。",
    },
    env: {
      eyebrow: "环境变量",
      title: "明文不会进入存储",
      copy: "只有在明确解锁后，变量值才会显示并按需注入到 shell 中。",
    },
    ssh: {
      eyebrow: "SSH 密钥",
      title: "密钥记录尚未就绪",
      copy: "导入的密钥材料和路径引用会共用同一套加密核心模型。",
    },
    security: {
      eyebrow: "平台能力",
      title: "已规划 macOS 解锁适配器",
      copy: "当前构建目标是 macOS 和 Linux。Touch ID 和 Secure Enclave 支持会在不直接持有密文的前提下提升 macOS 本地解锁体验。",
    },
  },
  errors: {
    refreshFailed: "无法刷新保险库状态：{message}",
  },
  create: {
    eyebrow: "创建保险库",
    title: "保护您的环境",
    description: "设置主密码以创建加密保险库。",
    passwordLabel: "主密码",
    confirmLabel: "确认密码",
    submit: "创建保险库",
    creating: "创建中…",
    errors: {
      mismatch: "密码不匹配",
      weak: "密码不能为空",
      alreadyExists: "保险库已存在",
      unknown: "创建保险库失败",
    },
  },
} as const;
