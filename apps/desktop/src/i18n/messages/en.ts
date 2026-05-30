export const en = {
  sidebar: {
    ariaLabel: "kenv sections",
    eyebrow: "local vault",
  },
  nav: {
    vault: "Vault",
    contexts: "Contexts",
    ssh: "SSH keys",
    security: "Security",
  },
  topbar: {
    eyebrow: "macOS-first developer credentials",
    title: "Secure contexts, ready for the first vault.",
    refresh: "Refresh vault status",
    languageLabel: "Language",
  },
  status: {
    eyebrow: "vault status",
    missing: "Missing",
    locked: "Locked",
    unlocked: "Unlocked",
    unknown: "Unknown",
    corrupted: "Corrupted",
    copy:
      "The shared Rust core is connected. Vault creation and encrypted storage are intentionally still waiting behind the MVP security boundary.",
  },
  panels: {
    contexts: {
      eyebrow: "contexts",
      title: "No contexts yet",
      copy: "Project, client, and environment contexts will appear here once vault storage lands.",
    },
    env: {
      eyebrow: "environment variables",
      title: "Plaintext stays out of storage",
      copy: "Values will be revealed only after explicit unlock and emitted to shells on request.",
    },
    ssh: {
      eyebrow: "ssh keys",
      title: "Key records pending",
      copy: "Imported key material and path references will share the same encrypted core model.",
    },
    security: {
      eyebrow: "platform capabilities",
      title: "macOS unlock adapter planned",
      copy: "Touch ID and Secure Enclave support will improve local unlock without owning ciphertext.",
    },
  },
  errors: {
    refreshFailed: "Unable to refresh vault status: {message}",
  },
} as const;
