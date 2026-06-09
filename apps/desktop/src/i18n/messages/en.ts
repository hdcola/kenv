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
    eyebrow: "Developer credentials for macOS and Linux",
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
    needs_recreation: "Needs Recreation",
    locked_description: "Encrypted. Full integrity verified on unlock.",
    needs_recreation_description:
      "Your vault was created with an older format that is no longer supported. Back up any stored credentials, then run: kenv create",
    copy:
      "The shared Rust core is connected. Vault creation is available today, and unlock plus credential workflows are the next MVP steps.",
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
      copy: "Current builds target macOS and Linux. Touch ID and Secure Enclave support will improve local unlock on macOS without owning ciphertext.",
    },
  },
  errors: {
    refreshFailed: "Unable to refresh vault status: {message}",
  },
  create: {
    eyebrow: "Create Vault",
    title: "Secure Your Environment",
    description: "Set a master password to create your encrypted vault.",
    passwordLabel: "Master Password",
    confirmLabel: "Confirm Password",
    submit: "Create Vault",
    creating: "Creating…",
    errors: {
      mismatch: "Passwords do not match",
      weak: "Password cannot be empty",
      alreadyExists: "A vault already exists",
      unknown: "Failed to create vault",
    },
  },
} as const;
