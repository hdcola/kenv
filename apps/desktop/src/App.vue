<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

type VaultStatus = "missing" | "locked" | "unlocked";

const vaultStatus = ref<VaultStatus>("missing");
const statusError = ref("");

const statusLabel = computed(() => {
  switch (vaultStatus.value) {
    case "locked":
      return "Locked";
    case "unlocked":
      return "Unlocked";
    default:
      return "Missing";
  }
});

const statusTone = computed(() => `status-pill status-pill--${vaultStatus.value}`);

async function refreshVaultStatus() {
  statusError.value = "";

  try {
    vaultStatus.value = await invoke<VaultStatus>("get_vault_status");
  } catch (error) {
    statusError.value = error instanceof Error ? error.message : String(error);
  }
}

onMounted(refreshVaultStatus);
</script>

<template>
  <main class="shell">
    <aside class="sidebar" aria-label="kenv sections">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">k</span>
        <div>
          <p class="eyebrow">local vault</p>
          <h1>kenv</h1>
        </div>
      </div>

      <nav class="nav-list">
        <a class="nav-item nav-item--active" href="#vault">Vault</a>
        <a class="nav-item" href="#contexts">Contexts</a>
        <a class="nav-item" href="#ssh">SSH keys</a>
        <a class="nav-item" href="#security">Security</a>
      </nav>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <p class="eyebrow">macOS-first developer credentials</p>
          <h2>Secure contexts, ready for the first vault.</h2>
        </div>
        <button class="icon-button" type="button" aria-label="Refresh vault status" @click="refreshVaultStatus">
          ↻
        </button>
      </header>

      <section id="vault" class="status-band">
        <div>
          <p class="eyebrow">vault status</p>
          <p class="status-title">{{ statusLabel }}</p>
          <p class="status-copy">
            The shared Rust core is connected. Vault creation and encrypted storage are intentionally
            still waiting behind the MVP security boundary.
          </p>
          <p v-if="statusError" class="error-text">{{ statusError }}</p>
        </div>
        <span :class="statusTone">{{ vaultStatus }}</span>
      </section>

      <section class="grid">
        <article id="contexts" class="panel">
          <p class="eyebrow">contexts</p>
          <h3>No contexts yet</h3>
          <p>Project, client, and environment contexts will appear here once vault storage lands.</p>
        </article>

        <article class="panel">
          <p class="eyebrow">environment variables</p>
          <h3>Plaintext stays out of storage</h3>
          <p>Values will be revealed only after explicit unlock and emitted to shells on request.</p>
        </article>

        <article id="ssh" class="panel">
          <p class="eyebrow">ssh keys</p>
          <h3>Key records pending</h3>
          <p>Imported key material and path references will share the same encrypted core model.</p>
        </article>

        <article id="security" class="panel">
          <p class="eyebrow">platform capabilities</p>
          <h3>macOS unlock adapter planned</h3>
          <p>Touch ID and Secure Enclave support will improve local unlock without owning ciphertext.</p>
        </article>
      </section>
    </section>
  </main>
</template>

<style scoped>
:global(*) {
  box-sizing: border-box;
}

:global(body) {
  margin: 0;
  min-width: 320px;
  min-height: 100vh;
  color: #1f2523;
  background: #f3f0e8;
  font-family: ui-serif, Georgia, "Times New Roman", serif;
}

.shell {
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  min-height: 100vh;
}

.sidebar {
  display: flex;
  flex-direction: column;
  gap: 48px;
  padding: 34px 24px;
  color: #f6f0df;
  background: #17201d;
}

.brand {
  display: flex;
  align-items: center;
  gap: 16px;
}

.brand-mark {
  display: grid;
  width: 48px;
  height: 48px;
  place-items: center;
  border: 1px solid #d6b760;
  color: #d6b760;
  font-size: 30px;
  line-height: 1;
}

.brand h1,
.topbar h2,
.panel h3,
.status-title {
  margin: 0;
  letter-spacing: 0;
}

.brand h1 {
  font-size: 32px;
  font-weight: 600;
}

.eyebrow {
  margin: 0 0 8px;
  color: #8b6f37;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

.sidebar .eyebrow {
  color: #bca663;
}

.nav-list {
  display: grid;
  gap: 8px;
}

.nav-item {
  padding: 12px 14px;
  border: 1px solid transparent;
  color: #e8dfc7;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
  text-decoration: none;
}

.nav-item--active,
.nav-item:hover {
  border-color: #d6b760;
  color: #fff7de;
  background: rgba(214, 183, 96, 0.1);
}

.workspace {
  display: grid;
  gap: 24px;
  align-content: start;
  padding: 38px;
}

.topbar {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: 24px;
}

.topbar h2 {
  max-width: 740px;
  font-size: clamp(34px, 5vw, 64px);
  line-height: 0.95;
  font-weight: 500;
}

.icon-button {
  display: grid;
  width: 42px;
  height: 42px;
  flex: 0 0 auto;
  place-items: center;
  border: 1px solid #1f2523;
  border-radius: 50%;
  color: #1f2523;
  background: transparent;
  font-size: 20px;
  cursor: pointer;
}

.icon-button:hover {
  color: #f3f0e8;
  background: #1f2523;
}

.status-band {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 28px;
  border: 1px solid #cabf9f;
  background: #fffaf0;
}

.status-title {
  font-size: 34px;
  line-height: 1;
}

.status-copy,
.panel p {
  max-width: 620px;
  margin: 12px 0 0;
  color: #59625e;
  font-family: ui-sans-serif, system-ui, sans-serif;
  line-height: 1.55;
}

.status-pill {
  flex: 0 0 auto;
  padding: 10px 14px;
  border: 1px solid currentColor;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
}

.status-pill--missing {
  color: #9b5d19;
  background: #fff1d6;
}

.status-pill--locked {
  color: #9b2d20;
  background: #ffe2dc;
}

.status-pill--unlocked {
  color: #236c47;
  background: #dff3df;
}

.error-text {
  color: #9b2d20;
}

.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.panel {
  min-height: 190px;
  padding: 24px;
  border: 1px solid #cabf9f;
  background: rgba(255, 250, 240, 0.72);
}

.panel h3 {
  font-size: 24px;
  font-weight: 500;
}

@media (max-width: 820px) {
  .shell {
    grid-template-columns: 1fr;
  }

  .sidebar {
    gap: 22px;
    padding: 24px;
  }

  .nav-list {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .workspace {
    padding: 24px;
  }

  .status-band,
  .topbar {
    align-items: stretch;
    flex-direction: column;
  }

  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
