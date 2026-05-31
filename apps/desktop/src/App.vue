<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { persistLocale, SUPPORTED_LOCALES, type SupportedLocale } from "./i18n";
import VaultCreateForm from "./VaultCreateForm.vue";

type VaultStatus = "missing" | "locked" | "unlocked" | "corrupted";
type VaultStatusView = VaultStatus | "unknown";

const vaultStatus = ref<VaultStatusView>("unknown");
const rawStatusError = ref("");

const { locale, t } = useI18n();

const statusLabel = computed(() => t(`status.${vaultStatus.value}`));
const statusTone = computed(() => `status-pill status-pill--${vaultStatus.value}`);
const statusError = computed(() =>
  rawStatusError.value ? t("errors.refreshFailed", { message: rawStatusError.value }) : "",
);
const statusDescription = computed(() => {
  if (vaultStatus.value === "locked") {
    return t("status.locked_description");
  }
  return t("status.copy");
});

function updateLocale(nextLocale: SupportedLocale) {
  locale.value = nextLocale;
  persistLocale(nextLocale);
}

async function refreshVaultStatus() {
  rawStatusError.value = "";

  try {
    vaultStatus.value = await invoke<VaultStatus>("get_vault_status");
  } catch (error) {
    vaultStatus.value = "unknown";
    rawStatusError.value = error instanceof Error ? error.message : String(error);
  }
}

onMounted(refreshVaultStatus);
</script>

<template>
  <main class="shell">
    <aside class="sidebar" :aria-label="t('sidebar.ariaLabel')">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">k</span>
        <div>
          <p class="eyebrow">{{ t("sidebar.eyebrow") }}</p>
          <h1>kenv</h1>
        </div>
      </div>

      <nav class="nav-list">
        <a class="nav-item nav-item--active" href="#vault">{{ t("nav.vault") }}</a>
        <a class="nav-item" href="#contexts">{{ t("nav.contexts") }}</a>
        <a class="nav-item" href="#ssh">{{ t("nav.ssh") }}</a>
        <a class="nav-item" href="#security">{{ t("nav.security") }}</a>
      </nav>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <p class="eyebrow">{{ t("topbar.eyebrow") }}</p>
          <h2>{{ t("topbar.title") }}</h2>
        </div>

        <div class="topbar-actions">
          <label class="locale-picker">
            <span class="locale-label">{{ t("topbar.languageLabel") }}</span>
            <select class="locale-select" :value="locale" @change="updateLocale(($event.target as HTMLSelectElement).value as SupportedLocale)">
              <option v-for="supportedLocale in SUPPORTED_LOCALES" :key="supportedLocale" :value="supportedLocale">
                {{ supportedLocale === "zh-CN" ? "中文" : "English" }}
              </option>
            </select>
          </label>

          <button class="icon-button" type="button" :aria-label="t('topbar.refresh')" @click="refreshVaultStatus">
            ↻
          </button>
        </div>
      </header>

      <VaultCreateForm
        v-if="vaultStatus === 'missing'"
        @vault-created="refreshVaultStatus"
      />
      <template v-else>
        <section id="vault" class="status-band">
          <div>
            <p class="eyebrow">{{ t("status.eyebrow") }}</p>
            <p class="status-title">{{ statusLabel }}</p>
            <p class="status-copy">{{ statusDescription }}</p>
            <p v-if="statusError" class="error-text">{{ statusError }}</p>
          </div>
          <span :class="statusTone">{{ statusLabel }}</span>
        </section>
      </template>

      <section class="grid">
        <article id="contexts" class="panel">
          <p class="eyebrow">{{ t("panels.contexts.eyebrow") }}</p>
          <h3>{{ t("panels.contexts.title") }}</h3>
          <p>{{ t("panels.contexts.copy") }}</p>
        </article>

        <article class="panel">
          <p class="eyebrow">{{ t("panels.env.eyebrow") }}</p>
          <h3>{{ t("panels.env.title") }}</h3>
          <p>{{ t("panels.env.copy") }}</p>
        </article>

        <article id="ssh" class="panel">
          <p class="eyebrow">{{ t("panels.ssh.eyebrow") }}</p>
          <h3>{{ t("panels.ssh.title") }}</h3>
          <p>{{ t("panels.ssh.copy") }}</p>
        </article>

        <article id="security" class="panel">
          <p class="eyebrow">{{ t("panels.security.eyebrow") }}</p>
          <h3>{{ t("panels.security.title") }}</h3>
          <p>{{ t("panels.security.copy") }}</p>
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

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.locale-picker {
  display: grid;
  gap: 6px;
}

.locale-label {
  color: #8b6f37;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}

.locale-select {
  min-width: 110px;
  padding: 9px 12px;
  border: 1px solid #cabf9f;
  color: #1f2523;
  background: #fffaf0;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 14px;
}

.icon-button {
  display: grid;
  width: 42px;
  height: 42px;
  flex: 0 0 auto;
  place-items: center;
  align-self: end;
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

.status-pill--unknown {
  color: #5f4b8b;
  background: #ece4ff;
}

.status-pill--corrupted {
  color: #b85c0f;
  background: #fed7a8;
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

  .topbar-actions {
    justify-content: space-between;
  }

  .icon-button {
    align-self: auto;
  }

  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
