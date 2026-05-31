<script setup lang="ts">
import { computed, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";

const password = ref("");
const confirm = ref("");
const loading = ref(false);
const error = ref<string | null>(null);

const { t } = useI18n();

const canSubmit = computed(() => password.value.length > 0 && password.value === confirm.value);
const errorMessage = computed(() => (error.value ? t(error.value) : null));

const emit = defineEmits<{
  "vault-created": [];
}>();

async function handleSubmit() {
  loading.value = true;
  error.value = null;

  try {
    await invoke("create_vault", { password: password.value });
    password.value = "";
    confirm.value = "";
    emit("vault-created");
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    error.value = mapErrorToI18nKey(errMessage);
    password.value = "";
    confirm.value = "";
    loading.value = false;
  }
}

function mapErrorToI18nKey(errorMessage: string): string {
  if (errorMessage.includes("vault already exists")) return "create.errors.alreadyExists";
  if (
    errorMessage.includes("password must not be empty") ||
    errorMessage.includes("too weak")
  )
    return "create.errors.weak";
  return "create.errors.unknown";
}
</script>

<template>
  <section class="create-band">
    <div>
      <p class="eyebrow">{{ t("create.eyebrow") }}</p>
      <p class="create-title">{{ t("create.title") }}</p>
      <p class="create-description">{{ t("create.description") }}</p>

      <form @submit.prevent="handleSubmit" class="create-form">
        <div class="form-field">
          <label for="password" class="form-label">{{ t("create.passwordLabel") }}</label>
          <input
            id="password"
            v-model="password"
            type="password"
            class="form-input"
            :disabled="loading"
            autocomplete="off"
          />
        </div>

        <div class="form-field">
          <label for="confirm" class="form-label">{{ t("create.confirmLabel") }}</label>
          <input
            id="confirm"
            v-model="confirm"
            type="password"
            class="form-input"
            :disabled="loading"
            autocomplete="off"
          />
        </div>

        <p v-if="errorMessage" class="error-text">{{ errorMessage }}</p>

        <button type="submit" class="btn-primary" :disabled="!canSubmit || loading">
          {{ loading ? t("create.creating") : t("create.submit") }}
        </button>
      </form>
    </div>
  </section>
</template>

<style scoped>
.create-band {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 28px;
  border: 1px solid #cabf9f;
  background: #fffaf0;
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

.create-title {
  margin: 0;
  font-size: 34px;
  font-weight: 500;
  line-height: 1;
  color: #1f2523;
}

.create-description {
  max-width: 620px;
  margin: 12px 0 24px;
  color: #59625e;
  font-family: ui-sans-serif, system-ui, sans-serif;
  line-height: 1.55;
}

.create-form {
  display: grid;
  gap: 16px;
  max-width: 340px;
}

.form-field {
  display: grid;
  gap: 6px;
}

.form-label {
  color: #8b6f37;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}

.form-input {
  padding: 9px 12px;
  border: 1px solid #cabf9f;
  color: #1f2523;
  background: #f3f0e8;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 14px;
}

.form-input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.form-input:focus {
  outline: none;
  border-color: #d6b760;
  background: #fffaf0;
  box-shadow: 0 0 0 2px rgba(214, 183, 96, 0.2);
}

.btn-primary {
  padding: 10px 16px;
  border: 1px solid #d6b760;
  color: #1f2523;
  background: #d6b760;
  font-family: ui-sans-serif, system-ui, sans-serif;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-primary:hover:not(:disabled) {
  color: #fff7de;
  background: #9b8946;
  border-color: #9b8946;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error-text {
  color: #9b2d20;
  font-size: 14px;
  margin: 0;
}

@media (max-width: 820px) {
  .create-band {
    align-items: stretch;
    flex-direction: column;
  }

  .create-form {
    max-width: none;
  }
}
</style>
