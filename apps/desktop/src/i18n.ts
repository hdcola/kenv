import { createI18n } from "vue-i18n";
import { en } from "./i18n/messages/en";
import { zhCN } from "./i18n/messages/zh-CN";

export const LOCALE_STORAGE_KEY = "kenv.locale";
export const SUPPORTED_LOCALES = ["en", "zh-CN"] as const;

export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

const messages = {
  en,
  "zh-CN": zhCN,
} as const;

export function createKenvI18n() {
  return createI18n({
    legacy: false,
    locale: getInitialLocale(),
    fallbackLocale: "en",
    messages,
  });
}

export function getInitialLocale(): SupportedLocale {
  if (typeof window !== "undefined") {
    const savedLocale = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (isSupportedLocale(savedLocale)) {
      return savedLocale;
    }
  }

  return detectLocaleFromNavigator();
}

export function persistLocale(locale: SupportedLocale) {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  }
}

function detectLocaleFromNavigator(): SupportedLocale {
  if (typeof navigator === "undefined") {
    return "en";
  }

  const candidates = [...(navigator.languages ?? []), navigator.language];

  for (const candidate of candidates) {
    const normalized = normalizeLocale(candidate);
    if (normalized) {
      return normalized;
    }
  }

  return "en";
}

function normalizeLocale(locale: string | null | undefined): SupportedLocale | null {
  if (!locale) {
    return null;
  }

  const lowered = locale.toLowerCase();
  if (lowered.startsWith("zh")) {
    return "zh-CN";
  }

  if (lowered.startsWith("en")) {
    return "en";
  }

  return null;
}

function isSupportedLocale(locale: string | null): locale is SupportedLocale {
  return locale === "en" || locale === "zh-CN";
}
