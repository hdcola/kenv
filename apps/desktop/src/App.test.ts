import { mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { nextTick } from "vue";
import App from "./App.vue";
import { createKenvI18n, LOCALE_STORAGE_KEY, type SupportedLocale } from "./i18n";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

describe("App", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    window.localStorage.clear();
    setNavigatorLanguages(["en-CA"]);
  });

  it("renders English by default when no saved locale exists and the environment prefers English", async () => {
    invokeMock.mockResolvedValueOnce("missing");
    const wrapper = mountApp();
    await flushPromises();

    expect(wrapper.find(".topbar h2").text()).toBe("Secure contexts, ready for the first vault.");
    expect(wrapper.find(".nav-item--active").text()).toBe("Vault");
    expect((wrapper.find(".locale-select").element as HTMLSelectElement).value).toBe("en");
  });

  it("renders Chinese by default when no saved locale exists and the environment prefers Chinese", async () => {
    setNavigatorLanguages(["zh-CN", "en-US"]);
    invokeMock.mockResolvedValueOnce("missing");
    const wrapper = mountApp();
    await flushPromises();

    expect(wrapper.find(".topbar h2").text()).toBe("安全上下文，准备好迎接第一个保险库。");
    expect(wrapper.find(".nav-item--active").text()).toBe("保险库");
    expect((wrapper.find(".locale-select").element as HTMLSelectElement).value).toBe("zh-CN");
  });

  it("prefers the saved locale over the environment locale", async () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    setNavigatorLanguages(["en-US"]);
    invokeMock.mockResolvedValueOnce("missing");
    const wrapper = mountApp();
    await flushPromises();

    expect(wrapper.find(".topbar h2").text()).toBe("安全上下文，准备好迎接第一个保险库。");
    expect((wrapper.find(".locale-select").element as HTMLSelectElement).value).toBe("zh-CN");
  });

  it("switches locale immediately and persists the selection", async () => {
    invokeMock.mockResolvedValueOnce("missing");
    const wrapper = mountApp();
    await flushPromises();

    await wrapper.find(".locale-select").setValue("zh-CN");
    await nextTick();

    expect(wrapper.find(".topbar h2").text()).toBe("安全上下文，准备好迎接第一个保险库。");
    expect(wrapper.find('button[aria-label="刷新保险库状态"]').exists()).toBe(true);
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
  });

  it("renders localized vault status labels for each state in both locales", async () => {
    const states = [
      { value: "missing", en: "Missing", zh: "缺失" },
      { value: "locked", en: "Locked", zh: "已锁定" },
      { value: "unlocked", en: "Unlocked", zh: "已解锁" },
      { value: "corrupted", en: "Corrupted", zh: "已损坏" },
    ] as const;

    for (const state of states) {
      invokeMock.mockResolvedValueOnce(state.value);
      const englishWrapper = mountApp("en");
      await flushPromises();

      expect(englishWrapper.find(".status-title").text()).toBe(state.en);
      expect(englishWrapper.find(".status-pill").text()).toBe(state.en);
      englishWrapper.unmount();

      invokeMock.mockResolvedValueOnce(state.value);
      const chineseWrapper = mountApp("zh-CN");
      await flushPromises();

      expect(chineseWrapper.find(".status-title").text()).toBe(state.zh);
      expect(chineseWrapper.find(".status-pill").text()).toBe(state.zh);
      chineseWrapper.unmount();

      invokeMock.mockReset();
    }
  });

  it("localizes the refresh button aria-label", async () => {
    invokeMock.mockResolvedValueOnce("missing");
    const wrapper = mountApp("zh-CN");
    await flushPromises();

    expect(wrapper.find('button[aria-label="刷新保险库状态"]').exists()).toBe(true);
  });

  it("shows a localized error prefix while preserving the original backend error", async () => {
    invokeMock.mockRejectedValueOnce(new Error("backend unavailable"));
    const wrapper = mountApp("zh-CN");
    await flushPromises();

    expect(wrapper.find(".error-text").text()).toContain("无法刷新保险库状态：backend unavailable");
  });

  it("resets the status to unknown when a refresh fails after a successful load", async () => {
    invokeMock.mockResolvedValueOnce("unlocked").mockRejectedValueOnce(new Error("backend unavailable"));
    const wrapper = mountApp();
    await flushPromises();

    expect(wrapper.find(".status-title").text()).toBe("Unlocked");
    expect(wrapper.find(".status-pill").text()).toBe("Unlocked");

    await wrapper.find('button[aria-label="Refresh vault status"]').trigger("click");
    await flushPromises();

    expect(wrapper.find(".status-title").text()).toBe("Unknown");
    expect(wrapper.find(".status-pill").text()).toBe("Unknown");
    expect(wrapper.find(".status-pill--unknown").exists()).toBe(true);
    expect(wrapper.find(".error-text").text()).toContain("Unable to refresh vault status: backend unavailable");
  });
});

function mountApp(savedLocale?: SupportedLocale) {
  if (savedLocale) {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, savedLocale);
  }

  return mount(App, {
    global: {
      plugins: [createKenvI18n()],
    },
  });
}

function setNavigatorLanguages(languages: string[]) {
  Object.defineProperty(window.navigator, "language", {
    configurable: true,
    value: languages[0],
  });

  Object.defineProperty(window.navigator, "languages", {
    configurable: true,
    value: languages,
  });
}

async function flushPromises() {
  await Promise.resolve();
  await nextTick();
}
