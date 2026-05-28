import { mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { nextTick } from "vue";
import App from "./App.vue";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

describe("App", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("renders status label and tone for each vault state", async () => {
    const states = [
      { value: "missing", label: "Missing" },
      { value: "locked", label: "Locked" },
      { value: "unlocked", label: "Unlocked" },
    ] as const;

    for (const state of states) {
      invokeMock.mockResolvedValueOnce(state.value);
      const wrapper = mount(App);
      await flushPromises();

      expect(invokeMock).toHaveBeenCalledWith("get_vault_status");
      expect(wrapper.find(".status-title").text()).toBe(state.label);
      expect(wrapper.find(".status-pill").text()).toBe(state.value);
      expect(wrapper.find(`.status-pill--${state.value}`).exists()).toBe(true);

      wrapper.unmount();
      invokeMock.mockReset();
    }
  });

  it("shows invoke errors in the error area", async () => {
    invokeMock.mockRejectedValueOnce(new Error("backend unavailable"));
    const wrapper = mount(App);
    await flushPromises();

    expect(wrapper.find(".error-text").text()).toContain("backend unavailable");
  });

  it("refresh button triggers another invoke call", async () => {
    invokeMock.mockResolvedValue("missing");
    const wrapper = mount(App);
    await flushPromises();

    expect(invokeMock).toHaveBeenCalledTimes(1);
    await wrapper.find('button[aria-label="Refresh vault status"]').trigger("click");
    await flushPromises();
    expect(invokeMock).toHaveBeenCalledTimes(2);
  });
});

async function flushPromises() {
  await Promise.resolve();
  await nextTick();
}
