// @vitest-environment happy-dom

import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ConfirmDialog from "./ConfirmDialog.vue";
import PaginationControls from "./PaginationControls.vue";
import SeverityBadge from "./SeverityBadge.vue";

describe("shared UI components", () => {
  it("emits accessible confirmation decisions", async () => {
    const wrapper = mount(ConfirmDialog, {
      props: {
        open: true,
        title: "Clear results",
        message: "Review decisions remain.",
        confirmLabel: "Clear",
        danger: true,
      },
    });
    expect(wrapper.get('[role="alertdialog"]').attributes("aria-modal")).toBe(
      "true",
    );
    await wrapper.get("button.danger").trigger("click");
    expect(wrapper.emitted("confirm")).toHaveLength(1);
    await wrapper.get("button.ghost").trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(1);
    await wrapper.get(".hunter-dialog-backdrop").trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(2);
  });

  it("emits bounded page changes", async () => {
    const wrapper = mount(PaginationControls, {
      props: { offset: 50, limit: 50, total: 120 },
    });
    const buttons = wrapper.findAll("button");
    await buttons[0]!.trigger("click");
    await buttons[1]!.trigger("click");
    expect(wrapper.emitted("change")).toEqual([[0], [100]]);
    expect(wrapper.text()).toContain("51–100 of 120");
  });

  it("renders a severity-specific badge", () => {
    const wrapper = mount(SeverityBadge, { props: { severity: "CRITICAL" } });
    expect(wrapper.classes()).toContain("severity-CRITICAL");
    expect(wrapper.text()).toBe("CRITICAL");
  });
});
