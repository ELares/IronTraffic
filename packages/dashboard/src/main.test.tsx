import { render as preactRender } from "preact";
import { describe, expect, test } from "vitest";
import { Shell, mount } from "./main";

describe("main", () => {
  test("shell_renders_the_build_id", () => {
    const container = document.createElement("div");
    preactRender(<Shell buildId="dev" />, container);
    expect(container.querySelector("#build-id")!.textContent).toBe("build dev");
  });

  test("shell_escapes_a_hostile_build_id", () => {
    const container = document.createElement("div");
    const hostile = "</p><img src=x onerror=1>";
    preactRender(<Shell buildId={hostile} />, container);
    expect(container.querySelectorAll("img").length).toBe(0);
    expect(container.querySelector("#build-id")!.textContent).toBe(
      `build ${hostile}`,
    );
  });

  test("mount_reports_a_missing_root", () => {
    document.getElementById("app")?.remove();
    expect(() => mount()).not.toThrow();
    expect(document.body.textContent).toContain("#app is missing");
  });
});
