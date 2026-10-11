import { beforeEach, expect, it, vi } from "vitest";

import { createReturnTo } from "./createReturnTo";

vi.mock("esm-env", () => ({ BROWSER: true }));

beforeEach(() => {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  });
  vi.stubGlobal("window", { addEventListener: vi.fn() });
});

it.each([
  "https://app.test/devices?view=local#details",
  "tauri://localhost/devices?view=local#details",
])("returns to an application path for %s", async (url) => {
  const goto = vi.fn(async (_path: string) => {});
  const returnTo = createReturnTo({ id: url, goto, defaultPath: "/" });

  returnTo.setURL(new URL(url));
  await returnTo.onReturn();

  expect(goto).toHaveBeenCalledWith("/devices?view=local#details");
});

it("accepts an application path from a native location", async () => {
  vi.stubGlobal("location", new URL("tauri://localhost/signin"));
  const goto = vi.fn(async (_path: string) => {});
  const returnTo = createReturnTo({ id: "native-path", goto });

  returnTo.setPath("/devices?view=local#details");
  await returnTo.onReturn();

  expect(goto).toHaveBeenCalledWith("/devices?view=local#details");
});

it.each([
  "i://localhost/devices",
  "https://other.test/devices",
  "//other.test/devices",
  "/\\other.test/devices",
])("discards a persisted non-application return target %s", async (path) => {
  localStorage.setItem("return-to:invalid-target", JSON.stringify(path));
  const goto = vi.fn(async (_path: string) => {});
  const returnTo = createReturnTo({
    id: "invalid-target",
    goto,
    defaultPath: "/",
  });

  await returnTo.onReturn();
  await returnTo.onReturn();

  expect(goto.mock.calls).toEqual([["/"], ["/"]]);
});
