import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, mutate, request } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("same-origin controller API", () => {
  it("uses browser session credentials and JSON for writes", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response('{"id":"saved"}', {
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      mutate("/api/v1/networks", "POST", { name: "production" }),
    ).resolves.toEqual({ id: "saved" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/networks",
      expect.objectContaining({
        credentials: "same-origin",
        method: "POST",
        body: '{"name":"production"}',
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }),
    );
  });
  it("handles no-content deletes and raw YAML without trying to parse JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 204 }))
        .mockResolvedValueOnce(
          new Response("services: {}", {
            headers: { "content-type": "application/yaml" },
          }),
        ),
    );
    await expect(
      mutate("/api/v1/networks/id", "DELETE"),
    ).resolves.toBeUndefined();
    await expect(request("/api/v1/nodes/id/deployment")).resolves.toBe(
      "services: {}",
    );
  });
  it("propagates server-safe validation messages", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"error":"unpublish node before deleting"}', {
            status: 409,
          }),
        ),
    );
    await expect(mutate("/api/v1/nodes/id", "DELETE")).rejects.toMatchObject({
      message: "unpublish node before deleting",
      status: 409,
    });
  });
  it("expires the session on authenticated API 401, without reloading the page", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response('{"error":"login required"}', { status: 401 }),
        ),
    );
    await expect(request("/api/v1/nodes")).rejects.toBeInstanceOf(ApiError);
    expect(dispatchEvent).toHaveBeenCalledWith(
      expect.objectContaining({ type: "session-expired" }),
    );
  });
  it("treats anonymous /me as normal login state and falls back on non-JSON errors", async () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal("window", { dispatchEvent });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>unavailable</html>", { status: 401 }),
        ),
    );
    await expect(request("/api/v1/me")).rejects.toMatchObject({
      message: "请求失败（HTTP 401）",
    });
    expect(dispatchEvent).not.toHaveBeenCalled();
  });
});
