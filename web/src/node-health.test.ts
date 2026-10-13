import { describe, expect, it } from "vitest";
import { nodeHealth } from "./node-health";

const now = Date.parse("2026-10-14T00:00:00Z");
const fresh = "2026-10-13T23:59:45Z";
const sample = { derper_probe_timestamp_seconds: now / 1000 - 15 };
describe("management channel and actual DERP probe are independent", () => {
  it("does not mark relay healthy from a fresh heartbeat or running process", () => {
    expect(
      nodeHealth(
        {
          last_seen: fresh,
          metrics: {
            ...sample,
            derper_up: 0,
            derper_process_up: 1,
            caddy_process_up: 1,
          },
        },
        now,
      ),
    ).toMatchObject({
      management: "online",
      relay: "unhealthy",
      derper: "running",
      caddy: "running",
    });
  });
  it("shows the actual probe independently from metrics collection", () => {
    expect(
      nodeHealth(
        {
          last_seen: fresh,
          metrics: {
            ...sample,
            derper_up: 1,
            derper_process_up: 1,
            derper_metrics_up: 0,
          },
        },
        now,
      ),
    ).toMatchObject({
      management: "online",
      relay: "healthy",
      metricsAvailable: false,
    });
  });
  it("expires old relay and process data without claiming the relay is down", () => {
    expect(
      nodeHealth(
        {
          last_seen: "2026-10-13T23:58:00Z",
          metrics: { ...sample, derper_up: 1, derper_process_up: 1 },
        },
        now,
      ),
    ).toMatchObject({
      management: "offline",
      relay: "stale",
      derper: "unknown",
    });
  });
  it("treats the sixty-second boundary as stale", () => {
    expect(
      nodeHealth(
        {
          last_seen: "2026-10-13T23:59:00Z",
          metrics: { ...sample, derper_up: 1 },
        },
        now,
      ).management,
    ).toBe("offline");
  });
  it("does not invent success when no probe has been reported", () => {
    expect(
      nodeHealth(
        { last_seen: fresh, metrics: { ...sample, derper_process_up: 1 } },
        now,
      ),
    ).toMatchObject({
      management: "online",
      relay: "unknown",
      derper: "running",
    });
  });
  it("expires the probe sample even while a long image pull keeps heartbeats alive", () => {
    expect(
      nodeHealth(
        {
          last_seen: fresh,
          metrics: {
            derper_probe_timestamp_seconds: now / 1000 - 65,
            derper_up: 1,
            derper_process_up: 1,
          },
        },
        now,
      ),
    ).toMatchObject({
      management: "online",
      relay: "stale",
      derper: "unknown",
    });
  });
  it("requires the explicit probe sample timestamp", () => {
    expect(
      nodeHealth(
        { last_seen: fresh, metrics: { derper_up: 1, derper_process_up: 1 } },
        now,
      ),
    ).toMatchObject({
      management: "online",
      relay: "unknown",
      derper: "unknown",
    });
  });
  it("handles enrollment and invalid status data safely", () => {
    expect(nodeHealth({ metrics: { derper_up: 1 } }, now)).toMatchObject({
      management: "awaiting_enrollment",
      relay: "unknown",
    });
    expect(
      nodeHealth({ last_seen: "invalid", metrics: { derper_up: 1 } }, now)
        .relay,
    ).toBe("unknown");
    expect(
      nodeHealth({ last_seen: fresh, metrics: { derper_up: NaN } }, now).relay,
    ).toBe("unknown");
  });
});
