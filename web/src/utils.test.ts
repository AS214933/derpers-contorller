import { describe, expect, it } from "vitest";
import {
  dnsInput,
  exportMap,
  isPinnedImage,
  networkInput,
  parseRecordIDs,
  generatedNodeHostname,
} from "./utils";
import { parseMetrics, safeMonitoringURL } from "./metrics";

describe("credential write boundaries", () => {
  it("preserves omitted secret values and excludes read-only fields", () => {
    const result = networkInput({
      name: " Production ",
      kind: "tailscale",
      tailnet: "example.com",
      client_id: "",
      client_secret: "",
      status: "approved",
      revision: 100,
    });
    expect(result.credentials).toBeUndefined();
    expect(result).not.toHaveProperty("status");
    expect(result).not.toHaveProperty("revision");
    expect(result.name).toBe("Production");
  });
  it("does not send stale secrets from the other connector form", () => {
    const result = networkInput({
      name: "HS",
      kind: "headscale",
      url: "https://hs.example.com/verify",
      client_id: "obsolete",
      client_secret: "obsolete",
      bearer_token: "selected",
      ca_pem: "",
    });
    expect(result.credentials).toEqual({ bearer_token: "selected" });
    expect(result.tailnet).toBe("");
  });
  it("sends only the selected DNS provider credentials", () => {
    expect(
      dnsInput({
        name: "DNS",
        provider: "dnspod",
        zone: "example.com",
        suffix: "derp.example.com",
        api_token: "old",
        secret_id: "id",
        secret_key: "secret",
      }).credentials,
    ).toEqual({ secret_id: "id", secret_key: "secret" });
  });
});
describe("deployment and map exports", () => {
  it("derives a valid default node hostname once name and DNS suffix are available", () => {
    expect(generatedNodeHostname(undefined, "derp.example.com")).toBe("");
    expect(generatedNodeHostname("hk-01", undefined)).toBe("");
    expect(generatedNodeHostname("HK-01", "derp.example.com")).toBe(
      "hk-01.derp.example.com",
    );
    expect(generatedNodeHostname("US West 01", "derp.example.com")).toBe(
      "us-west-01.derp.example.com",
    );
    expect(generatedNodeHostname("---", "derp.example.com")).toBe("");
  });
  it("requires explicit DNS record IDs and deduplicates pasted lists", () => {
    expect(parseRecordIDs("123\n456,123，789")).toEqual(["123", "456", "789"]);
    expect(() => parseRecordIDs("")).toThrow();
    expect(() => parseRecordIDs("https://unexpected.example")).toThrow();
    expect(() =>
      parseRecordIDs(
        Array.from({ length: 101 }, (_, i) => String(i)).join("\n"),
      ),
    ).toThrow();
  });
  it("wraps a Tailnet map in the correct policy key without altering omission policy", () => {
    const map = {
      OmitDefaultRegions: false,
      Regions: { "900": { RegionID: 900 } },
    };
    expect(
      JSON.parse(exportMap(JSON.stringify(map), "tailscale", "json")),
    ).toEqual({ derpMap: map });
    expect(exportMap("regions: {}", "headscale", "yaml")).toBe("regions: {}");
  });
  it("requires a full immutable image digest", () => {
    expect(
      isPinnedImage(
        `ghcr.io/as214933/derpers-contorller-derper@sha256:${"a".repeat(64)}`,
      ),
    ).toBe(true);
    expect(
      isPinnedImage("ghcr.io/as214933/derpers-contorller-derper:latest"),
    ).toBe(false);
    expect(isPinnedImage(`evil/image@sha256:${"g".repeat(64)}`)).toBe(false);
  });
});
describe("live monitoring output", () => {
  it("reads samples with HELP, labels, escaped quotes and histograms", () => {
    const samples = parseMetrics(
      '# HELP relay_total Admissions\n# TYPE relay_total counter\nrelay_total{result="allowed",note="a\\\"b"} 7\n# HELP latency_seconds Delay\n# TYPE latency_seconds histogram\nlatency_seconds_count 2\nlatency_seconds_sum 0.05\nlatency_seconds_bucket{le="+Inf"} 2\nunbounded NaN\n# comment',
    );
    expect(samples).toHaveLength(4);
    expect(samples[0]).toMatchObject({
      name: "relay_total",
      value: 7,
      type: "counter",
      help: "Admissions",
    });
    expect(samples[1]).toMatchObject({
      name: "latency_seconds_count",
      value: 2,
      type: "histogram",
      help: "Delay",
    });
    expect(samples[3].labels).toBe('{le="+Inf"}');
  });
  it("rejects unsafe dashboard URLs", () => {
    expect(safeMonitoringURL("javascript:alert(1)")).toBeUndefined();
    expect(safeMonitoringURL("//attacker.example")).toBeUndefined();
    expect(safeMonitoringURL("https://user:pass@example.com")).toBeUndefined();
    expect(safeMonitoringURL("/grafana/")).toBe("/grafana/");
    expect(safeMonitoringURL("https://monitor.example.com")).toBe(
      "https://monitor.example.com/",
    );
  });
});
