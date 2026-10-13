import type { DERPNode } from "./types";

export type ManagementState = "online" | "offline" | "awaiting_enrollment";
export type RelayState = "healthy" | "unhealthy" | "unknown" | "stale";
export type ProcessState = "running" | "stopped" | "unknown";

export function nodeHealth(
  node: Pick<DERPNode, "last_seen" | "metrics">,
  now = Date.now(),
) {
  const last = node.last_seen ? Date.parse(node.last_seen) : NaN;
  const fresh = Number.isFinite(last) && now - last < 60_000;
  const management: ManagementState = !Number.isFinite(last)
    ? "awaiting_enrollment"
    : fresh
      ? "online"
      : "offline";
  const sampled = node.metrics?.derper_probe_timestamp_seconds;
  const sampleAge = sampled === undefined ? NaN : now - sampled * 1000;
  const sampleFresh =
    Number.isFinite(sampleAge) && sampleAge < 60_000 && sampleAge >= -60_000;
  const usable = fresh && sampleFresh;
  const flag = (name: string): number | undefined => {
    if (!usable) return undefined;
    const value = node.metrics?.[name];
    return value === 0 || value === 1 ? value : undefined;
  };
  const probe = flag("derper_up");
  const relay: RelayState =
    (!fresh && Number.isFinite(last)) ||
    (Number.isFinite(sampleAge) && !sampleFresh)
      ? "stale"
      : probe === 1
        ? "healthy"
        : probe === 0
          ? "unhealthy"
          : "unknown";
  const process = (name: string): ProcessState =>
    flag(name) === 1 ? "running" : flag(name) === 0 ? "stopped" : "unknown";
  return {
    management,
    relay,
    derper: process("derper_process_up"),
    caddy: process("caddy_process_up"),
    metricsAvailable: flag("derper_metrics_up") === 1,
  };
}
