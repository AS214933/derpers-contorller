export interface MetricSample {
  name: string;
  labels: string;
  value: number;
  help: string;
  type: string;
}
export function parseMetrics(text: string): MetricSample[] {
  const help = new Map<string, string>();
  const types = new Map<string, string>();
  const result: MetricSample[] = [];
  const lines = text.split("\n");
  for (const line of lines) {
    const h = /^# HELP (\S+) (.*)$/.exec(line);
    const t = /^# TYPE (\S+) (\S+)$/.exec(line);
    if (h) help.set(h[1], h[2]);
    if (t) types.set(t[1], t[2]);
  }
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const m =
      /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?:[^"}]|"(?:\\.|[^"\\])*")*\})?\s+([^\s]+)(?:\s+\d+)?(?:\s+#.*)?$/.exec(
        line.trim(),
      );
    if (!m) continue;
    const value = Number(m[3]);
    if (!Number.isFinite(value)) continue;
    const base = m[1].replace(/_(?:bucket|sum|count)$/, "");
    result.push({
      name: m[1],
      labels: m[2] || "",
      value,
      help: help.get(m[1]) || help.get(base) || "",
      type: types.get(m[1]) || types.get(base) || "untyped",
    });
  }
  return result;
}
export function safeMonitoringURL(value?: string): string | undefined {
  if (!value) return undefined;
  if (/^\/(?!\/)/.test(value)) return value;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) &&
      !url.username &&
      !url.password
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}
