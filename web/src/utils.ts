import type { Credentials, DNSInput, NetworkInput } from "./types";

export const timestamp = (value?: string) =>
  value
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "尚无记录";
export function compact(value: number): string {
  return Intl.NumberFormat("zh-CN", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}
export function credentials(
  values: Record<string, unknown>,
  keys: string[],
): Credentials | undefined {
  const result: Credentials = {};
  keys.forEach((key) => {
    if (typeof values[key] === "string" && values[key] !== "")
      result[key] = values[key] as string;
  });
  return Object.keys(result).length ? result : undefined;
}
export function networkInput(values: Record<string, unknown>): NetworkInput {
  const kind = values.kind === "headscale" ? "headscale" : "tailscale";
  return {
    name: String(values.name).trim(),
    kind,
    note: typeof values.note === "string" ? values.note.trim() : "",
    ...(kind === "tailscale"
      ? { tailnet: String(values.tailnet).trim(), url: "" }
      : { url: String(values.url).trim(), tailnet: "" }),
    credentials: credentials(
      values,
      kind === "tailscale"
        ? ["client_id", "client_secret"]
        : ["bearer_token", "ca_pem"],
    ),
  };
}
export const DNS_KEYS = {
  cloudflare: ["api_token"],
  alidns: ["access_key_id", "access_key_secret"],
  dnspod: ["secret_id", "secret_key"],
};
export function dnsInput(values: Record<string, unknown>): DNSInput {
  const provider = values.provider as DNSInput["provider"];
  return {
    name: String(values.name).trim(),
    provider,
    zone: String(values.zone).trim(),
    suffix: String(values.suffix).trim(),
    credentials: credentials(values, DNS_KEYS[provider]),
  };
}
export function exportMap(text: string, kind: string, format: string): string {
  if (kind === "tailscale" && format === "json")
    return JSON.stringify({ derpMap: JSON.parse(text) }, null, 2);
  return text;
}
export function isPinnedImage(image: string): boolean {
  return /^[a-z0-9][a-z0-9._/-]*(?::[0-9]+)?(?:\/[a-z0-9._/-]+)*@sha256:[a-f0-9]{64}$/.test(
    image,
  );
}
export function parseRecordIDs(value: string): string[] {
  const ids = [
    ...new Set(
      value
        .split(/[\s,，]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
  if (
    !ids.length ||
    ids.length > 100 ||
    ids.some((id) => !/^[a-zA-Z0-9._:-]{1,128}$/.test(id))
  )
    throw new Error("请填写 1–100 个有效 DNS 记录 ID，使用换行或逗号分隔。");
  return ids;
}
export function generatedNodeHostname(
  name: string | undefined,
  suffix: string | undefined,
): string {
  if (!name || !suffix) return "";
  const label = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
  return label ? `${label}.${suffix}` : "";
}
