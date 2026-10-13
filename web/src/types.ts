export interface User {
  id: string;
  subject: string;
  email: string;
  name: string;
  groups: string[];
  admin: boolean;
}
export interface Network {
  id: string;
  owner_id: string;
  name: string;
  kind: "tailscale" | "headscale";
  status: string;
  health: string;
  revision: number;
  tailnet?: string;
  url?: string;
  device_count: number;
  last_success?: string;
  last_error?: string;
  note?: string;
  created_at: string;
}
export interface DERPNode {
  id: string;
  name: string;
  region_id: number;
  region_code: string;
  region_name: string;
  hostname: string;
  ipv4: string;
  ipv6: string;
  https_port: number;
  stun_port: number;
  stun_enabled: boolean;
  http_enabled: boolean;
  dns_account_id?: string;
  enabled: boolean;
  published: boolean;
  revision: number;
  applied_revision: number;
  status: string;
  last_seen?: string;
  metrics?: Record<string, number>;
  derper_image: string;
  caddy_image: string;
}
export interface DNSAccount {
  id: string;
  name: string;
  provider: "cloudflare" | "alidns" | "dnspod";
  zone: string;
  suffix: string;
  health: string;
  last_error?: string;
}
export interface Task {
  id: string;
  node_id: string;
  type: string;
  status: string;
  payload: Record<string, unknown>;
  message?: string;
  logs?: string;
  created_at: string;
}
export interface Audit {
  id: string;
  time: string;
  event: string;
  actor: string;
  node_id?: string;
  network_id?: string;
  node_public?: string;
  allow?: boolean;
  detail: string;
}
export interface Settings {
  approval_mode: "manual" | "automatic";
}
export type Credentials = Record<string, string>;
export type NetworkInput = Pick<
  Network,
  "name" | "kind" | "tailnet" | "url" | "note"
> & { credentials?: Credentials };
export type DNSInput = Pick<
  DNSAccount,
  "name" | "provider" | "zone" | "suffix"
> & { credentials?: Credentials };
