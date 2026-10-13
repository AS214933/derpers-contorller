import { Space, Tag, Tooltip } from "antd";
import type { DERPNode } from "./types";
import { nodeHealth } from "./node-health";

export function ManagementTag({
  node,
  compact = false,
}: {
  node: DERPNode;
  compact?: boolean;
}) {
  const state = nodeHealth(node).management;
  return (
    <Tooltip title="管理通道基于 Agent 最近一次心跳；60 秒无新心跳视为失联。它不代表中继可用性。">
      <Tag
        bordered={false}
        color={
          state === "online"
            ? "blue"
            : state === "offline"
              ? "error"
              : "default"
        }
      >
        {state === "online"
          ? compact
            ? "管理在线"
            : "管理通道在线"
          : state === "offline"
            ? compact
              ? "管理失联"
              : "管理通道失联"
            : "等待 Agent"}
      </Tag>
    </Tooltip>
  );
}
export function RelayTag({
  node,
  compact = false,
}: {
  node: DERPNode;
  compact?: boolean;
}) {
  const state = nodeHealth(node).relay;
  const text = {
    healthy: compact ? "中继正常" : "DERP 中继正常",
    unhealthy: compact ? "中继故障" : "DERP 探测失败",
    unknown: "中继待检测",
    stale: "中继数据过期",
  }[state];
  return (
    <Tooltip
      title={
        state === "stale"
          ? "管理心跳或 DERP 探测样本已超过 60 秒，无法确认当前中继状态。"
          : "基于 Agent 实际 HTTPS /derp/probe 结果，正常验证 TLS 域名和证书；管理心跳及探测样本都须在 60 秒内。"
      }
    >
      <Tag
        bordered={false}
        color={
          state === "healthy"
            ? "success"
            : state === "unhealthy"
              ? "error"
              : "default"
        }
      >
        {text}
      </Tag>
    </Tooltip>
  );
}
export function ProcessTags({ node }: { node: DERPNode }) {
  const health = nodeHealth(node);
  return (
    <Space size={3} wrap>
      {(
        [
          ["DERP", health.derper],
          ["Caddy", health.caddy],
        ] as const
      ).map(([name, state]) => (
        <Tooltip
          key={name}
          title="Docker 进程运行状态；进程运行并不证明中继握手、TLS 或数据通信正常。"
        >
          <Tag
            bordered={false}
            color={
              state === "running"
                ? "cyan"
                : state === "stopped"
                  ? "error"
                  : "default"
            }
          >
            {name}{" "}
            {state === "running"
              ? "运行"
              : state === "stopped"
                ? "停止"
                : "未知"}
          </Tag>
        </Tooltip>
      ))}
    </Space>
  );
}
