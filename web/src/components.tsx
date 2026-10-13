import { useState } from "react";
import type { ReactNode } from "react";
import {
  Alert,
  App,
  Button,
  Card,
  Empty,
  Space,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  ReloadOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  ClockCircleOutlined,
  CopyOutlined,
  DownloadOutlined,
} from "@ant-design/icons";
import { copy, download, errorText } from "./api";

const labels: Record<string, string> = {
  approved: "已批准",
  pending: "待审核",
  rejected: "已拒绝",
  disabled: "已停用",
  enabled: "已启用",
  healthy: "正常",
  ok: "正常",
  online: "在线",
  ready: "就绪",
  unhealthy: "异常",
  error: "异常",
  failed: "失败",
  offline: "离线",
  unknown: "待检测",
  enrolling: "待注册",
  awaiting_enrollment: "待注册",
  provisioning: "准备中",
  degraded: "部分异常",
  completed: "已完成",
  succeeded: "已完成",
  success: "成功",
  running: "执行中",
  queued: "队列中",
  pending_apply: "待应用",
  rolled_back: "已回滚",
};
export function StateTag({
  value = "unknown",
  label,
}: {
  value?: string;
  label?: string;
}) {
  const good = [
    "approved",
    "healthy",
    "online",
    "ready",
    "ok",
    "enabled",
    "completed",
    "succeeded",
    "success",
  ].includes(value);
  const bad = [
    "rejected",
    "unhealthy",
    "error",
    "failed",
    "offline",
    "degraded",
    "rolled_back",
  ].includes(value);
  const pending = [
    "pending",
    "enrolling",
    "awaiting_enrollment",
    "provisioning",
    "running",
    "queued",
    "pending_apply",
  ].includes(value);
  return (
    <Tag
      bordered={false}
      color={good ? "success" : bad ? "error" : pending ? "warning" : "default"}
      icon={
        good ? (
          <CheckCircleFilled />
        ) : bad ? (
          <CloseCircleFilled />
        ) : pending ? (
          <ClockCircleOutlined />
        ) : undefined
      }
    >
      {label || labels[value] || value}
    </Tag>
  );
}
export function PageTitle({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <Space wrap>{actions}</Space>
    </div>
  );
}
export function ResourceError({
  error,
  reload,
}: {
  error: string;
  reload: () => void;
}) {
  return error ? (
    <Alert
      type="error"
      showIcon
      message="无法获取最新数据"
      description={error}
      action={
        <Button size="small" onClick={reload}>
          重试
        </Button>
      }
      className="resource-error"
    />
  ) : null;
}
export function Refresh({
  loading,
  reload,
}: {
  loading: boolean;
  reload: () => void;
}) {
  return (
    <Tooltip title="刷新数据">
      <Button
        aria-label="刷新数据"
        icon={<ReloadOutlined spin={loading} />}
        onClick={reload}
        disabled={loading}
      />
    </Tooltip>
  );
}
export function NoData({ text, action }: { text: string; action?: ReactNode }) {
  return (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={text}>
      {action}
    </Empty>
  );
}
export function CodeBlock({
  text,
  filename,
  loading = false,
}: {
  text: string;
  filename?: string;
  loading?: boolean;
}) {
  const { message } = App.useApp();
  return (
    <div className="code-wrap">
      <div className="code-toolbar">
        <span>{filename || "OUTPUT"}</span>
        <Space size={3}>
          <Button
            type="text"
            size="small"
            icon={<CopyOutlined />}
            disabled={!text || loading}
            onClick={() =>
              void copy(text)
                .then(() => message.success("已复制"))
                .catch((e) => message.error(errorText(e)))
            }
          >
            复制
          </Button>
          {filename && (
            <Button
              type="text"
              size="small"
              icon={<DownloadOutlined />}
              disabled={!text || loading}
              onClick={() => download(text, filename)}
            >
              下载
            </Button>
          )}
        </Space>
      </div>
      <pre>{loading ? "正在加载…" : text || "暂无输出"}</pre>
    </div>
  );
}
export function Detail({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <div>{children || "—"}</div>
    </div>
  );
}
export function StatCard({
  label,
  value,
  sub,
  icon,
  tone = "blue",
}: {
  label: string;
  value: ReactNode;
  sub: string;
  icon: ReactNode;
  tone?: string;
}) {
  return (
    <Card className="stat-card">
      <div className="stat-top">
        <span>{label}</span>
        <div className={`stat-icon ${tone}`}>{icon}</div>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-sub">{sub}</div>
    </Card>
  );
}
export function useActions() {
  const { message, modal } = App.useApp();
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  async function run<T>(
    key: string,
    fn: () => Promise<T>,
    success?: string,
    onSuccess?: (value: T) => void,
  ) {
    setBusy((s) => ({ ...s, [key]: true }));
    try {
      const result = await fn();
      if (success) void message.success(success);
      onSuccess?.(result);
      return result;
    } catch (e) {
      void message.error(errorText(e));
      return undefined;
    } finally {
      setBusy((s) => ({ ...s, [key]: false }));
    }
  }
  function confirm(
    title: string,
    content: ReactNode,
    fn: () => Promise<unknown>,
    danger = true,
  ) {
    modal.confirm({
      title,
      content,
      okText: "确认",
      cancelText: "取消",
      okButtonProps: { danger },
      onOk: async () => {
        try {
          await fn();
        } catch (e) {
          void message.error(errorText(e));
          throw e;
        }
      },
    });
  }
  return { busy, run, confirm, message };
}
export function SecretHint({ editing }: { editing: boolean }) {
  return (
    <Typography.Text type="secondary" className="form-hint">
      {editing
        ? "已保存的凭据不会返回浏览器。留空保留当前凭据，填写后替换对应字段。"
        : "凭据加密保存在控制器，仅用于验证和同步。"}
    </Typography.Text>
  );
}
