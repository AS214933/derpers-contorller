import { useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CloudDownloadOutlined,
  CloudServerOutlined,
  DeleteOutlined,
  EditOutlined,
  ExportOutlined,
  FileTextOutlined,
  KeyOutlined,
  PlusOutlined,
  PoweroffOutlined,
  ReloadOutlined,
  RocketOutlined,
  SearchOutlined,
  UploadOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { DERPNode, DNSAccount, Task, User } from "../types";
import { mutate, request } from "../api";
import { useResource } from "../hooks";
import {
  CodeBlock,
  Detail,
  NoData,
  PageTitle,
  Refresh,
  ResourceError,
  StateTag,
  useActions,
} from "../components";
import {
  generatedNodeHostname,
  isPinnedImage,
  parseRecordIDs,
  timestamp,
} from "../utils";
import { ManagementTag, ProcessTags, RelayTag } from "../NodeHealth";
import { MapExport } from "./Networks";

const nodeFields = [
  "name",
  "region_id",
  "region_code",
  "region_name",
  "hostname",
  "ipv4",
  "ipv6",
  "https_port",
  "stun_port",
  "stun_enabled",
  "http_enabled",
  "dns_account_id",
  "enabled",
  "derper_image",
  "caddy_image",
] as const;
const blankNode = {
  https_port: 443,
  stun_port: 3478,
  stun_enabled: true,
  http_enabled: true,
  enabled: true,
  region_id: 900,
};
const componentOptions = [
  { value: "derper", label: "DERP 中继" },
  { value: "caddy", label: "Caddy 验证代理" },
];
function nodeInput(values: Record<string, unknown>) {
  return Object.fromEntries(
    nodeFields
      .filter((key) => values[key] !== undefined)
      .map((key) => [
        key,
        typeof values[key] === "string"
          ? (values[key] as string).trim()
          : values[key],
      ]),
  );
}

export function Nodes({ user }: { user: User }) {
  const resource = useResource<DERPNode[]>("/api/v1/nodes", 15000);
  const dns = useResource<DNSAccount[]>(
    user.admin ? "/api/v1/dns-accounts" : null,
  );
  const { run, busy, confirm } = useActions();
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<DERPNode | null | undefined>();
  const [detailID, setDetailID] = useState<string>();
  const [token, setToken] = useState<{ token: string; node_id: string }>();
  const [deployment, setDeployment] = useState<{
    name: string;
    text: string;
  }>();
  const [upgrade, setUpgrade] = useState<DERPNode>();
  const [importDNS, setImportDNS] = useState<DERPNode>();
  const [exportOpen, setExportOpen] = useState(false);
  const [form] = Form.useForm();
  const [upgradeForm] = Form.useForm();
  const [importForm] = Form.useForm();
  const manualHostname = useRef(false);
  const nodeName = Form.useWatch("name", form);
  const dnsAccountID = Form.useWatch("dns_account_id", form);
  const stunEnabled = Form.useWatch("stun_enabled", form);
  const detail = resource.data?.find((n) => n.id === detailID);
  const data = useMemo(
    () =>
      (resource.data || []).filter((n) =>
        `${n.name} ${n.hostname} ${n.region_code} ${n.region_name}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ),
    [resource.data, search],
  );
  const tasks = useResource<Task[]>(
    user.admin && detailID ? `/api/v1/nodes/${detailID}/tasks` : null,
    5000,
  );
  useEffect(() => {
    if (editing !== undefined) {
      manualHostname.current = Boolean(editing);
      form.resetFields();
      const regionID =
        Math.max(899, ...(resource.data || []).map((n) => n.region_id)) + 1;
      form.setFieldsValue(
        editing || { ...blankNode, region_id: Math.min(999, regionID) },
      );
    }
  }, [editing, form]); // Existing form input is preserved during background refresh.
  useEffect(() => {
    if (editing !== null || manualHostname.current) return;
    const suffix = dns.data?.find(
      (account) => account.id === dnsAccountID,
    )?.suffix;
    const hostname = generatedNodeHostname(nodeName, suffix);
    if (hostname !== (form.getFieldValue("hostname") || ""))
      form.setFieldValue("hostname", hostname);
  }, [nodeName, dnsAccountID, dns.data, editing, form]);
  useEffect(() => {
    if (upgrade) {
      upgradeForm.resetFields();
      upgradeForm.setFieldsValue({
        component: "derper",
        image: upgrade.derper_image,
      });
    }
  }, [upgrade, upgradeForm]);
  function task(
    node: DERPNode,
    type: string,
    payload: Record<string, unknown>,
  ) {
    return run(
      `${type}:${node.id}`,
      () =>
        mutate<Task>(`/api/v1/nodes/${node.id}/tasks`, "POST", {
          type,
          payload,
        }),
      "任务已提交，结果会显示在节点任务列表",
      () => {
        setDetailID(node.id);
        tasks.reload();
      },
    );
  }
  function restart(node: DERPNode, component = "derper") {
    confirm(
      `重启 ${node.name} 的 ${component}？`,
      component === "derper"
        ? "此节点已有中继连接将断开，客户端随后会重新连接。"
        : "验证代理会短暂不可用，期间新连接将按默认拒绝策略处理。",
      () => task(node, "restart", { component }),
    );
  }
  function publish(node: DERPNode) {
    const verb = node.published ? "unpublish" : "publish";
    const execute = () =>
      run(
        `${verb}:${node.id}`,
        () => mutate(`/api/v1/nodes/${node.id}/${verb}`),
        node.published ? "节点已取消发布" : "节点已发布到 DERP Map",
        resource.reload,
      );
    if (node.published)
      confirm(
        "从 DERP Map 取消发布？",
        "控制平面下次获取列表时不再发现该节点，现有连接按客户端行为处理。",
        execute,
      );
    else void execute();
  }
  function provision(node: DERPNode) {
    confirm(
      "更新 DNS 并签发证书？",
      "控制器会使用关联 DNS 账户为节点创建解析并执行 ACME DNS-01 验证。完成后 Agent 应用新证书并受控重启 DERP。",
      () =>
        run(
          `provision:${node.id}`,
          () => mutate(`/api/v1/nodes/${node.id}/provision`),
          "DNS 与证书准备请求已提交",
          resource.reload,
        ),
      false,
    );
  }
  function cleanupDNS(node: DERPNode) {
    confirm(
      "清理此节点的 DNS 解析？",
      "仅删除平台拥有的 DNS 记录。节点域名将无法继续通过这些记录解析；请确认已取消发布并完成流量迁移。清理后可以修改节点域名或 DNS 账户。",
      () =>
        run(
          `dns-cleanup:${node.id}`,
          () => mutate(`/api/v1/nodes/${node.id}/dns-cleanup`, "POST", {}),
          "平台管理的 DNS 记录已清理",
          resource.reload,
        ),
    );
  }
  const columns: ColumnsType<DERPNode> = [
    {
      title: "节点 / 域名",
      width: 280,
      render: (_, node) => (
        <div className="node-cell">
          <div className="small-list-icon">
            <CloudServerOutlined />
          </div>
          <div>
            <Button
              type="link"
              className="table-name"
              onClick={() => setDetailID(node.id)}
            >
              {node.name}
            </Button>
            <div className="cell-subtitle">
              {node.hostname}:{node.https_port}
            </div>
          </div>
        </div>
      ),
    },
    {
      title: "区域",
      width: 170,
      render: (_, node) => (
        <div>
          <strong>{node.region_name || node.region_code}</strong>
          <div className="cell-subtitle">
            {node.region_code} · {node.region_id}
          </div>
        </div>
      ),
    },
    {
      title: "管理通道",
      width: 130,
      render: (_, node) => <ManagementTag node={node} compact />,
    },
    {
      title: "DERP 中继健康",
      width: 150,
      render: (_, node) => <RelayTag node={node} compact />,
    },
    {
      title: "进程状态",
      width: 180,
      render: (_, node) => <ProcessTags node={node} />,
    },
    {
      title: "中继服务",
      width: 140,
      render: (_, n) => (
        <Space direction="vertical" size={3}>
          <span>
            <Badge status={n.stun_enabled ? "success" : "default"} /> STUN{" "}
            {n.stun_enabled ? n.stun_port : "关闭"}
          </span>
          <span className="muted">
            HTTP 探测 {n.http_enabled ? "开启" : "关闭"}
          </span>
        </Space>
      ),
    },
    ...(user.admin
      ? [
          {
            title: "发布状态",
            width: 120,
            render: (_: unknown, node: DERPNode) => (
              <Tag bordered={false} color={node.published ? "blue" : "default"}>
                {node.published ? "已发布" : "未发布"}
              </Tag>
            ),
          },
          {
            title: "配置版本",
            width: 130,
            render: (_: unknown, node: DERPNode) => (
              <Tooltip
                title={`目标版本 ${node.revision}，已应用 ${node.applied_revision}`}
              >
                <span
                  className={
                    node.revision === node.applied_revision
                      ? "text-green"
                      : "text-orange"
                  }
                >
                  v{node.applied_revision} / v{node.revision}
                </span>
              </Tooltip>
            ),
          },
          {
            title: "最近心跳",
            width: 185,
            render: (_: unknown, node: DERPNode) => (
              <span className="muted">{timestamp(node.last_seen)}</span>
            ),
          },
          {
            title: "操作",
            key: "actions",
            width: 145,
            fixed: "right" as const,
            render: (_: unknown, node: DERPNode) => (
              <Space size={1}>
                <Tooltip title="编辑节点">
                  <Button
                    type="text"
                    aria-label={`编辑 ${node.name}`}
                    icon={<EditOutlined />}
                    onClick={() => setEditing(node)}
                  />
                </Tooltip>
                <Tooltip title={node.published ? "取消发布" : "发布节点"}>
                  <Button
                    type="text"
                    aria-label={
                      node.published
                        ? `取消发布 ${node.name}`
                        : `发布 ${node.name}`
                    }
                    icon={
                      node.published ? <PoweroffOutlined /> : <UploadOutlined />
                    }
                    loading={
                      busy[
                        `${node.published ? "unpublish" : "publish"}:${node.id}`
                      ]
                    }
                    onClick={() => publish(node)}
                  />
                </Tooltip>
                <Tooltip
                  title={node.published ? "先取消发布，再删除节点" : "删除节点"}
                >
                  <span>
                    <Button
                      type="text"
                      danger
                      disabled={node.published}
                      aria-label={`删除 ${node.name}`}
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        confirm(
                          `删除节点“${node.name}”？`,
                          "节点身份将失效。请在主机上另外停止部署的容器。平台不会删除节点主机上的数据目录。",
                          async () => {
                            await mutate(`/api/v1/nodes/${node.id}`, "DELETE");
                            if (detailID === node.id) setDetailID(undefined);
                            resource.reload();
                          },
                        )
                      }
                    />
                  </span>
                </Tooltip>
              </Space>
            ),
          },
        ]
      : [
          {
            title: "详情",
            width: 90,
            render: (_: unknown, node: DERPNode) => (
              <Button type="link" onClick={() => setDetailID(node.id)}>
                查看
              </Button>
            ),
          },
        ]),
  ];
  return (
    <>
      <PageTitle
        eyebrow="RELAY INFRASTRUCTURE"
        title={user.admin ? "中继节点管理" : "可用中继节点"}
        description={
          user.admin
            ? "集中部署、配置与监控 DERP 节点，维护区域和发布状态。"
            : "所有已批准网络共享这些节点，使用 DERP Map 将其添加到你的控制平面。"
        }
        actions={
          <>
            <Refresh loading={resource.loading} reload={resource.reload} />
            <Button
              icon={<ExportOutlined />}
              onClick={() => setExportOpen(true)}
            >
              导出 DERP Map
            </Button>
            {user.admin && (
              <Button
                type="primary"
                icon={<PlusOutlined />}
                onClick={() => setEditing(null)}
              >
                添加节点
              </Button>
            )}
          </>
        }
      />
      <ResourceError error={resource.error} reload={resource.reload} />
      <Card className="table-card">
        <div className="table-toolbar">
          <div>
            <strong>{user.admin ? "全部中继节点" : "已发布节点"}</strong>
            <span className="muted toolbar-count">
              {resource.data?.length ?? "—"} 个节点
            </span>
          </div>
          <Input
            className="table-search"
            prefix={<SearchOutlined />}
            placeholder="搜索节点、地域或域名"
            aria-label="搜索节点"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            allowClear
          />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={data}
          loading={resource.loading}
          scroll={{ x: user.admin ? 1780 : 1200 }}
          pagination={{ pageSize: 10, showSizeChanger: true }}
          locale={{
            emptyText: (
              <NoData
                text={
                  user.admin
                    ? "尚未添加中继节点"
                    : "暂无已发布节点，请联系管理员"
                }
                action={
                  user.admin && (
                    <Button onClick={() => setEditing(null)}>
                      创建第一个节点
                    </Button>
                  )
                }
              />
            ),
          }}
        />
      </Card>
      <div className="info-strip">
        <CloudServerOutlined />
        <span>
          HTTPS 中继由官方 derper 直接提供。Caddy 负责内部验证转发与 HTTP
          探测；STUN 不受设备准入验证保护。
        </span>
      </div>
      <Modal
        open={editing !== undefined}
        title={editing ? `编辑节点 · ${editing.name}` : "添加 DERP 节点"}
        onCancel={() => setEditing(undefined)}
        width={750}
        okText="保存节点"
        confirmLoading={busy.save}
        destroyOnHidden
        onOk={() =>
          void form
            .validateFields()
            .then((values) =>
              run(
                "save",
                () =>
                  mutate(
                    editing ? `/api/v1/nodes/${editing.id}` : "/api/v1/nodes",
                    editing ? "PUT" : "POST",
                    nodeInput(values),
                  ),
                "节点配置已保存",
                (result: unknown) => {
                  setEditing(undefined);
                  resource.reload();
                  if (
                    !editing &&
                    result &&
                    typeof result === "object" &&
                    "id" in result
                  )
                    setDetailID(String(result.id));
                },
              ),
            )
            .catch(() => undefined)
        }
      >
        <Form form={form} layout="vertical" className="modal-form">
          <Row gutter={18}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="name"
                label="节点名称"
                rules={[{ required: true, whitespace: true }, { max: 64 }]}
              >
                <Input placeholder="hk-01" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="region_name"
                label="地域名称"
                rules={[{ required: true, whitespace: true }]}
              >
                <Input placeholder="香港" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="region_code"
                label="Region Code"
                rules={[
                  { required: true },
                  {
                    pattern: /^[a-z0-9-]+$/,
                    message: "使用小写字母、数字和连字符",
                  },
                ]}
              >
                <Input placeholder="hkg" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="region_id"
                label="Region ID"
                rules={[{ required: true }]}
                extra="900–999，每个节点分配独立且稳定的 ID。"
              >
                <InputNumber
                  min={900}
                  max={999}
                  precision={0}
                  disabled={Boolean(editing)}
                  className="full-width"
                />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="dns_account_id"
            label="DNS 账户"
            extra="关联后可从节点详情执行 DNS 解析与证书签发。"
          >
            <Select
              loading={dns.loading}
              allowClear
              placeholder="选择 DNS 服务账户"
              options={dns.data?.map((a) => ({
                value: a.id,
                label: `${a.name} · ${a.suffix}`,
              }))}
            />
          </Form.Item>
          {dns.error && (
            <Alert
              className="form-alert"
              type="error"
              message={dns.error}
              action={
                <Button size="small" onClick={dns.reload}>
                  重试
                </Button>
              }
            />
          )}
          <Form.Item
            name="hostname"
            label="节点域名"
            rules={[
              { required: true },
              {
                pattern:
                  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/,
                message: "填写完整域名，不包含协议与端口",
              },
            ]}
          >
            <Input
              placeholder="hk-01.derp.example.com"
              onChange={(event) => {
                manualHostname.current = Boolean(event.target.value);
              }}
            />
          </Form.Item>
          <Row gutter={18}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="ipv4"
                label="公网 IPv4"
                rules={[
                  {
                    validator: (_, value) =>
                      !value ||
                      (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) &&
                        value.split(".").every((n: string) => Number(n) <= 255))
                        ? Promise.resolve()
                        : Promise.reject(new Error("请输入有效 IPv4 地址")),
                  },
                ]}
              >
                <Input placeholder="203.0.113.10" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="ipv6"
                label="公网 IPv6（可选）"
                rules={[
                  {
                    validator: (_, value) =>
                      !value ||
                      (/^[a-fA-F0-9:]+$/.test(value) && value.includes(":"))
                        ? Promise.resolve()
                        : Promise.reject(new Error("请输入有效 IPv6 地址")),
                  },
                ]}
              >
                <Input placeholder="2001:db8::10" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={18}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="https_port"
                label="HTTPS 中继端口"
                rules={[{ required: true }]}
              >
                <InputNumber
                  min={1}
                  max={65535}
                  precision={0}
                  className="full-width"
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="stun_port"
                label="STUN UDP 端口"
                rules={[{ required: stunEnabled }]}
              >
                <InputNumber
                  min={1}
                  max={65535}
                  precision={0}
                  disabled={!stunEnabled}
                  className="full-width"
                />
              </Form.Item>
            </Col>
          </Row>
          <Space wrap size={26}>
            {editing && (
              <Form.Item
                name="enabled"
                label="启用节点"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            )}
            <Form.Item
              name="stun_enabled"
              label="公开 STUN"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="http_enabled"
              label="HTTP 80 探测"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          </Space>
          {editing && (
            <>
              <Form.Item
                name="derper_image"
                label="DERP 镜像"
                extra="镜像通过节点详情的升级任务修改，要求固定摘要并执行健康检查与失败回滚。"
              >
                <Input className="monospace" disabled />
              </Form.Item>
              <Form.Item name="caddy_image" label="Caddy 镜像">
                <Input className="monospace" disabled />
              </Form.Item>
            </>
          )}
          <Alert
            type="info"
            showIcon
            message="保存后部署节点"
            description="新节点默认启用但尚未发布。准备 DNS 与证书 → 生成一次性注册令牌 → 下载 Compose → 在节点主机启动 → 检查状态后发布到 DERP Map。配置变化由 Agent 拉取并应用。"
          />
        </Form>
      </Modal>
      <Drawer
        width={780}
        title="节点详情"
        open={Boolean(detailID)}
        onClose={() => setDetailID(undefined)}
      >
        {detail ? (
          <>
            <div className="drawer-hero">
              <div className="list-icon">
                <CloudServerOutlined />
              </div>
              <h2>{detail.name}</h2>
              <Space>
                <ManagementTag node={detail} />
                <RelayTag node={detail} />
                <Tag
                  color={detail.published ? "blue" : "default"}
                  bordered={false}
                >
                  {detail.published ? "已发布到 DERP Map" : "未发布"}
                </Tag>
              </Space>
              <div style={{ marginTop: 10 }}>
                <ProcessTags node={detail} />
              </div>
              <p>
                {detail.hostname}:{detail.https_port}{" "}
                <span className="dot-separator">·</span> {detail.region_name}
              </p>
            </div>
            <Tabs
              items={[
                {
                  key: "overview",
                  label: "节点概况",
                  children: (
                    <>
                      <Descriptions
                        bordered
                        column={1}
                        size="small"
                        items={[
                          {
                            key: "domain",
                            label: "节点域名",
                            children: (
                              <Typography.Text copyable>
                                {detail.hostname}
                              </Typography.Text>
                            ),
                          },
                          {
                            key: "region",
                            label: "区域",
                            children: `${detail.region_name} · ${detail.region_code} (${detail.region_id})`,
                          },
                          {
                            key: "ip",
                            label: "公网地址",
                            children:
                              [detail.ipv4, detail.ipv6]
                                .filter(Boolean)
                                .join(" / ") || "由 DNS 解析",
                          },
                          {
                            key: "https",
                            label: "HTTPS 端口",
                            children: detail.https_port,
                          },
                          {
                            key: "stun",
                            label: "STUN",
                            children: detail.stun_enabled
                              ? `UDP ${detail.stun_port}`
                              : "已关闭",
                          },
                          {
                            key: "http",
                            label: "HTTP 探测",
                            children: detail.http_enabled ? "TCP 80" : "已关闭",
                          },
                          ...(user.admin
                            ? [
                                {
                                  key: "id",
                                  label: "节点 ID",
                                  children: (
                                    <Typography.Text copyable>
                                      {detail.id}
                                    </Typography.Text>
                                  ),
                                },
                                {
                                  key: "config",
                                  label: "配置版本",
                                  children: (
                                    <span>
                                      已应用 v{detail.applied_revision} / 目标 v
                                      {detail.revision}
                                    </span>
                                  ),
                                },
                                {
                                  key: "heartbeat",
                                  label: "最近心跳",
                                  children: timestamp(detail.last_seen),
                                },
                              ]
                            : []),
                        ]}
                      />
                      {user.admin && (
                        <>
                          <div className="section-label">部署与运维</div>
                          <div className="node-action-grid">
                            <Button
                              icon={<GlobalIcon />}
                              disabled={!detail.dns_account_id}
                              loading={busy[`provision:${detail.id}`]}
                              onClick={() => provision(detail)}
                            >
                              准备 DNS / 证书
                            </Button>
                            <Button
                              icon={<KeyOutlined />}
                              loading={busy[`token:${detail.id}`]}
                              onClick={() =>
                                confirm(
                                  "生成一次性注册令牌？",
                                  "令牌有效期 10 分钟，使用成功后立即失效，只在本次展示。请妥善保存。",
                                  () =>
                                    run(
                                      `token:${detail.id}`,
                                      () =>
                                        mutate<{
                                          token: string;
                                          node_id: string;
                                        }>(`/api/v1/nodes/${detail.id}/token`),
                                      undefined,
                                      setToken,
                                    ),
                                  false,
                                )
                              }
                            >
                              生成注册令牌
                            </Button>
                            <Button
                              icon={<CloudDownloadOutlined />}
                              loading={busy[`deployment:${detail.id}`]}
                              onClick={() =>
                                void run(
                                  `deployment:${detail.id}`,
                                  () =>
                                    request<string>(
                                      `/api/v1/nodes/${detail.id}/deployment`,
                                    ),
                                  undefined,
                                  (text) =>
                                    setDeployment({ name: detail.name, text }),
                                )
                              }
                            >
                              下载 Compose
                            </Button>
                            <Button
                              icon={<EditOutlined />}
                              onClick={() => setEditing(detail)}
                            >
                              编辑节点
                            </Button>
                            <Button
                              icon={<ReloadOutlined />}
                              loading={busy[`restart:${detail.id}`]}
                              onClick={() => restart(detail)}
                            >
                              重启 DERP
                            </Button>
                            <Button
                              icon={<ReloadOutlined />}
                              onClick={() => restart(detail, "caddy")}
                            >
                              重启 Caddy
                            </Button>
                            <Button
                              icon={<RocketOutlined />}
                              onClick={() => setUpgrade(detail)}
                            >
                              升级组件
                            </Button>
                            <Button
                              icon={
                                detail.published ? (
                                  <PoweroffOutlined />
                                ) : (
                                  <UploadOutlined />
                                )
                              }
                              loading={
                                busy[
                                  `${detail.published ? "unpublish" : "publish"}:${detail.id}`
                                ]
                              }
                              onClick={() => publish(detail)}
                            >
                              {detail.published ? "取消发布" : "发布节点"}
                            </Button>
                          </div>
                          <div className="section-label">DNS 记录归属</div>
                          <Detail label="关联 DNS 账户">
                            {dns.data?.find(
                              (a) => a.id === detail.dns_account_id,
                            )?.name ||
                              detail.dns_account_id ||
                              "未关联"}
                          </Detail>
                          <Space wrap className="spaced-field">
                            <Button
                              disabled={!detail.dns_account_id}
                              onClick={() => {
                                importForm.resetFields();
                                setImportDNS(detail);
                              }}
                            >
                              认领已有 DNS 记录
                            </Button>
                            <Tooltip
                              title={
                                detail.published
                                  ? "先取消发布，再清理记录"
                                  : "仅清理平台拥有的记录"
                              }
                            >
                              <span>
                                <Button
                                  danger
                                  disabled={
                                    detail.published || !detail.dns_account_id
                                  }
                                  loading={busy[`dns-cleanup:${detail.id}`]}
                                  onClick={() => cleanupDNS(detail)}
                                >
                                  清理平台 DNS 记录
                                </Button>
                              </span>
                            </Tooltip>
                          </Space>
                          <div className="section-label">运行指标</div>
                          {detail.metrics &&
                          Object.keys(detail.metrics).length ? (
                            <div className="metrics-list">
                              {Object.entries(detail.metrics).map(
                                ([key, value]) => (
                                  <div key={key}>
                                    <span>{key}</span>
                                    <strong>
                                      {Number.isFinite(value)
                                        ? value.toLocaleString("zh-CN")
                                        : "—"}
                                    </strong>
                                  </div>
                                ),
                              )}
                            </div>
                          ) : (
                            <NoData text="Agent 尚未上报运行指标" />
                          )}
                          <Detail label="DERP 镜像">
                            <span className="break-all monospace">
                              {detail.derper_image}
                            </span>
                          </Detail>
                          <Detail label="Caddy 镜像">
                            <span className="break-all monospace">
                              {detail.caddy_image}
                            </span>
                          </Detail>
                        </>
                      )}
                    </>
                  ),
                },
                ...(user.admin
                  ? [
                      {
                        key: "tasks",
                        label: (
                          <Space>
                            任务与日志
                            <Tag bordered={false}>
                              {tasks.data?.length || 0}
                            </Tag>
                          </Space>
                        ),
                        children: (
                          <>
                            <div className="task-toolbar">
                              <Space>
                                <Button
                                  icon={<FileTextOutlined />}
                                  loading={busy[`logs:${detail.id}`]}
                                  onClick={() =>
                                    void task(detail, "logs", {
                                      component: "derper",
                                      tail: 200,
                                    })
                                  }
                                >
                                  获取 DERP 日志
                                </Button>
                                <Button
                                  icon={<FileTextOutlined />}
                                  onClick={() =>
                                    void task(detail, "logs", {
                                      component: "caddy",
                                      tail: 200,
                                    })
                                  }
                                >
                                  获取 Caddy 日志
                                </Button>
                              </Space>
                              <Refresh
                                loading={tasks.loading}
                                reload={tasks.reload}
                              />
                            </div>
                            <ResourceError
                              error={tasks.error}
                              reload={tasks.reload}
                            />
                            <List
                              dataSource={tasks.data || []}
                              loading={tasks.loading && !tasks.data}
                              locale={{
                                emptyText: <NoData text="暂无节点任务" />,
                              }}
                              renderItem={(item) => (
                                <List.Item className="task-item">
                                  <Card size="small" className="full-width">
                                    <div className="task-header">
                                      <Space>
                                        <strong>
                                          {(
                                            {
                                              restart: "重启组件",
                                              upgrade: "升级组件",
                                              logs: "获取日志",
                                              provision: "DNS / 证书准备",
                                            } as Record<string, string>
                                          )[item.type] || item.type}
                                        </strong>
                                        <StateTag
                                          value={item.status}
                                          label={
                                            item.status === "pending"
                                              ? "待执行"
                                              : undefined
                                          }
                                        />
                                      </Space>
                                      <span className="muted">
                                        {timestamp(item.created_at)}
                                      </span>
                                    </div>
                                    <div className="task-meta">
                                      {String(
                                        item.payload?.component || "node",
                                      )}{" "}
                                      <span className="dot-separator">·</span>{" "}
                                      {item.id}
                                    </div>
                                    {item.message && (
                                      <p
                                        className={
                                          item.status === "failed"
                                            ? "text-red"
                                            : "muted"
                                        }
                                      >
                                        {item.message}
                                      </p>
                                    )}
                                    {item.logs && (
                                      <CodeBlock
                                        text={item.logs}
                                        filename={`${detail.name}-${item.id}.log`}
                                      />
                                    )}
                                  </Card>
                                </List.Item>
                              )}
                            />
                          </>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
          </>
        ) : (
          <NoData text="节点已删除或暂时无法读取" />
        )}
      </Drawer>
      <Modal
        open={Boolean(token)}
        title="一次性节点注册令牌"
        onCancel={() => setToken(undefined)}
        footer={
          <Button onClick={() => setToken(undefined)}>已保存，关闭</Button>
        }
        width={650}
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          message="令牌只在本次显示"
          description="将其作为节点 Compose 的 ENROLLMENT_TOKEN。不要发到聊天、版本库或日志中；使用成功后令牌立即失效。"
          className="form-alert"
        />
        <CodeBlock
          text={
            token
              ? `ENROLLMENT_TOKEN=${token.token}\nNODE_ID=${token.node_id}\n`
              : ""
          }
          filename="node-enrollment.env"
        />
      </Modal>
      <Modal
        open={Boolean(deployment)}
        title={`节点部署 · ${deployment?.name || ""}`}
        onCancel={() => setDeployment(undefined)}
        width={850}
        footer={<Button onClick={() => setDeployment(undefined)}>关闭</Button>}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          message="在节点主机使用 Docker Compose 部署"
          description="保存为 compose.yaml，按文件中的说明配置 .env 和主机目录，并填写一次性注册令牌，然后执行 docker compose up -d。Agent 需要 Docker socket 管理本节点容器。"
          className="form-alert"
        />
        <CodeBlock
          text={deployment?.text || ""}
          filename={`${deployment?.name || "derp"}-compose.yaml`}
        />
      </Modal>
      <Modal
        open={Boolean(upgrade)}
        title={`升级节点组件 · ${upgrade?.name || ""}`}
        onCancel={() => setUpgrade(undefined)}
        okText="提交升级任务"
        confirmLoading={Boolean(upgrade && busy[`upgrade:${upgrade.id}`])}
        destroyOnHidden
        onOk={() =>
          void upgradeForm
            .validateFields()
            .then((values) => {
              if (upgrade)
                return task(upgrade, "upgrade", values).then((result) => {
                  if (result) setUpgrade(undefined);
                });
            })
            .catch(() => undefined)
        }
      >
        <Alert
          type="warning"
          showIcon
          message="升级会短暂重启目标组件"
          description="Agent 仅接受允许的镜像仓库。健康检查失败时回滚到原配置，并在任务列表报告结果。"
          className="form-alert"
        />
        <Form form={upgradeForm} layout="vertical">
          <Form.Item name="component" label="组件" rules={[{ required: true }]}>
            <Select
              options={componentOptions}
              onChange={(value) =>
                upgradeForm.setFieldValue(
                  "image",
                  value === "derper"
                    ? upgrade?.derper_image
                    : upgrade?.caddy_image,
                )
              }
            />
          </Form.Item>
          <Form.Item
            name="image"
            label="目标镜像摘要"
            rules={[
              { required: true },
              {
                validator: (_, value: string) =>
                  !value || isPinnedImage(value)
                    ? Promise.resolve()
                    : Promise.reject(
                        new Error("请输入完整镜像地址及 @sha256:64位摘要"),
                      ),
              },
            ]}
          >
            <Input.TextArea
              rows={3}
              className="monospace"
              placeholder="ghcr.io/as214933/derpers-contorller-derper@sha256:…"
            />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        open={Boolean(importDNS)}
        title={`认领已有 DNS 记录 · ${importDNS?.name || ""}`}
        okText="确认认领"
        confirmLoading={Boolean(
          importDNS && busy[`dns-import:${importDNS.id}`],
        )}
        onCancel={() => setImportDNS(undefined)}
        destroyOnHidden
        onOk={() =>
          void importForm
            .validateFields()
            .then((values) => {
              if (importDNS)
                return run(
                  `dns-import:${importDNS.id}`,
                  () =>
                    mutate(`/api/v1/nodes/${importDNS.id}/dns-import`, "POST", {
                      record_ids: parseRecordIDs(values.record_ids),
                    }),
                  "DNS 记录已认领",
                  () => {
                    setImportDNS(undefined);
                    resource.reload();
                  },
                );
            })
            .catch(() => undefined)
        }
      >
        <Alert
          type="warning"
          showIcon
          className="form-alert"
          message="明确授予平台记录管理权限"
          description={`仅填写 ${importDNS?.hostname || "当前节点域名"} 的 A/AAAA 记录 ID。认领后，平台可更新或删除这些记录；其他域名、CNAME 与不存在的 ID 会被拒绝。请从服务商控制台核对记录。`}
        />
        <Form form={importForm} layout="vertical">
          <Form.Item
            name="record_ids"
            label="DNS 记录 ID"
            rules={[
              { required: true },
              {
                validator: (_, value: string) => {
                  if (!value) return Promise.resolve();
                  try {
                    parseRecordIDs(value);
                    return Promise.resolve();
                  } catch {
                    return Promise.reject(
                      new Error("请输入有效记录 ID，以换行或逗号分隔"),
                    );
                  }
                },
              },
            ]}
          >
            <Input.TextArea
              rows={4}
              className="monospace"
              placeholder="每行一个记录 ID"
            />
          </Form.Item>
        </Form>
      </Modal>
      <MapExport
        network={
          exportOpen ? { kind: "headscale", name: "平台节点" } : undefined
        }
        onClose={() => setExportOpen(false)}
      />
    </>
  );
}
function GlobalIcon() {
  return <UploadOutlined />;
}
