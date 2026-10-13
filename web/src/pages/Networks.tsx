import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Drawer,
  Form,
  Input,
  Modal,
  Radio,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CheckOutlined,
  CloseOutlined,
  DeleteOutlined,
  EditOutlined,
  ExportOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { Network, User } from "../types";
import { errorText, mutate, request } from "../api";
import { useResource } from "../hooks";
import {
  CodeBlock,
  Detail,
  NoData,
  PageTitle,
  Refresh,
  ResourceError,
  SecretHint,
  StateTag,
  useActions,
} from "../components";
import { exportMap, networkInput, timestamp } from "../utils";

type Filter = "all" | "pending" | "approved" | "disabled" | "rejected";
export function Networks({
  user,
  review = false,
}: {
  user: User;
  review?: boolean;
}) {
  const resource = useResource<Network[]>("/api/v1/networks", 30000);
  const { busy, run, confirm } = useActions();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>(review ? "pending" : "all");
  const [editing, setEditing] = useState<Network | null | undefined>();
  const [detailID, setDetailID] = useState<string>();
  const [exportNetwork, setExportNetwork] = useState<Network>();
  const [form] = Form.useForm();
  const kind = Form.useWatch("kind", form) || "tailscale";
  const data = useMemo(
    () =>
      (resource.data || []).filter(
        (n) =>
          (review || n.owner_id === user.id) &&
          (filter === "all" || n.status === filter) &&
          `${n.name} ${n.tailnet || ""} ${n.url || ""}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [resource.data, review, user.id, filter, search],
  );
  const detail = resource.data?.find((n) => n.id === detailID);
  useEffect(() => {
    if (editing !== undefined) {
      form.resetFields();
      form.setFieldsValue(editing || { kind: "tailscale" });
    }
  }, [editing, form]);
  const action = (network: Network, verb: string, message: string) =>
    run(
      `${verb}:${network.id}`,
      () =>
        mutate(`/api/v1/networks/${encodeURIComponent(network.id)}/${verb}`),
      message,
      resource.reload,
    );
  const remove = (n: Network) =>
    confirm(
      `删除“${n.name}”？`,
      "该来源的授权将立即失效。已建立的 DERP 连接遵循节点原有连接生命周期。",
      async () => {
        await mutate(`/api/v1/networks/${encodeURIComponent(n.id)}`, "DELETE");
        if (detailID === n.id) setDetailID(undefined);
        resource.reload();
      },
    );
  const columns: ColumnsType<Network> = [
    {
      title: "网络",
      dataIndex: "name",
      key: "name",
      width: 260,
      render: (_, n) => (
        <div>
          <Button
            type="link"
            className="table-name"
            onClick={() => setDetailID(n.id)}
          >
            {n.name}
          </Button>
          <div className="cell-subtitle">
            {n.kind === "tailscale" ? n.tailnet : n.url}
          </div>
        </div>
      ),
    },
    {
      title: "控制平面",
      dataIndex: "kind",
      width: 140,
      render: (value) => (
        <Tag bordered={false} color={value === "tailscale" ? "blue" : "purple"}>
          {value === "tailscale" ? "Tailscale" : "Headscale"}
        </Tag>
      ),
    },
    {
      title: "审批",
      dataIndex: "status",
      width: 120,
      render: (value) => <StateTag value={value} />,
    },
    {
      title: "来源健康",
      dataIndex: "health",
      width: 130,
      render: (value, n) => (
        <Tooltip title={n.last_error}>
          <StateTag value={value} />
        </Tooltip>
      ),
    },
    {
      title: "设备 / 验证",
      width: 120,
      render: (_, n) =>
        n.kind === "tailscale" ? (
          `${n.device_count} 台设备`
        ) : (
          <span className="muted">实时验证</span>
        ),
    },
    {
      title: "最近成功",
      dataIndex: "last_success",
      width: 190,
      render: (value) => <span className="muted">{timestamp(value)}</span>,
    },
    {
      title: "操作",
      key: "actions",
      width: review ? 260 : 205,
      fixed: "right",
      render: (_, n) => (
        <Space size={2}>
          {review && n.status !== "approved" && (
            <Tooltip title="批准接入">
              <Button
                type="text"
                aria-label={`批准 ${n.name}`}
                icon={<CheckOutlined />}
                loading={busy[`approve:${n.id}`]}
                onClick={() => void action(n, "approve", "已批准网络")}
              />
            </Tooltip>
          )}
          {review && n.status === "pending" && (
            <Tooltip title="拒绝申请">
              <Button
                type="text"
                danger
                aria-label={`拒绝 ${n.name}`}
                icon={<CloseOutlined />}
                loading={busy[`reject:${n.id}`]}
                onClick={() =>
                  confirm("拒绝网络申请？", n.name, async () => {
                    await mutate(`/api/v1/networks/${n.id}/reject`);
                    resource.reload();
                  })
                }
              />
            </Tooltip>
          )}
          {review && n.status === "approved" && (
            <Tooltip title="停用授权源">
              <Button
                type="text"
                danger
                aria-label={`停用 ${n.name}`}
                icon={<CloseOutlined />}
                onClick={() =>
                  confirm(
                    "停用该授权来源？",
                    "后续连接不能再通过该来源获得授权。",
                    async () => {
                      await mutate(`/api/v1/networks/${n.id}/disable`);
                      resource.reload();
                    },
                  )
                }
              />
            </Tooltip>
          )}
          <Tooltip title="编辑网络">
            <Button
              type="text"
              aria-label={`编辑 ${n.name}`}
              icon={<EditOutlined />}
              onClick={() => setEditing(n)}
            />
          </Tooltip>
          <Tooltip
            title={
              n.kind === "tailscale" && n.status === "approved"
                ? "立即同步设备"
                : "测试授权来源"
            }
          >
            <Button
              type="text"
              aria-label={`测试 ${n.name}`}
              icon={<SyncOutlined />}
              loading={
                busy[
                  `${n.kind === "tailscale" && n.status === "approved" ? "sync" : "test"}:${n.id}`
                ]
              }
              onClick={() =>
                void action(
                  n,
                  n.kind === "tailscale" && n.status === "approved"
                    ? "sync"
                    : "test",
                  n.kind === "tailscale" && n.status === "approved"
                    ? "同步请求已完成"
                    : "授权来源检查完成",
                )
              }
            />
          </Tooltip>
          <Tooltip title="导出接入配置">
            <Button
              type="text"
              aria-label={`导出 ${n.name} 配置`}
              icon={<ExportOutlined />}
              onClick={() => setExportNetwork(n)}
            />
          </Tooltip>
          <Tooltip title="删除网络">
            <Button
              type="text"
              danger
              aria-label={`删除 ${n.name}`}
              icon={<DeleteOutlined />}
              onClick={() => remove(n)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];
  return (
    <>
      <PageTitle
        eyebrow={review ? "NETWORK APPROVAL" : "YOUR NETWORKS"}
        title={review ? "网络接入审核" : "我的网络"}
        description={
          review
            ? "审核所有授权来源，分别查看审批状态与运行健康。"
            : "接入独立的 Tailnet 或 Headscale，让授权设备使用共享中继。"
        }
        actions={
          <>
            <Refresh loading={resource.loading} reload={resource.reload} />
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setEditing(null)}
            >
              添加网络
            </Button>
          </>
        }
      />
      <ResourceError error={resource.error} reload={resource.reload} />
      <Card className="table-card">
        <div className="table-toolbar">
          <Tabs
            activeKey={filter}
            onChange={(key) => setFilter(key as Filter)}
            items={[
              { key: "all", label: "全部网络" },
              { key: "pending", label: "待审核" },
              { key: "approved", label: "已批准" },
              { key: "disabled", label: "已停用" },
              { key: "rejected", label: "已拒绝" },
            ]}
          />
          <Input
            prefix={<SearchOutlined />}
            placeholder="搜索网络、Tailnet 或地址"
            aria-label="搜索网络"
            allowClear
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="table-search"
          />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={data}
          loading={resource.loading}
          scroll={{ x: 1230 }}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个网络`,
          }}
          locale={{
            emptyText: (
              <NoData
                text={filter === "all" ? "尚未添加网络" : "当前筛选下没有网络"}
                action={
                  filter === "all" && (
                    <Button type="primary" onClick={() => setEditing(null)}>
                      添加第一个网络
                    </Button>
                  )
                }
              />
            ),
          }}
        />
      </Card>
      <div className="info-strip">
        <SafetyCertificateOutlined />
        <span>
          只有已批准且启用的授权来源可以放行新连接。官方设备每 5
          分钟同步，Headscale 按设备公钥实时验证。
        </span>
      </div>
      <Modal
        title={editing ? `编辑网络 · ${editing.name}` : "添加授权网络"}
        open={editing !== undefined}
        onCancel={() => setEditing(undefined)}
        width={600}
        okText={editing ? "保存更改" : "提交网络"}
        confirmLoading={busy.save}
        onOk={() =>
          void form
            .validateFields()
            .then((values) =>
              run(
                "save",
                () =>
                  mutate(
                    editing
                      ? `/api/v1/networks/${editing.id}`
                      : "/api/v1/networks",
                    editing ? "PUT" : "POST",
                    networkInput(values),
                  ),
                "网络已保存",
                () => {
                  setEditing(undefined);
                  resource.reload();
                },
              ),
            )
            .catch(() => undefined)
        }
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          preserve={false}
          className="modal-form"
        >
          <Form.Item
            name="name"
            label="网络名称"
            rules={[
              {
                required: true,
                whitespace: true,
                message: "请输入便于识别的网络名称",
              },
              { max: 100 },
            ]}
          >
            <Input placeholder="例如：团队生产网络" />
          </Form.Item>
          <Form.Item
            name="kind"
            label="控制平面类型"
            rules={[{ required: true }]}
          >
            <Radio.Group
              optionType="button"
              buttonStyle="solid"
              options={[
                { value: "tailscale", label: "Tailscale 官方" },
                { value: "headscale", label: "Headscale 自建" },
              ]}
            />
          </Form.Item>
          {kind === "tailscale" ? (
            <>
              <Alert
                type="info"
                showIcon
                message="OAuth 仅需 devices:core:read 权限"
                className="form-alert"
              />
              <Form.Item
                name="tailnet"
                label="Tailnet 标识"
                rules={[{ required: true, whitespace: true }]}
                extra="填写 Tailnet 名称或组织标识，例如 example.com。"
              >
                <Input placeholder="example.com" />
              </Form.Item>
              <Form.Item
                name="client_id"
                label="OAuth Client ID"
                rules={[{ required: !editing }]}
              >
                <Input
                  autoComplete="off"
                  placeholder={
                    editing ? "留空保留已保存的 Client ID" : "OAuth Client ID"
                  }
                />
              </Form.Item>
              <Form.Item
                name="client_secret"
                label="OAuth Client Secret"
                rules={[{ required: !editing }]}
              >
                <Input.Password
                  autoComplete="new-password"
                  placeholder={
                    editing ? "留空保留当前密钥" : "OAuth Client Secret"
                  }
                />
              </Form.Item>
            </>
          ) : (
            <>
              <Form.Item
                name="url"
                label="Headscale 验证地址"
                rules={[
                  { required: true },
                  { type: "url", message: "请输入包含 https:// 的完整 URL" },
                  {
                    validator: (_, value: string) =>
                      !value || value.startsWith("https://")
                        ? Promise.resolve()
                        : Promise.reject(new Error("验证地址必须使用 HTTPS")),
                  },
                ]}
                extra="原生接口路径为 /verify；私网地址需由管理员预先配置允许范围。"
              >
                <Input placeholder="https://headscale.example.com/verify" />
              </Form.Item>
              <Form.Item
                name="bearer_token"
                label="反向代理 Bearer Token（可选）"
              >
                <Input.Password
                  autoComplete="new-password"
                  placeholder={
                    editing
                      ? "留空保留现有凭据"
                      : "仅反向代理要求身份验证时填写"
                  }
                />
              </Form.Item>
              <Form.Item name="ca_pem" label="自定义 CA（可选）">
                <Input.TextArea
                  rows={3}
                  className="monospace"
                  placeholder="-----BEGIN CERTIFICATE-----"
                />
              </Form.Item>
            </>
          )}
          <SecretHint editing={Boolean(editing)} />
          <Form.Item name="note" label="备注" className="spaced-field">
            <Input.TextArea
              rows={2}
              maxLength={1000}
              showCount
              placeholder="接入用途或审核说明"
            />
          </Form.Item>
          {editing && (
            <Alert
              type="warning"
              showIcon
              message="更改 Tailnet 身份或验证地址后，将重新检查接入并按当前模式审核。"
            />
          )}
        </Form>
      </Modal>
      <Drawer
        title="网络详情"
        width={540}
        open={Boolean(detailID)}
        onClose={() => setDetailID(undefined)}
      >
        {detail ? (
          <>
            <div className="drawer-hero">
              <div className="list-icon">
                <TeamIcon kind={detail.kind} />
              </div>
              <h2>{detail.name}</h2>
              <Space>
                <StateTag value={detail.status} />
                <StateTag value={detail.health} />
              </Space>
            </div>
            <Detail label="类型">
              {detail.kind === "tailscale"
                ? "官方 Tailscale"
                : "自建 Headscale"}
            </Detail>
            <Detail label="来源标识">{detail.tailnet || detail.url}</Detail>
            {review && (
              <Detail label="申请人 ID">
                <Typography.Text copyable>{detail.owner_id}</Typography.Text>
              </Detail>
            )}
            <Detail label="设备数量">
              {detail.kind === "tailscale"
                ? detail.device_count
                : "按连接实时验证"}
            </Detail>
            <Detail label="最近成功">{timestamp(detail.last_success)}</Detail>
            <Detail label="创建时间">{timestamp(detail.created_at)}</Detail>
            <Detail label="配置版本">v{detail.revision}</Detail>
            <Detail label="备注">{detail.note}</Detail>
            {detail.last_error && (
              <Alert
                type="error"
                showIcon
                message="来源检查异常"
                description={detail.last_error}
                className="spaced-field"
              />
            )}
            <Button
              block
              type="primary"
              icon={<ExportOutlined />}
              className="spaced-field"
              onClick={() => setExportNetwork(detail)}
            >
              导出客户端接入配置
            </Button>
            <Alert
              className="spaced-field"
              type="info"
              showIcon
              message="应用配置到你的控制平面"
              description="平台提供中继发现配置。请将 DERP Map 手动应用到 Tailnet 策略或 Headscale 配置，现有网络的访问策略仍由各自控制平面管理。"
            />
          </>
        ) : (
          <NoData text="网络已删除或暂时无法读取" />
        )}
      </Drawer>
      <MapExport
        network={exportNetwork}
        onClose={() => setExportNetwork(undefined)}
      />
    </>
  );
}
function TeamIcon({ kind }: { kind: string }) {
  return kind === "tailscale" ? (
    <SafetyCertificateOutlined />
  ) : (
    <SyncOutlined />
  );
}

export function MapExport({
  network,
  onClose,
}: {
  network?: Pick<Network, "kind" | "name">;
  onClose: () => void;
}) {
  const [format, setFormat] = useState("json");
  const [onlyCustom, setOnlyCustom] = useState(false);
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (network) {
      setFormat("json");
      setOnlyCustom(false);
    }
  }, [network?.kind, network?.name]);
  useEffect(() => {
    if (!network) return;
    const ctrl = new AbortController();
    setLoading(true);
    setError("");
    setText("");
    request<string>(
      `/api/v1/derpmap?format=${format}&only_custom=${onlyCustom}`,
      {
        signal: ctrl.signal,
        headers: {
          Accept: format === "json" ? "application/json" : "text/yaml",
        },
      },
    )
      .then((result) => {
        // The API may use application/json and return an already parsed map.
        setText(
          exportMap(
            typeof result === "string"
              ? result
              : JSON.stringify(result, null, 2),
            network.kind,
            format,
          ),
        );
      })
      .catch((e) => {
        if (!ctrl.signal.aborted) setError(errorText(e));
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setLoading(false);
      });
    return () => ctrl.abort();
  }, [network?.kind, network?.name, format, onlyCustom]);
  return (
    <Modal
      open={Boolean(network)}
      onCancel={onClose}
      title={`导出 DERP 配置${network?.name ? ` · ${network.name}` : ""}`}
      width={760}
      footer={<Button onClick={onClose}>关闭</Button>}
      destroyOnHidden
    >
      <Alert
        type="info"
        showIcon
        message={
          network?.kind === "tailscale"
            ? "将 derpMap 合并到 Tailnet 的访问控制策略"
            : "将 JSON URL 或 YAML 文件配置到 Headscale 的 derp 设置"
        }
        description={
          network?.kind === "tailscale"
            ? "保留其他访问策略字段。默认继续使用 Tailscale 官方中继；只使用平台节点会让控制器或节点故障直接影响中继可用性。"
            : "公共 JSON URL 仅列出平台节点。如需保留官方 DERP，请在 Headscale 中同时保留其官方 DERP URL。"
        }
        className="form-alert"
      />
      <Space wrap className="export-controls">
        {network?.kind === "headscale" && (
          <Radio.Group
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            options={[
              { value: "json", label: "JSON" },
              { value: "yaml", label: "YAML 文件" },
            ]}
            optionType="button"
          />
        )}
        <Checkbox
          checked={onlyCustom}
          onChange={(e) => setOnlyCustom(e.target.checked)}
        >
          仅使用平台节点
        </Checkbox>
      </Space>
      {network?.kind === "headscale" && (
        <Detail label="平台 JSON URL">
          <Typography.Text
            copyable
          >{`${location.origin}/derpmap.json`}</Typography.Text>
        </Detail>
      )}
      {error && (
        <Alert
          type="error"
          message="配置导出失败"
          description={error}
          showIcon
          className="form-alert"
        />
      )}
      <CodeBlock
        text={text}
        filename={
          network?.kind === "tailscale"
            ? "tailscale-derp-policy.json"
            : `derpmap.${format}`
        }
        loading={loading}
      />
    </Modal>
  );
}
