import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
} from "antd";
import {
  CheckCircleOutlined,
  DeleteOutlined,
  EditOutlined,
  GlobalOutlined,
  PlusOutlined,
  SearchOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { DNSAccount } from "../types";
import { mutate } from "../api";
import { useResource } from "../hooks";
import {
  NoData,
  PageTitle,
  Refresh,
  ResourceError,
  SecretHint,
  StateTag,
  useActions,
} from "../components";
import { DNS_KEYS, dnsInput } from "../utils";

const providers = {
  cloudflare: "Cloudflare",
  alidns: "阿里云 DNS",
  dnspod: "腾讯云 DNSPod",
};
const fieldNames: Record<string, string> = {
  api_token: "API Token",
  access_key_id: "AccessKey ID",
  access_key_secret: "AccessKey Secret",
  secret_id: "SecretId",
  secret_key: "SecretKey",
};
export function DNSAccounts() {
  const resource = useResource<DNSAccount[]>("/api/v1/dns-accounts");
  const { run, busy, confirm } = useActions();
  const [editing, setEditing] = useState<DNSAccount | null | undefined>();
  const [search, setSearch] = useState("");
  const [form] = Form.useForm();
  const provider = (Form.useWatch("provider", form) ||
    "cloudflare") as DNSAccount["provider"];
  useEffect(() => {
    if (editing !== undefined) {
      form.resetFields();
      form.setFieldsValue(editing || { provider: "cloudflare" });
    }
  }, [editing, form]);
  const columns: ColumnsType<DNSAccount> = [
    {
      title: "账户名称",
      dataIndex: "name",
      width: 230,
      render: (name) => (
        <Space>
          <div className="small-list-icon">
            <GlobalOutlined />
          </div>
          <strong>{name}</strong>
        </Space>
      ),
    },
    {
      title: "服务商",
      dataIndex: "provider",
      width: 180,
      render: (value) => (
        <Tag
          bordered={false}
          color={
            value === "cloudflare"
              ? "orange"
              : value === "alidns"
                ? "blue"
                : "purple"
          }
        >
          {providers[value as keyof typeof providers] || value}
        </Tag>
      ),
    },
    { title: "DNS Zone", dataIndex: "zone", width: 210 },
    { title: "统一域名后缀", dataIndex: "suffix", width: 230 },
    {
      title: "连接状态",
      dataIndex: "health",
      width: 140,
      render: (value, account) => (
        <Tooltip title={account.last_error}>
          <StateTag value={value} />
        </Tooltip>
      ),
    },
    {
      title: "操作",
      fixed: "right",
      width: 160,
      render: (_, account) => (
        <Space size={2}>
          <Tooltip title="测试 DNS 账户">
            <Button
              type="text"
              icon={<CheckCircleOutlined />}
              aria-label={`测试 ${account.name}`}
              loading={busy[`test:${account.id}`]}
              onClick={() =>
                void run(
                  `test:${account.id}`,
                  () => mutate(`/api/v1/dns-accounts/${account.id}/test`),
                  "DNS 账户检查完成",
                  resource.reload,
                )
              }
            />
          </Tooltip>
          <Tooltip title="编辑账户">
            <Button
              type="text"
              icon={<EditOutlined />}
              aria-label={`编辑 ${account.name}`}
              onClick={() => setEditing(account)}
            />
          </Tooltip>
          <Tooltip title="删除账户">
            <Button
              type="text"
              danger
              icon={<DeleteOutlined />}
              aria-label={`删除 ${account.name}`}
              onClick={() =>
                confirm(
                  `删除 DNS 账户“${account.name}”？`,
                  "请先解除节点对此账户的引用。删除后，将无法使用此账户申请或续期证书。",
                  async () => {
                    await mutate(
                      `/api/v1/dns-accounts/${account.id}`,
                      "DELETE",
                    );
                    resource.reload();
                  },
                )
              }
            />
          </Tooltip>
        </Space>
      ),
    },
  ];
  const dnsDomainRule = {
    pattern:
      /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/,
    message: "请输入完整域名，不包含协议、路径或通配符",
  };
  return (
    <>
      <PageTitle
        eyebrow="DNS AUTOMATION"
        title="DNS 与域名"
        description="连接域名服务商，为中继节点创建解析并自动签发、续期证书。"
        actions={
          <>
            <Refresh loading={resource.loading} reload={resource.reload} />
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setEditing(null)}
            >
              添加 DNS 账户
            </Button>
          </>
        }
      />
      <ResourceError error={resource.error} reload={resource.reload} />
      <div className="provider-cards">
        {Object.entries(providers).map(([key, name]) => (
          <Card key={key} className={`provider-card ${key}`}>
            <GlobalOutlined />
            <strong>{name}</strong>
            <span>
              {key === "cloudflare"
                ? "Zone-scoped API Token"
                : key === "alidns"
                  ? "AccessKey 凭据"
                  : "SecretId / SecretKey"}
            </span>
          </Card>
        ))}
      </div>
      <Card className="table-card">
        <div className="table-toolbar">
          <div>
            <strong>域名服务账户</strong>
            <span className="muted toolbar-count">
              {resource.data?.length ?? "—"} 个账户
            </span>
          </div>
          <Input
            className="table-search"
            prefix={<SearchOutlined />}
            placeholder="搜索账户或域名"
            aria-label="搜索 DNS 账户"
            allowClear
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={(resource.data || []).filter((n) =>
            `${n.name} ${n.zone} ${n.suffix}`
              .toLowerCase()
              .includes(search.toLowerCase()),
          )}
          loading={resource.loading}
          scroll={{ x: 1100 }}
          pagination={{ pageSize: 10 }}
          locale={{
            emptyText: (
              <NoData
                text="尚未配置域名服务账户"
                action={
                  <Button onClick={() => setEditing(null)}>
                    添加 DNS 账户
                  </Button>
                }
              />
            ),
          }}
        />
      </Card>
      <div className="info-strip">
        <GlobalOutlined />
        <span>
          平台只管理登记的 DNS 记录。DNS
          密钥加密保存在控制器，节点仅接收自身证书；Cloudflare 记录使用 DNS
          only。
        </span>
      </div>
      <Modal
        title={editing ? `编辑 DNS 账户 · ${editing.name}` : "添加 DNS 账户"}
        open={editing !== undefined}
        onCancel={() => setEditing(undefined)}
        width={580}
        okText="保存账户"
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
                      ? `/api/v1/dns-accounts/${editing.id}`
                      : "/api/v1/dns-accounts",
                    editing ? "PUT" : "POST",
                    dnsInput(values),
                  ),
                "DNS 账户已保存",
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
            label="账户名称"
            rules={[{ required: true, whitespace: true }, { max: 100 }]}
          >
            <Input placeholder="例如：生产域名" />
          </Form.Item>
          <Form.Item
            name="provider"
            label="DNS 服务商"
            rules={[{ required: true }]}
          >
            <Select
              disabled={Boolean(editing)}
              options={Object.entries(providers).map(([value, label]) => ({
                value,
                label,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="zone"
            label="DNS Zone"
            rules={[{ required: true }, dnsDomainRule]}
            extra={
              editing
                ? "服务商与 DNS Zone 创建后固定。更换时请创建新账户。"
                : "在该服务商托管的 DNS Zone 域名，例如 example.com。"
            }
          >
            <Input placeholder="example.com" disabled={Boolean(editing)} />
          </Form.Item>
          <Form.Item
            name="suffix"
            label="节点统一域名后缀"
            rules={[
              { required: true },
              dnsDomainRule,
              {
                validator: (_, value: string) => {
                  const zone = form.getFieldValue("zone");
                  return !value ||
                    !zone ||
                    value === zone ||
                    value.endsWith(`.${zone}`)
                    ? Promise.resolve()
                    : Promise.reject(
                        new Error("域名后缀必须属于所填 DNS Zone"),
                      );
                },
              },
            ]}
            extra="节点域名形如 hk-01.derp.example.com。"
          >
            <Input placeholder="derp.example.com" />
          </Form.Item>
          {DNS_KEYS[provider].map((key) => (
            <Form.Item
              key={key}
              name={key}
              label={fieldNames[key]}
              rules={[{ required: !editing || editing.provider !== provider }]}
            >
              <Input.Password
                autoComplete="new-password"
                placeholder={
                  editing && editing.provider === provider
                    ? "留空保留当前凭据"
                    : `填写 ${fieldNames[key]}`
                }
              />
            </Form.Item>
          ))}
          <SecretHint editing={Boolean(editing)} />
          <Alert
            type="info"
            showIcon
            className="spaced-field"
            message={
              provider === "cloudflare"
                ? "API Token 需要对应 Zone 的 DNS 编辑与 Zone 读取权限。"
                : "凭据需具备所选 DNS Zone 的查询和记录管理权限。"
            }
            description="保存后可执行账户测试。实际解析与证书签发在节点详情中执行。"
          />
        </Form>
      </Modal>
    </>
  );
}
