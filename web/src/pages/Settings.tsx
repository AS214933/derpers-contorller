import { useEffect } from "react";
import { Alert, Button, Card, Form, Radio, Space } from "antd";
import {
  LockOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
} from "@ant-design/icons";
import type { Settings } from "../types";
import { mutate } from "../api";
import { useResource } from "../hooks";
import { PageTitle, ResourceError, useActions } from "../components";

export function SettingsPage() {
  const resource = useResource<Settings>("/api/v1/settings");
  const [form] = Form.useForm<Settings>();
  const { busy, run, confirm } = useActions();
  useEffect(() => {
    if (resource.data) form.setFieldsValue(resource.data);
  }, [resource.data, form]);
  async function save() {
    const value = await form.validateFields();
    const execute = () =>
      run(
        "save",
        () => mutate("/api/v1/settings", "PUT", value),
        "审批设置已更新",
        resource.reload,
      );
    if (
      value.approval_mode === "automatic" &&
      resource.data?.approval_mode !== "automatic"
    )
      confirm(
        "启用自动审批？",
        "所有通过 OIDC 登录的用户都将被视为可信授权来源提供者，其提交的 Headscale 服务通过接入检查后可授权设备使用共享 DERP。现有待审核网络仍需手动处理。",
        execute,
        false,
      );
    else await execute();
  }
  return (
    <>
      <PageTitle
        eyebrow="PLATFORM SETTINGS"
        title="平台设置"
        description="配置网络接入策略。身份提供商及节点信任配置通过控制器启动参数管理。"
      />
      <ResourceError error={resource.error} reload={resource.reload} />
      <div className="settings-grid">
        <Card
          title={
            <Space>
              <SafetyCertificateOutlined /> 网络审批模式
            </Space>
          }
          loading={resource.loading}
        >
          <Form form={form} layout="vertical" onFinish={() => void save()}>
            <Form.Item name="approval_mode" rules={[{ required: true }]}>
              <Radio.Group className="approval-options">
                <Radio value="manual">
                  <strong>人工审核</strong>
                  <span>用户提交网络后，由管理员检查并批准接入。</span>
                  <TagRecommended />
                </Radio>
                <Radio value="automatic">
                  <strong>自动通过</strong>
                  <span>OIDC 用户提交的网络通过连接检查后自动启用。</span>
                </Radio>
              </Radio.Group>
            </Form.Item>
            <Alert
              type="info"
              showIcon
              message="自动审批的信任范围"
              description="自动模式信任所有 OIDC 登录用户及其提供的 Headscale 验证服务。切换模式不改变已审核网络的当前状态。"
            />
            <Button
              className="spaced-field"
              type="primary"
              htmlType="submit"
              icon={<SaveOutlined />}
              loading={busy.save}
              disabled={Boolean(resource.error)}
            >
              保存设置
            </Button>
          </Form>
        </Card>
        <Card
          title={
            <Space>
              <LockOutlined /> 运行策略
            </Space>
          }
        >
          <div className="policy-list">
            <div>
              <strong>默认拒绝</strong>
              <p>没有有效来源明确允许时，拒绝新的 DERP 连接。</p>
            </div>
            <div>
              <strong>官方设备同步</strong>
              <p>每 5 分钟同步，成功快照最多有效 15 分钟。</p>
            </div>
            <div>
              <strong>Headscale 实时验证</strong>
              <p>沿用原生 /verify 语义，不保存正向授权缓存。</p>
            </div>
            <div>
              <strong>连接生命周期</strong>
              <p>
                禁用来源限制后续连接。需断开已建立连接时，在节点管理中重启中继。
              </p>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}
function TagRecommended() {
  return <span className="recommended-pill">推荐</span>;
}
