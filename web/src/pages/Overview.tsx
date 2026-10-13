import {
  Alert,
  Button,
  Card,
  Col,
  List,
  Progress,
  Row,
  Skeleton,
  Space,
  Tag,
} from "antd";
import {
  ArrowRightOutlined,
  CheckCircleFilled,
  CloudServerOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import type { Audit, DERPNode, Network, User } from "../types";
import { useResource } from "../hooks";
import {
  NoData,
  PageTitle,
  ResourceError,
  StateTag,
  StatCard,
} from "../components";
import { compact, timestamp } from "../utils";

export function Overview({
  user,
  navigate,
}: {
  user: User;
  navigate: (key: string) => void;
}) {
  const networks = useResource<Network[]>("/api/v1/networks", 30000);
  const nodes = useResource<DERPNode[]>("/api/v1/nodes", 15000);
  const audit = useResource<Audit[]>(
    user.admin ? "/api/v1/audit" : null,
    30000,
  );
  const approved = networks.data?.filter((n) => n.status === "approved").length;
  const pending =
    networks.data?.filter((n) => n.status === "pending").length || 0;
  const published = nodes.data?.filter((n) => n.published).length;
  const online = nodes.data?.filter((n) =>
    ["online", "healthy", "ready", "ok"].includes(n.status),
  ).length;
  const devices = networks.data?.reduce(
    (total, n) => total + n.device_count,
    0,
  );
  return (
    <>
      <PageTitle
        eyebrow="CONTROL PLANE"
        title={`你好，${user.name || user.email?.split("@")[0] || "欢迎回来"}`}
        description="统一查看授权网络与中继节点的运行情况。"
        actions={
          <Button
            type="primary"
            icon={<TeamOutlined />}
            onClick={() => navigate("networks")}
          >
            管理我的网络
          </Button>
        }
      />
      <ResourceError
        error={networks.error || nodes.error}
        reload={() => {
          networks.reload();
          nodes.reload();
        }}
      />
      <div className="overview-banner">
        <div>
          <Tag bordered={false} color="green">
            <SafetyCertificateOutlined /> 统一准入已启用
          </Tag>
          <h2>独立的网络，共享的连接。</h2>
          <p>来自已批准网络的设备通过公钥验证，安全接入同一组 DERP 中继。</p>
          <Button type="link" onClick={() => navigate("nodes")}>
            查看中继网络 <ArrowRightOutlined />
          </Button>
        </div>
        <div
          className="topology"
          aria-label="独立 Tailnet 与 Headscale 通过准入控制器连接 DERP 节点"
        >
          <div className="topology-sources">
            <span>Tailnet</span>
            <span>Headscale</span>
          </div>
          <div className="topology-lines" />
          <div className="topology-core">
            <SafetyCertificateOutlined />
            <small>ADMISSION</small>
          </div>
          <div className="topology-lines single" />
          <div className="topology-node">
            <CloudServerOutlined />
            <span>DERP</span>
          </div>
        </div>
      </div>
      <Row gutter={[18, 18]} className="stats-row">
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label="已批准网络"
            value={approved ?? "—"}
            sub={`${pending} 个网络等待审核`}
            icon={<TeamOutlined />}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label="已发布节点"
            value={published ?? "—"}
            sub="面向所有已批准网络共享"
            icon={<CloudServerOutlined />}
            tone="purple"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label="在线节点"
            value={online ?? "—"}
            sub={user.admin ? "基于 Agent 最新状态" : "已发布节点运行状态"}
            icon={<ThunderboltOutlined />}
            tone="green"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label="已同步设备"
            value={devices === undefined ? "—" : compact(devices)}
            sub="官方 Tailnet 缓存 · Headscale 实时验证"
            icon={<SafetyCertificateOutlined />}
            tone="orange"
          />
        </Col>
      </Row>
      {user.admin && pending > 0 && (
        <Alert
          className="resource-error"
          showIcon
          type="info"
          message={`有 ${pending} 个网络正在等待审核`}
          action={
            <Button type="link" size="small" onClick={() => navigate("review")}>
              前往审核 <ArrowRightOutlined />
            </Button>
          }
        />
      )}
      <Row gutter={[22, 22]}>
        <Col xs={24} xl={14}>
          <Card
            title="中继节点"
            extra={
              <Button type="link" onClick={() => navigate("nodes")}>
                查看全部 <ArrowRightOutlined />
              </Button>
            }
            className="dashboard-card"
          >
            <Skeleton
              loading={nodes.loading && !nodes.data}
              active
              paragraph={{ rows: 4 }}
            >
              <List
                dataSource={(nodes.data || []).slice(0, 5)}
                locale={{
                  emptyText: (
                    <NoData
                      text={
                        user.admin ? "尚未添加中继节点" : "暂无已发布的中继节点"
                      }
                    />
                  ),
                }}
                renderItem={(node) => (
                  <List.Item className="node-list-item">
                    <List.Item.Meta
                      avatar={
                        <div className="list-icon">
                          <CloudServerOutlined />
                        </div>
                      }
                      title={
                        <Space>
                          <strong>{node.name}</strong>
                          <StateTag value={node.status} />
                        </Space>
                      }
                      description={
                        <span>
                          {node.hostname}:{node.https_port}{" "}
                          <span className="dot-separator">·</span>{" "}
                          {node.region_name || node.region_code}
                        </span>
                      }
                    />
                    <div className="node-list-status">
                      <span
                        className={`status-dot ${node.applied_revision === node.revision ? "green" : "orange"}`}
                      />
                      {user.admin
                        ? `配置 v${node.applied_revision}/${node.revision}`
                        : `Region ${node.region_id}`}
                    </div>
                  </List.Item>
                )}
              />
            </Skeleton>
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card
            title="授权来源"
            extra={<Tag bordered={false}>即时数据</Tag>}
            className="dashboard-card"
          >
            <Skeleton
              loading={networks.loading && !networks.data}
              active
              paragraph={{ rows: 4 }}
            >
              {networks.data?.length ? (
                <>
                  <div className="source-breakdown">
                    <span>官方 Tailscale</span>
                    <strong>
                      {
                        networks.data.filter((n) => n.kind === "tailscale")
                          .length
                      }
                    </strong>
                  </div>
                  <Progress
                    percent={Math.round(
                      (networks.data.filter((n) => n.kind === "tailscale")
                        .length /
                        networks.data.length) *
                        100,
                    )}
                    showInfo={false}
                    strokeColor="#3263e7"
                  />
                  <div className="source-breakdown">
                    <span>自建 Headscale</span>
                    <strong>
                      {
                        networks.data.filter((n) => n.kind === "headscale")
                          .length
                      }
                    </strong>
                  </div>
                  <Progress
                    percent={Math.round(
                      (networks.data.filter((n) => n.kind === "headscale")
                        .length /
                        networks.data.length) *
                        100,
                    )}
                    showInfo={false}
                    strokeColor="#8060ce"
                  />
                  <div className="source-footnote">
                    <CheckCircleFilled /> 各控制平面独立管理设备与访问策略
                  </div>
                </>
              ) : (
                <NoData
                  text="添加网络以启用共享中继"
                  action={
                    <Button onClick={() => navigate("networks")}>
                      添加网络
                    </Button>
                  }
                />
              )}
            </Skeleton>
          </Card>
        </Col>
        <Col span={24}>
          <Card
            title={user.admin ? "最近审计事件" : "接入步骤"}
            extra={
              user.admin && (
                <Button type="link" onClick={() => navigate("audit")}>
                  完整审计 <ArrowRightOutlined />
                </Button>
              )
            }
          >
            {user.admin ? (
              <>
                <ResourceError error={audit.error} reload={audit.reload} />
                <List
                  loading={audit.loading && !audit.data}
                  dataSource={(audit.data || []).slice(0, 5)}
                  locale={{ emptyText: <NoData text="尚无审计事件" /> }}
                  renderItem={(event) => (
                    <List.Item
                      extra={
                        <span className="muted">{timestamp(event.time)}</span>
                      }
                    >
                      <Space>
                        <span
                          className={`status-dot ${event.allow === false ? "orange" : "blue"}`}
                        />
                        <strong>{event.event}</strong>
                        <span className="muted">{event.detail}</span>
                      </Space>
                    </List.Item>
                  )}
                />
              </>
            ) : (
              <div className="quick-steps">
                {[
                  [
                    "01",
                    "添加授权来源",
                    "提交官方 Tailnet OAuth 凭据或 Headscale 验证地址。",
                  ],
                  [
                    "02",
                    "等待审核与检查",
                    "平台批准后，持续同步或实时验证设备公钥。",
                  ],
                  [
                    "03",
                    "应用 DERP 配置",
                    "将导出的 DERP Map 应用到自己的控制平面。",
                  ],
                ].map(([n, title, detail]) => (
                  <div key={n}>
                    <span>{n}</span>
                    <h3>{title}</h3>
                    <p>{detail}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </>
  );
}
