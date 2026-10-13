import { useMemo, useState } from "react";
import {
  Button,
  Card,
  Col,
  Input,
  Row,
  Space,
  Table,
  Tag,
  Tooltip,
} from "antd";
import {
  DashboardOutlined,
  ExportOutlined,
  FileTextOutlined,
  SearchOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { DERPNode } from "../types";
import type { MetricSample } from "../metrics";
import { parseMetrics, safeMonitoringURL } from "../metrics";
import { useResource } from "../hooks";
import {
  CodeBlock,
  NoData,
  PageTitle,
  Refresh,
  ResourceError,
} from "../components";
import { timestamp } from "../utils";
import { ManagementTag, ProcessTags, RelayTag } from "../NodeHealth";

export function Monitoring() {
  const config = useResource<{ grafana_url: string; prometheus_url: string }>(
    "/api/v1/monitoring-config",
  );
  const metrics = useResource<string>("/api/v1/metrics", 15000);
  const nodes = useResource<DERPNode[]>("/api/v1/nodes", 15000);
  const [search, setSearch] = useState("");
  const [view, setView] = useState("table");
  const samples = useMemo(
    () => parseMetrics(typeof metrics.data === "string" ? metrics.data : ""),
    [metrics.data],
  );
  const filtered = samples.filter((sample) =>
    `${sample.name} ${sample.labels} ${sample.help}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const grafanaURL = safeMonitoringURL(config.data?.grafana_url);
  const prometheusURL = safeMonitoringURL(config.data?.prometheus_url);
  const interesting = samples
    .filter(
      (s) =>
        s.name.startsWith("derpers_") &&
        (s.type === "counter" || s.name.endsWith("_total")) &&
        s.value >= 0,
    )
    .slice(0, 6);
  const max = Math.max(1, ...interesting.map((s) => s.value));
  const columns: ColumnsType<MetricSample> = [
    {
      title: "指标",
      dataIndex: "name",
      width: 350,
      render: (_, sample) => (
        <Tooltip title={sample.help}>
          <strong className="metric-name">{sample.name}</strong>
        </Tooltip>
      ),
    },
    {
      title: "标签",
      dataIndex: "labels",
      width: 300,
      render: (value) => (
        <span className="monospace muted break-all">{value || "—"}</span>
      ),
    },
    {
      title: "类型",
      dataIndex: "type",
      width: 120,
      render: (type) => <Tag bordered={false}>{type}</Tag>,
    },
    {
      title: "当前值",
      dataIndex: "value",
      width: 180,
      align: "right",
      render: (value) => (
        <strong className="metric-number">
          {Number(value).toLocaleString("zh-CN", { maximumFractionDigits: 6 })}
        </strong>
      ),
    },
  ];
  return (
    <>
      <PageTitle
        eyebrow="OBSERVABILITY"
        title="监控中心"
        description="每 15 秒刷新当前指标。历史趋势、告警与仪表盘通过 Prometheus 和 Grafana 查看。"
        actions={
          <>
            <Refresh
              loading={metrics.loading || nodes.loading}
              reload={() => {
                metrics.reload();
                nodes.reload();
                config.reload();
              }}
            />
            {prometheusURL && (
              <Button
                icon={<ExportOutlined />}
                href={prometheusURL}
                target="_blank"
                rel="noopener noreferrer"
              >
                Prometheus
              </Button>
            )}
            {grafanaURL && (
              <Button
                type="primary"
                icon={<DashboardOutlined />}
                href={grafanaURL}
                target="_blank"
                rel="noopener noreferrer"
              >
                打开 Grafana
              </Button>
            )}
          </>
        }
      />
      <ResourceError
        error={metrics.error || nodes.error || config.error}
        reload={() => {
          metrics.reload();
          nodes.reload();
          config.reload();
        }}
      />
      <Row gutter={[22, 22]}>
        <Col xs={24} xl={14}>
          <Card
            title={
              <Space>
                <ThunderboltOutlined /> 节点运行情况
              </Space>
            }
            className="monitor-card"
          >
            <div className="monitor-node-grid">
              {nodes.data?.length ? (
                nodes.data.map((node) => (
                  <div className="monitor-node" key={node.id}>
                    <div className="monitor-node-top">
                      <strong>{node.name}</strong>
                      <ManagementTag node={node} compact />
                    </div>
                    <span className="muted">
                      {node.region_name} · {node.hostname}
                    </span>
                    <div style={{ marginTop: 12 }}>
                      <RelayTag node={node} />
                    </div>
                    <div style={{ marginTop: 7 }}>
                      <ProcessTags node={node} />
                    </div>
                    <div className="monitor-node-version">
                      <span>已应用配置</span>
                      <strong>
                        v{node.applied_revision} / v{node.revision}
                      </strong>
                    </div>
                    <div className="monitor-node-seen">
                      最近心跳 {timestamp(node.last_seen)}
                    </div>
                  </div>
                ))
              ) : (
                <NoData text="暂无节点指标" />
              )}
            </div>
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card
            title="控制器累计计数"
            extra={<Tag bordered={false}>当前快照</Tag>}
            className="monitor-card"
          >
            {interesting.length ? (
              <div className="metric-bars">
                {interesting.map((sample, i) => (
                  <div key={`${sample.name}${sample.labels}`}>
                    <div className="metric-bar-label">
                      <Tooltip title={`${sample.name}${sample.labels}`}>
                        <span>
                          {sample.name
                            .replace(/^derpers_/, "")
                            .replace(/_total$/, "")}
                          {sample.labels}
                        </span>
                      </Tooltip>
                      <strong>{sample.value.toLocaleString("zh-CN")}</strong>
                    </div>
                    <div className="metric-bar-track">
                      <div
                        style={{
                          width: `${Math.max(sample.value > 0 ? 1 : 0, (sample.value / max) * 100)}%`,
                          background: [
                            "#3263e7",
                            "#8c6bd9",
                            "#139a72",
                            "#c78419",
                            "#41a5b7",
                            "#d74c56",
                          ][i],
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <NoData
                text={
                  metrics.loading
                    ? "正在读取控制器计数"
                    : "尚无应用计数，原始指标见下方"
                }
              />
            )}
          </Card>
        </Col>
      </Row>
      <Card
        className="table-card spaced-field"
        title="Prometheus 实时指标"
        extra={
          <Space>
            <Button
              type={view === "table" ? "primary" : "default"}
              size="small"
              onClick={() => setView("table")}
            >
              指标表格
            </Button>
            <Button
              type={view === "raw" ? "primary" : "default"}
              size="small"
              icon={<FileTextOutlined />}
              onClick={() => setView("raw")}
            >
              原始输出
            </Button>
          </Space>
        }
      >
        {view === "raw" ? (
          <CodeBlock
            text={metrics.data || ""}
            filename="derpers-metrics.prom"
            loading={metrics.loading && !metrics.data}
          />
        ) : (
          <>
            <div className="table-toolbar">
              <span className="muted">
                {samples.length} 个指标样本 · 点击刷新获取最新值
              </span>
              <Input
                className="table-search"
                prefix={<SearchOutlined />}
                placeholder="搜索指标名称或标签"
                aria-label="搜索指标"
                value={search}
                allowClear
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Table
              columns={columns}
              dataSource={filtered}
              rowKey={(r) => `${r.name}${r.labels}`}
              size="small"
              scroll={{ x: 950 }}
              pagination={{ pageSize: 15, showSizeChanger: true }}
              loading={metrics.loading && !metrics.data}
              locale={{ emptyText: <NoData text="没有匹配的指标" /> }}
            />
          </>
        )}
      </Card>
    </>
  );
}
