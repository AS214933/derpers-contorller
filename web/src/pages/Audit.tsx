import { useMemo, useState } from "react";
import {
  Button,
  Card,
  Drawer,
  Input,
  Select,
  Table,
  Tag,
  Typography,
} from "antd";
import { DownloadOutlined, SearchOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import type { Audit } from "../types";
import { download } from "../api";
import { useResource } from "../hooks";
import {
  Detail,
  NoData,
  PageTitle,
  Refresh,
  ResourceError,
} from "../components";
import { timestamp } from "../utils";

export function AuditPage() {
  const resource = useResource<Audit[]>("/api/v1/audit", 30000);
  const [search, setSearch] = useState("");
  const [event, setEvent] = useState("all");
  const [selected, setSelected] = useState<Audit>();
  const events = useMemo(
    () => [...new Set(resource.data?.map((a) => a.event) || [])].sort(),
    [resource.data],
  );
  const data = useMemo(
    () =>
      (resource.data || []).filter(
        (a) =>
          (event === "all" || a.event === event) &&
          `${a.event} ${a.actor} ${a.detail} ${a.node_id || ""} ${a.network_id || ""} ${a.node_public || ""}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [resource.data, event, search],
  );
  const columns: ColumnsType<Audit> = [
    {
      title: "发生时间",
      dataIndex: "time",
      width: 190,
      render: timestamp,
      sorter: (a, b) => Date.parse(a.time) - Date.parse(b.time),
      defaultSortOrder: "descend",
    },
    {
      title: "事件",
      dataIndex: "event",
      width: 220,
      render: (value) => (
        <Tag
          bordered={false}
          color={
            value.includes("fail") || value.includes("error") ? "error" : "blue"
          }
        >
          {value}
        </Tag>
      ),
    },
    {
      title: "准入结果",
      dataIndex: "allow",
      width: 110,
      render: (value) =>
        value === undefined ? (
          "—"
        ) : (
          <Tag bordered={false} color={value ? "success" : "error"}>
            {value ? "允许" : "拒绝"}
          </Tag>
        ),
    },
    { title: "操作者", dataIndex: "actor", width: 170, ellipsis: true },
    { title: "详情", dataIndex: "detail", width: 350, ellipsis: true },
    {
      title: "操作",
      width: 90,
      fixed: "right",
      render: (_, record) => (
        <Button type="link" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ];
  return (
    <>
      <PageTitle
        eyebrow="AUDIT TRAIL"
        title="审计日志"
        description="追踪准入决策、来源同步与管理员操作。展示控制器返回的近期事件，默认保留 30 天。"
        actions={
          <>
            <Refresh loading={resource.loading} reload={resource.reload} />
            <Button
              icon={<DownloadOutlined />}
              disabled={!data.length}
              onClick={() =>
                download(
                  JSON.stringify(data, null, 2),
                  `derp-audit-${new Date().toISOString().slice(0, 10)}.json`,
                  "application/json",
                )
              }
            >
              导出当前结果
            </Button>
          </>
        }
      />
      <ResourceError error={resource.error} reload={resource.reload} />
      <Card className="table-card">
        <div className="table-toolbar">
          <Select
            aria-label="筛选事件类型"
            value={event}
            onChange={setEvent}
            options={[
              { value: "all", label: "所有事件类型" },
              ...events.map((value) => ({ value, label: value })),
            ]}
            style={{ minWidth: 230 }}
          />
          <Input
            className="table-search"
            prefix={<SearchOutlined />}
            placeholder="搜索公钥、节点、事件或操作人"
            aria-label="搜索审计日志"
            allowClear
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={data}
          loading={resource.loading}
          scroll={{ x: 1180 }}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showTotal: (total) => `当前返回 ${total} 条事件`,
          }}
          locale={{ emptyText: <NoData text="没有匹配的审计事件" /> }}
        />
      </Card>
      <Drawer
        title="审计事件详情"
        open={Boolean(selected)}
        onClose={() => setSelected(undefined)}
        width={580}
      >
        {selected && (
          <>
            <Detail label="事件 ID">
              <Typography.Text copyable>{selected.id}</Typography.Text>
            </Detail>
            <Detail label="发生时间">{timestamp(selected.time)}</Detail>
            <Detail label="类型">{selected.event}</Detail>
            <Detail label="操作者">{selected.actor}</Detail>
            <Detail label="准入结果">
              {selected.allow === undefined
                ? "不适用"
                : selected.allow
                  ? "允许"
                  : "拒绝"}
            </Detail>
            <Detail label="节点 ID">{selected.node_id}</Detail>
            <Detail label="来源 ID">{selected.network_id}</Detail>
            <Detail label="设备 Node Key">
              {selected.node_public && (
                <Typography.Text copyable className="break-all">
                  {selected.node_public}
                </Typography.Text>
              )}
            </Detail>
            <div className="spaced-field">
              <strong>详情</strong>
              <pre className="plain-output">{selected.detail}</pre>
            </div>
          </>
        )}
      </Drawer>
    </>
  );
}
