import { lazy, Suspense, useEffect, useState } from "react";
import {
  Alert,
  Avatar,
  Button,
  Card,
  Drawer,
  Dropdown,
  Layout,
  Menu,
  Result,
  Skeleton,
  Space,
  Spin,
  Tag,
} from "antd";
import {
  ApiOutlined,
  AppstoreOutlined,
  AuditOutlined,
  CloudServerOutlined,
  DownOutlined,
  GlobalOutlined,
  LockOutlined,
  LogoutOutlined,
  MenuOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { ApiError, errorText, mutate, request } from "./api";
import type { User } from "./types";
const Overview = lazy(() =>
  import("./pages/Overview").then((m) => ({ default: m.Overview })),
);
const Networks = lazy(() =>
  import("./pages/Networks").then((m) => ({ default: m.Networks })),
);
const Nodes = lazy(() =>
  import("./pages/Nodes").then((m) => ({ default: m.Nodes })),
);
const DNSAccounts = lazy(() =>
  import("./pages/DNSAccounts").then((m) => ({ default: m.DNSAccounts })),
);
const SettingsPage = lazy(() =>
  import("./pages/Settings").then((m) => ({ default: m.SettingsPage })),
);
const AuditPage = lazy(() =>
  import("./pages/Audit").then((m) => ({ default: m.AuditPage })),
);
const Monitoring = lazy(() =>
  import("./pages/Monitoring").then((m) => ({ default: m.Monitoring })),
);

const pages = {
  overview: "运行概览",
  networks: "我的网络",
  nodes: "中继节点",
  review: "网络审核",
  dns: "DNS 与域名",
  audit: "审计日志",
  monitoring: "监控中心",
  settings: "平台设置",
};
type Page = keyof typeof pages;
const adminPages: Page[] = ["review", "dns", "audit", "monitoring", "settings"];
function getPage(): Page {
  const key = location.hash.replace("#/", "").replace("#", "") as Page;
  return key in pages ? key : "overview";
}

function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? "compact" : ""}`}>
      <div className="brand-mark">
        <ApiOutlined />
      </div>
      <div>
        <strong>
          DERP<span>Control</span>
        </strong>
        {!compact && <small>SHARED RELAY PLATFORM</small>}
      </div>
    </div>
  );
}

function Login({ error, reload }: { error?: string; reload: () => void }) {
  return (
    <main className="login-page">
      <div className="login-top">
        <Logo compact />
        <Tag color="blue">私有中继平台</Tag>
      </div>
      <div className="login-content">
        <div className="login-copy">
          <div className="eyebrow">YOUR NETWORKS. ONE RELAY.</div>
          <h1>
            网络各自独立，
            <br />
            <span>中继连接共享。</span>
          </h1>
          <p>
            将多个 Tailnet 与 Headscale 接入统一的私有 DERP
            网络。集中管理节点、自动维护授权，在每一次连接时验证设备身份。
          </p>
          <div className="login-features">
            <div>
              <SafetyCertificateOutlined />
              <span>基于设备公钥的准入</span>
            </div>
            <div>
              <CloudServerOutlined />
              <span>节点部署与运行监控</span>
            </div>
            <div>
              <GlobalOutlined />
              <span>域名与证书自动管理</span>
            </div>
          </div>
        </div>
        <Card className="login-card">
          <div className="login-lock">
            <LockOutlined />
          </div>
          <h2>登录控制台</h2>
          <p>
            使用组织的身份提供商登录，
            <br />
            访问你的网络与中继资源。
          </p>
          {error && (
            <Alert
              type="error"
              message="控制台暂时不可用"
              description={error}
              showIcon
              action={
                <Button size="small" onClick={reload}>
                  重试
                </Button>
              }
            />
          )}
          <Button type="primary" size="large" block href="/auth/login">
            通过 OIDC 安全登录 <span aria-hidden>→</span>
          </Button>
          <div className="login-note">
            <SafetyCertificateOutlined /> 由组织统一验证身份
          </div>
        </Card>
      </div>
      <footer>
        DERP Control <span>·</span> 共享基础设施，独立控制平面
      </footer>
    </main>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>();
  const [error, setError] = useState("");
  const [page, setPage] = useState<Page>(getPage);
  const [mobileNav, setMobileNav] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  async function loadSession() {
    setError("");
    setUser(undefined);
    try {
      setUser(await request<User>("/api/v1/me"));
    } catch (e) {
      setUser(null);
      if (!(e instanceof ApiError && e.status === 401)) setError(errorText(e));
    }
  }
  useEffect(() => {
    void loadSession();
    const expire = () => setUser(null);
    const hash = () => setPage(getPage());
    window.addEventListener("session-expired", expire);
    window.addEventListener("hashchange", hash);
    return () => {
      window.removeEventListener("session-expired", expire);
      window.removeEventListener("hashchange", hash);
    };
  }, []);
  if (user === undefined)
    return (
      <div className="boot">
        <Logo />
        <Spin size="large" />
        <p>正在连接控制器…</p>
      </div>
    );
  if (!user) return <Login error={error} reload={() => void loadSession()} />;
  const selected = !user.admin && adminPages.includes(page) ? "overview" : page;
  const navigate = (key: string) => {
    location.hash = `/${key}`;
    setPage(key as Page);
    setMobileNav(false);
  };
  const items = [
    { key: "overview", icon: <AppstoreOutlined />, label: "运行概览" },
    { key: "networks", icon: <TeamOutlined />, label: "我的网络" },
    {
      key: "nodes",
      icon: <CloudServerOutlined />,
      label: user.admin ? "节点管理" : "可用节点",
    },
    ...(user.admin
      ? [
          {
            type: "group" as const,
            label: "管理工作区",
            children: [
              {
                key: "review",
                icon: <SafetyCertificateOutlined />,
                label: "网络审核",
              },
              { key: "dns", icon: <GlobalOutlined />, label: "DNS 与域名" },
              {
                key: "monitoring",
                icon: <ThunderboltOutlined />,
                label: "监控中心",
              },
              { key: "audit", icon: <AuditOutlined />, label: "审计日志" },
              { key: "settings", icon: <SettingOutlined />, label: "平台设置" },
            ],
          },
        ]
      : []),
  ];
  const nav = (
    <>
      <Logo />
      <div className="sidebar-label">工作空间</div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[selected]}
        items={items}
        onClick={({ key }) => navigate(key)}
      />
      <div className="sidebar-footer">
        <div className="security-indicator">
          <span />
          默认拒绝未知设备
        </div>
        <p>多控制平面 · 统一准入</p>
      </div>
    </>
  );
  let content;
  switch (selected) {
    case "networks":
      content = <Networks user={user} />;
      break;
    case "review":
      content = <Networks user={user} review />;
      break;
    case "nodes":
      content = <Nodes user={user} />;
      break;
    case "dns":
      content = <DNSAccounts />;
      break;
    case "settings":
      content = <SettingsPage />;
      break;
    case "audit":
      content = <AuditPage />;
      break;
    case "monitoring":
      content = <Monitoring />;
      break;
    case "overview":
      content = <Overview user={user} navigate={navigate} />;
      break;
    default:
      content = <Result status="404" title="页面不存在" />;
  }
  return (
    <Layout className="app-shell">
      <Layout.Sider width={238} className="desktop-sidebar">
        {nav}
      </Layout.Sider>
      <Drawer
        placement="left"
        width={260}
        open={mobileNav}
        onClose={() => setMobileNav(false)}
        className="mobile-sidebar"
        styles={{ body: { padding: 0, background: "#0b1529" } }}
      >
        {nav}
      </Drawer>
      <Layout className="main-layout">
        <header className="topbar">
          <Space>
            <Button
              className="mobile-menu"
              type="text"
              aria-label="打开导航"
              icon={<MenuOutlined />}
              onClick={() => setMobileNav(true)}
            />
            <span className="breadcrumb-home">工作空间</span>
            <span className="breadcrumb-slash">/</span>
            <strong>{pages[selected]}</strong>
          </Space>
          <Space size={16}>
            <Tag
              className="role-tag"
              bordered={false}
              color={user.admin ? "blue" : "default"}
            >
              {user.admin ? "管理员" : "成员"}
            </Tag>
            <Dropdown
              trigger={["click"]}
              menu={{
                items: [
                  {
                    key: "logout",
                    icon: <LogoutOutlined />,
                    label: "退出登录",
                    disabled: loggingOut,
                  },
                ],
                onClick: () => {
                  setLoggingOut(true);
                  void mutate("/auth/logout")
                    .then(() => {
                      setUser(null);
                      location.hash = "";
                    })
                    .catch((e) => setError(errorText(e)))
                    .finally(() => setLoggingOut(false));
                },
              }}
            >
              <Button type="text" className="user-menu">
                <Avatar
                  size={28}
                  style={{ background: "#e7edff", color: "#3263e7" }}
                >
                  {(user.name || user.email || "U").slice(0, 1).toUpperCase()}
                </Avatar>
                <span className="user-name">
                  {user.name || user.email || "用户"}
                </span>
                <DownOutlined />
              </Button>
            </Dropdown>
          </Space>
        </header>
        <Layout.Content className="page-content">
          {error && (
            <Alert
              type="error"
              message={error}
              closable
              onClose={() => setError("")}
              className="resource-error"
            />
          )}
          <Suspense
            key={selected}
            fallback={
              <Card>
                <Skeleton active paragraph={{ rows: 7 }} />
              </Card>
            }
          >
            {content}
          </Suspense>
        </Layout.Content>
        <footer className="app-footer">
          <span>DERP Control</span>
          <span>共享中继 · 每次连接验证身份</span>
        </footer>
      </Layout>
    </Layout>
  );
}
