# DERP Control 管理门户

React + TypeScript + Vite + Ant Design 中文网页，全部数据来自控制器同源 API。页面按 OIDC 用户的管理员身份显示相应操作，服务端仍必须执行资源归属和管理员权限检查。

```powershell
npm ci
npm run dev
```

开发服务器仅监听 `127.0.0.1:5173`，将 `/api`、`/auth`、`/metrics` 和 DERP Map 请求代理到 `127.0.0.1:8080`。实际 OIDC 回调需要控制器配置与所用的 HTTPS 入口对应；开发服务器不绕过认证。

```powershell
npm test
npm run build
```

生产构建在 `dist/`，由控制器以 `WEB_DIR=/app/web` 提供。镜像构建将网页一起打包，不需要额外部署 Node.js 服务。前端无环境密钥、无虚构数据、无本地认证旁路。

页面覆盖用户网络接入与配置导出、管理员网络审批、DERP 节点配置与注册、DNS 三家服务商管理、节点配置/重启/升级/日志任务、审批模式、审计和实时 Prometheus 指标。Grafana 和 Prometheus 链接读取 `/api/v1/monitoring-config`，未配置时隐藏。

读取接口不返回凭据。编辑表单的秘密字段不回填，留空保留已有值；一次性注册令牌只在当次弹窗内保存，不写入浏览器持久存储。升级要求完整 `@sha256:` 镜像摘要。下载配置、日志、审计文件均由浏览器在本地生成。
