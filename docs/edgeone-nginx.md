# EdgeOne 与 Nginx 部署

v0.2.0 采用 `Agent/浏览器 → EdgeOne HTTPS → Nginx → controller:8080`。节点证书和私钥继续保存在 Agent；Agent 用 `Authorization: DerpersProof <JWS>` 签名每次节点请求，控制器校验证书、签名、请求绑定、时间窗口和防重放 nonce。代理无需客户端证书或身份转发头。DERP 中继仍直接进入 derper，原生验证 URL 和 fail-closed 参数保持不变。

## 初次部署

1. 执行 `bash deploy/bootstrap.sh`，生成数据库密码、加密主密钥、节点身份 CA 和监控令牌；不生成控制器服务端 TLS 证书。
2. 编辑 `deploy/.env`，设置同一公开 HTTPS 域名的 `CONTROLLER_URL`、`PUBLIC_URL` 及 OIDC。默认版本为 `v0.2.0`，可用完整 `@sha256` 引用覆盖。
3. 将 `deploy/nginx-origin.conf` 的 `controller.example.com` 替换为公开域名，回源 Host 保留该域名；非匹配 Host 默认关闭连接。
4. 运行 `docker compose --env-file deploy/.env -f deploy/compose.yaml up -d`。controller 无宿主端口，Nginx 默认绑定 `127.0.0.1:8080`。本机可用 `curl -H 'Host: controller.example.com' http://127.0.0.1:8080/readyz` 验证。
5. 公网回源时保持 Compose `ORIGIN_BIND=127.0.0.1`，将 [公网源站 TLS 示例](../deploy/nginx-public-origin.conf) 作为主机 Nginx 的 server 配置，替换域名和有效源站证书路径并执行 `nginx -t`。在 EdgeOne 选择 HTTPS 回源、启用源站证书验证，回源 SNI/Host 使用配置域名；防火墙仅允许实际 EdgeOne 回源来源。源站 TLS 在 Nginx 终止，controller 仍仅 HTTP。私网或受控隧道回源才可将 `ORIGIN_BIND` 改为私网地址并用 HTTP。

示例 HTTP 回源适用于受控网络。签名提供身份和请求完整性验证，配置响应包含 DERP 服务证书私钥；Agent 的节点身份私钥始终保留在本机。公网跨网络回源由 Nginx 终止标准 HTTPS，再以 HTTP 连接 controller，不需要控制器服务端证书或 mTLS。

## EdgeOne 规则

首版建议整个控制器域名不缓存，验证后可只缓存带内容哈希的 `/assets/*`。以下路径始终不缓存，包括成功、拒绝、重定向和错误响应：

| 路径 | 配置 |
| --- | --- |
| `/api/*` | 不缓存，透传 Cookie、Authorization、请求体和 Set-Cookie |
| `/node/*`、`/admission/*` | 不缓存，不使用过期响应，保留完整 DerpersProof 头 |
| `/auth/*` | 不缓存，保留 OIDC 查询串、Cookie、Set-Cookie 和 Location |
| `/healthz`、`/readyz`、`/derpmap.json` | 不缓存，避免过期状态或连接配置 |
| `/metrics` | Nginx 拒绝公开访问，Prometheus 从 Docker 私网采集 |

源站已设置 `proxy_cache off`、禁用代理自动重试并发送 `Cache-Control: no-store`。EdgeOne 也需明确不缓存，而不是通过缓存键区分节点；任务、nonce 和续期不能复用缓存响应。[EdgeOne 内容缓存规则](https://cloud.tencent.com/document/product/1552/87651)、[规则引擎操作](https://www.tencentcloud.com/zh/document/product/1145/54759)。

对机器接口 `/api/v1/node-enroll`、`/node/*`、`/admission/*` 关闭 JS、验证码、浏览器挑战和强制交互认证，保留应用鉴权与必要限速；不得将 401/403/503 改写为 HTML 200。[Bot 智能分析的自动化请求例外](https://cloud.tencent.com/document/product/1552/98206)。

保留原始 HTTP 方法、路径、查询串、请求体和 Authorization；不要做 API 路径重写、尾斜杠重定向、请求体格式化或内容改写。最长签名头为 8 KiB，示例 Nginx 使用 `large_client_header_buffers 4 16k`。Host 使用公开域名，`X-Forwarded-Proto` 为 `https`。转发证书头不能代替签名。

EdgeOne 默认透传客户端请求头，仍需检查自定义规则是否删除或替换 Authorization。[回源请求头配置](https://cloud.tencent.com/document/product/1552/71012)、[默认回源请求头](https://www.tencentcloud.com/document/product/1145/54211)、[Nginx proxy 模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)。

## 节点链路

节点仍为三个容器：derper 调用 `http://caddy:9080/verify`，Caddy 通过 Docker 私网调用 `http://agent:9081/verify`，Agent 签名后将相同验证 JSON 发往 `CONTROLLER_URL/admission/v1/verify`。两个内部验证口不绑定宿主；未注册、签名或上游故障均拒绝准入。Agent 校验公开入口 TLS；`CONTROLLER_CA_FILE` 只用于私有入口 CA，与节点身份 CA 分开。身份续期后，后续管理和准入自动使用新证书。

## v0.1.0 迁移

1. 备份数据库、MASTER_KEY、原节点 CA、Agent 状态和原服务端 TLS 材料。保留原直连 HTTPS 地址，先组合 `compose.yaml` 与 `hybrid-compose.yaml` 运行新控制器；`LEGACY_TLS_BIND` 限定为旧节点可达的受控地址。hybrid 同时接受签名和真实 native mTLS，不信任转发证书头。
2. 暂时保持控制器 `CONTROLLER_URL` 为旧直连 HTTPS 地址，逐个升级 Agent 至 v0.2.0。新 Agent 在旧入口用签名并将 Caddy 切到本机 relay，旧 Agent 保持原 mTLS。检查任务、上报和真实 DERP 通信。
3. 配置并验证 EdgeOne/Nginx 后，在维护窗口停止全部待切换 Agent，统一更新控制器和所有节点 Agent 的 `CONTROLLER_URL` 为 CDN 公开 HTTPS 地址，再逐个启动 Agent；保留持久化身份目录。Agent 要求下发 URL 与本机配置一致，不能只修改一端并期望自动重定向。完成后核对配置、任务、心跳、身份续期和准入。不要提前把旧 Agent 的准入上游改到终止 TLS 的 CDN。
4. 确认无旧 Agent，设置 `NODE_AUTH_MODE=proof`，停止使用 hybrid overlay，关闭 native TLS 端口。proof 模式不因看到 TLS 客户端证书而绕过签名。

旧 `.env` 无监控令牌：用 `openssl rand -hex 32` 生成独立令牌，同时写入 `.env` 的 `METRICS_TOKEN` 和 `deploy/secrets/metrics-token`，文件设为 0600，再重启 controller/Prometheus。两个值必须一致；不要记录令牌或放入 URL。Prometheus 示例以容器内 root 读取只读私有文件，不持有 Docker socket。

## 验收

通过公开域名检查 readyz，注册节点、执行日志任务、等待上报和实际身份续期，最后用两真实客户端验证 DERP。匿名 metrics、未签名节点请求、伪造转发证书头都应被拒绝。日志只保留无查询串路径、方法、状态及签名是否存在，不保存 Authorization、Cookie、令牌或私钥。

GitHub E2E 使用两个固定版本的真实 Nginx 模拟边缘 TLS 终止和 HTTP 源站代理，控制器关闭 native TLS；四个原生架构/端口组合均核对注册、配置、任务、上报、续期、准入及原有通信和故障拒绝。CI 不连接真实 EdgeOne 账户；生产缓存、挑战、回源网络和证书仍需按实际站点规则验收。
