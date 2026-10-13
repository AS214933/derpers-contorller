# derpers-contorller

多官方 Tailnet、多独立 Headscale 共用一组私有 DERP 节点的准入和管理平台。Go 控制器负责授权、审批、节点任务、DNS/证书和审计；中文网页使用 OIDC 登录。节点部署 Agent、官方 derper 和 Caddy 三个容器。公开中继 TLS 直接由 derper 处理，Caddy 只承担本机准入转发和可选 HTTP 探测。

目标仓库：[AS214933/derpers-contorller](https://github.com/AS214933/derpers-contorller)。完整设计和验收条件见 [PLAN.md](PLAN.md)。

## 授权与故障行为

- 官方 Tailnet 使用 `devices:core:read` OAuth 凭据，5 分钟同步，成功快照最多有效 15 分钟。
- Headscale 使用原生 `/verify` 实时查询，沿用该版本的设备公钥判断语义。
- 任一已批准且启用的有效来源明确授权即可通过。未知设备和无有效来源的设备被拒绝。
- 每个 derper 强制 `--verify-client-url-fail-open=false`。控制器或本机验证链路故障时拒绝新连接。
- 验证发生在连接建立时；删除网络不能自动踢掉既有连接，重启节点可断开这些连接。
- DERP 验证不保护 STUN；UDP 3478 可以独立开启或关闭。

## 镜像

| 组件 | 镜像 |
| --- | --- |
| 控制器、网页、CLI | `ghcr.io/as214933/derpers-contorller-controller` |
| Agent | `ghcr.io/as214933/derpers-contorller-agent` |
| 官方源码 derper、JSON 参数入口 | `ghcr.io/as214933/derpers-contorller-derper` |

项目镜像支持 `linux/amd64`、`linux/arm64`。main 成功发布不可变 `sha-<完整提交SHA>`，仅当该提交仍是当前 main 时更新 `edge`。版本标签通过独立 release 工作流提升已成功完成 main CI 的同一 manifest 摘要，不重建或覆盖 SHA 标签。稳定 `vX.Y.Z` 更新 `latest` 时比较 SemVer，旧版本和预发布版本不会让 `latest` 回退。生产固定发布摘要；`edge` 便于首次部署验证。上游镜像摘要及源码提交固定在 [deploy/images.env](deploy/images.env)。客户端与 derper 均从同一固定 Tailscale 源码构建，避免假设 Docker Hub 已经发布同名客户端镜像。

## 控制器部署

需要 Linux、Docker Engine、Compose v2、OpenSSL，以及可以给登录用户提供 `groups` 声明的 OIDC 服务。

```bash
bash deploy/bootstrap.sh
# 编辑 deploy/.env：配置 OIDC 和公开 CONTROLLER_URL。
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d
docker compose --env-file deploy/.env -f deploy/compose.yaml logs -f controller
```

引导脚本创建数据库密码、32 字节加密主密钥、节点身份 CA 和短期 localhost TLS 证书，拒绝覆盖现有秘密。默认端口只绑定 `127.0.0.1`，本地证书须显式信任；生产将 `secrets/server.crt`、`server.key` 替换为 `CONTROLLER_URL` 的有效证书，修改绑定地址或通过受控入口转发。节点 mTLS 必须到达控制器原生 TLS listener；普通反向代理终止 TLS 后不能用未经校验的身份头代替客户端证书。

OIDC 回调地址为 `<PUBLIC_URL>/auth/callback`；共用入口时与 `CONTROLLER_URL` 相同。默认管理员组 `derpers-admin`；没有对应组的用户只能管理自己的网络。人工审批默认开启。自动审批模式将所有登录用户提供的 Headscale 视为受信任授权源，启用前应确认 OIDC 用户范围。

如需接入私网 Headscale，在 `HEADSCALE_ALLOWED_CIDRS` 中明确列出允许网段。不要把整个公网和内网全部加入例外。DNS API Key、OAuth Secret、证书私钥加密保存在 PostgreSQL，`MASTER_KEY` 独立备份。

使用自动 DNS-01 签发时必须设置 `ACME_EMAIL`，按 [DNS 与证书配置](docs/operations.md#dns-与-dns-01-证书配置) 准备三家服务商凭据和最小权限；Compose 已传递 `ACME_EMAIL`、`ACME_DIRECTORY`。控制器公开 TLS 证书与 DERP 节点的自动证书分别配置。

CLI 与服务共用校验和审计，例如：

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml exec controller controller network add \
  --name office --kind headscale --url https://headscale.example.com/verify --approve
docker compose --env-file deploy/.env -f deploy/compose.yaml exec controller controller derpmap --format yaml
```

## 节点部署

在管理员网页创建节点，指定地域、域名、端口、DNS 账户以及镜像版本。DNS/ACME 配置完成后申请节点证书，生成一次性注册令牌和部署包。也可使用 [deploy/node-compose.yaml](deploy/node-compose.yaml) 与 [deploy/node.env.example](deploy/node.env.example)。令牌绑定节点，10 分钟过期且只兑换一次；重启后使用已持久化的节点身份。

```bash
mkdir -p /opt/derpers/node /opt/derpers/agent-state
cp deploy/node.env.example deploy/node.env
# 填 NODE_ID、ENROLLMENT_TOKEN、CONTROLLER_URL、绝对宿主路径。
docker compose --env-file deploy/node.env -f deploy/node-compose.yaml up -d
```

Agent 主动连接控制器，通过 Docker API 创建并维护 derper、Caddy。`HOST_CONFIG_DIR`、`HOST_STATE_DIR` 必须与 Agent bind mount 的真实宿主路径一致；控制器下发的 derper 镜像包含 JSON 参数入口，不能换成没有该入口的任意镜像。Agent 独占 Docker socket，节点应使用专用宿主；容器 label 检查用于防止误操作，不能把 Docker socket 当作权限沙箱。

开放配置中的 DERP TLS 端口（默认 TCP 443）；按配置开放 STUN UDP 3478 和 HTTP TCP 80。Agent、Caddy 管理口及验证口无需公开。每节点一个 Region，门户导出官方 Tailnet 策略片段或 Headscale Map；用户将其应用到自己的控制平面。默认保留官方 DERP，可选择只使用平台节点。

Agent 每 15 秒上报状态，60 秒无心跳显示离线；配置失败保留或回滚旧版本，升级使用确定的镜像摘要。证书续期后受控重启 derper，因此现有客户端会重连。

## 真实 E2E 与发布

[CI](.github/workflows/ci.yml) 先检查 Go/网页并在原生 amd64、arm64 runner 各构建一次，再将同一镜像产物用于 443、8443 四组 [真实 E2E](.github/workflows/e2e.yml)。全部通过后，[发布工作流](.github/workflows/publish.yml) 推送这些已经测试过的镜像，核对注册表配置摘要与被测 image ID 一致，并按两个架构的不可变 manifest 摘要组合 GHCR 清单。各最终标签必须得到完全相同的索引；发布阶段不重建镜像，也不通过可变候选标签提升。

[Release](.github/workflows/release.yml) 只处理 `v*` 标签：要求提交属于 main 历史、相同 SHA 的 main push CI 已全部成功、GHCR SHA 清单含两个架构且 OCI revision 一致。发布操作通过同一并发组串行执行；已有版本和 SHA 标签禁止覆盖到不同摘要。应在 main CI 完成后创建版本标签；过早创建的 tag 工作流会失败，待 CI 成功后重跑该工作流。预发布标签使用 `vX.Y.Z-rc.1` 等形式；Docker 不允许 `+`，因此不接受 SemVer build metadata。

每组运行一个控制器/PostgreSQL、真实 Headscale、Agent 创建的 derper/Caddy、两个独立 TUN Tailscale 客户端。测试强制阻断客户端底层 IPv4/IPv6 UDP，实际 Map 只含 `e2e` Region；双向 DISCO 必须至少 3 个 pong，所有 pong 都为 `via DERP(e2e)`，再运行 TSMP 和系统 ICMP。还检查真实未知公钥拒绝、来源禁用、控制器断线、derper 到 Caddy 的传输故障以及恢复。

未知公钥探针读到 `ServerInfoMessage` 才算准入成功；仅 `Connect()` 成功不是最终结果。传输故障单独测试，避免 Caddy 返回 502 时掩盖错误的 fail-open 配置。测试证书和用户密钥每次临时生成，正常校验证书，无生产 Secrets 或关闭 TLS 验证开关。

在 Linux 本地运行：

```bash
DERP_PORT=8443 IMAGE_TAG=test bash e2e/run.sh
# 重用已经构建的当前镜像测试另一端口。
DERP_PORT=443 IMAGE_TAG=test E2E_SKIP_BUILD=1 bash e2e/run.sh
```

要求 `/dev/net/tun`、Docker、Compose v2、OpenSSL、jq、iptables、nsenter 和 sudo。测试只清理自己的 Compose project、网络和卷，脱敏证据保存在 `artifacts/`。手动运行 GitHub 的 **Real DERP E2E** 会自行构建；CI 调用则读取构建 job 的产物。GitHub artifacts 保留 7 天，无论成功失败均收集日志、Map、ping、网络规则、版本和审计。

单 runner 实机测试证明真实协议和容器链路，不证明跨地区公网质量。真实官方 Tailnet OAuth、三家 DNS API 需要账户凭据单独验收。首次 GHCR 发布后须将三个 package visibility 设置为 public，并使用未登录客户端验证匿名拉取；公开代码仓库不会自动让 package 公开。

## 备份、恢复和迁移

参见 [运维说明](docs/operations.md)。数据库、加密主密钥和节点身份 CA 必须一起保护；日志和 E2E artifacts 不能替代备份。现有节点迁移保留域名、端口和 DERP 私钥，验证后逐个切换。

## 监控与启动配置

可选监控配置包含固定摘要的 Prometheus/Grafana、私网采集、基本告警规则和预置仪表盘：

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml -f deploy/monitoring-compose.yaml up -d
```

Prometheus 和 Grafana 默认仅绑定本机 `9090`、`3000`，通过 SSH 转发或认证入口访问。Grafana 管理员密码由 bootstrap 写入 `.env`；禁止匿名访问和自助注册。规则在 Prometheus 中显示告警状态；需要外部通知时由运营者连接自己的 Alertmanager 接收器，配置中不包含虚构通知地址。

[启动配置示例](deploy/controller.example.yaml) 对应 `controller --config /path/config.yaml serve`，环境变量优先于 YAML。`DATABASE_URL`、`MASTER_KEY` 必填；`CONTROLLER_URL` 是 Agent 和 Caddy 使用的 HTTPS 原点，`PUBLIC_URL` 用于网页 OIDC 回调；两者可共用原生 TLS 入口。网页创建的网络、DNS 账户和节点属于 PostgreSQL 运行配置。
