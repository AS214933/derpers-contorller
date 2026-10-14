# 多 Tailnet 共享 DERP 平台实施计划

更新日期：2026-10-14。当前阶段执行本计划：开发完整平台，推送目标仓库，通过真实 E2E 后发布 GHCR。各功能是否完成以实现、测试和交付证据为准。Git 提交和 PR 标题遵守 [CONTRIBUTING.md](CONTRIBUTING.md) 中的 Conventional Commits 约定。

v0.2.0 增量目标：所有控制器接口可通过 `EdgeOne HTTPS → 普通 Nginx 反向代理 → HTTP 控制器`。默认使用基于原节点证书私钥的应用请求签名，控制器本机 TLS 可选；derper 镜像源码、入口、验证 URL 和参数保持不变。交付包含受控源站配置、旧 mTLS 节点迁移方式，以及四组真实双代理 E2E。部署细节见 [EdgeOne 与 Nginx](docs/edgeone-nginx.md)。

## 一、目标、架构与复用原则

构建一个支持多个官方 Tailnet 和多个独立 Headscale 的共享 DERP 平台。各控制平面独立管理设备，平台统一执行 DERP 准入，并提供 OIDC 门户、管理员审核、节点运维、DNS、证书和监控。

| 部分 | 选定实现 |
| --- | --- |
| 网页 | React、TypeScript、Vite、Ant Design，中文用户门户与管理后台 |
| 控制器 | 一个 Go 服务，包含管理 API、准入、授权同步、节点任务、DNS、证书和审计模块 |
| 存储 | PostgreSQL 保存运行配置、加密凭据、节点、任务、审计及快照元数据；授权热数据使用内存 |
| 节点 | Docker Compose 部署官方 derper、标准 Caddy、轻量 Agent 三个容器 |
| 登录 | 复用 go-oidc 与 OAuth 库；使用 OIDC groups 判定管理员 |
| DNS / ACME | 服务商 SDK 管理记录；lego 完成 DNS-01 申请和续期 |
| 运维 | Docker Engine API、Prometheus、Grafana、Docker logging |

后端和集中控制器作为一个服务交付。第一版采用单实例控制器，不引入 Redis 或 Kubernetes。Agent 管理 derper 和 Caddy 的配置、证书、启停、升级、状态与近期日志；设备准入由控制器决定。

公开中继 TLS 由官方 derper 直接处理，使用原生手动证书模式和可配置监听端口。Caddy 提供节点内部验证请求转发，以及公网 80 端口的 HTTP 探测。这样不把 Caddy 前置中继反向代理作为生产必需路径；后台分发的证书仍由 Agent 管理。

起步依赖固定为 Headscale v0.29.5、Tailscale / derper v1.104.1、Caddy v2.11.7。它们是本次查到的已发布版本，组合兼容性由下述真实 E2E 验收。开始实现时记录基础镜像摘要；随后依赖升级以单独提交重跑完整 CI，不使用浮动 latest 选择测试版本。

依据：[Headscale 发布版](https://github.com/juanfont/headscale/releases/tag/v0.29.5)、[Tailscale 发布版](https://github.com/tailscale/tailscale/releases/tag/v1.104.1)、[Caddy 发布版](https://github.com/caddyserver/caddy/releases/tag/v2.11.7)、[derper 手动证书实现](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/derper/cert.go)。

## 二、门户、权限、准入与对外接口

### 门户与审批

- 使用 issuer + sub 作为用户身份。从验证过的 OIDC 声明读取 groups；声明名称和管理员组名可配置，缺失匹配组时为普通用户。
- 用户管理自己的 Tailnet / Headscale 申请、凭据、接入状态、配置下载及删除操作；管理员审核所有网络，管理节点、DNS 账户、审批模式和审计。
- 提供全局人工审核 / 自动通过开关，默认人工审核。自动模式适用于所有 OIDC 登录用户，通过接入检查后启用。该模式将这些用户及其 Headscale 视为可信授权提供者。
- 审批状态使用 pending、approved、rejected、disabled；来源健康与审批状态分别展示。授权源关键身份或地址变更重新测试并按当前审批规则处理。
- 第一版所有启用网络共享所有已发布 DERP 节点；门户不提供按租户计费、配额或设备精确踢出。

### 授权来源与决策

- 官方 Tailnet 使用 OAuth Client ID / Secret 和设备只读权限 devices:core:read。启用时立即同步，此后每 5 分钟同步一次；按有效 nodeKey、authorized、设备到期状态筛选，排除外部共享设备。
- 每次成功获得完整设备列表后原子替换该来源快照；授权有效期不超过最后成功同步后 15 分钟，且未禁用设备密钥到期时还受设备到期时间限制。同步失败不延长快照，重启后重新同步。
- Headscale 使用原生 POST /verify，按明确的 Allow 结果实时判断，不保存正向授权缓存。该接口以所接版本的 Node Key 注册状态为准，不能将它解释为额外执行了设备到期或标签策略。
- 请求先查官方有效缓存，未命中时并发验证 Headscale。任一已批准且启用的有效来源允许即可通过；未知设备、来源异常且无其他明确授权时拒绝。
- 禁用、删除或改变来源关键配置时，立即失效对应授权；在途验证和同步结果提交前检查来源版本，防止已撤销来源重新写回缓存。
- 控制器未就绪、数据库无法提供有效策略、网络异常或验证响应错误时拒绝新连接。derper 强制配置 --verify-client-url-fail-open=false，使用外部验证接口，不启用本机 tailscaled 验证。
- 准入使用上游 DERPAdmitClientRequest / Response：NodePublic、Source，响应 Allow。正常拒绝返回 HTTP 200 + Allow=false；格式错误返回 400；内部不可用返回 503。接受原生请求缺少 Content-Type，按 HTTP 状态和 JSON 内容解析 Headscale 响应；后台总时限 3 秒，请求体上限 4 KiB。
- 撤销在新建连接时生效。现有连接沿用官方生命周期，运维重启可以断开；没有定时重验或自研设备踢出协议。
- 用户提交的 Headscale URL 实施 SSRF 防护：有效 HTTPS、连接时校验实际解析地址、限制重定向；私网范围由管理员明确允许。公网部署使用标准 TLS 验证，内部 CA 通过专用信任配置接入。

依据：[derper 参数](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/derper/derper.go)、[官方验证协议](https://github.com/tailscale/tailscale/blob/v1.104.1/tailcfg/derpmap.go)、[Headscale 验证实现](https://github.com/juanfont/headscale/blob/v0.29.5/hscontrol/handlers.go)、[Tailscale 设备只读权限](https://tailscale.com/docs/reference/trust-credentials)。

### 接口与 DERP Map

| 接口 | 用途与身份要求 |
| --- | --- |
| /auth/* | OIDC 登录、回调、退出 |
| /api/v1/networks/* | 本人网络管理，审批和全局管理要求管理员 |
| /api/v1/nodes/* | 节点配置、部署包、注册令牌、重启和升级；仅管理员 |
| /api/v1/dns-accounts/* | DNS 账户和域名后缀；仅管理员 |
| /api/v1/node-enroll | 标准 HTTPS 下兑换一次性注册令牌并提交 CSR |
| /node/v1/* | 获取配置、任务、证书和上报状态；每节点证书认证 |
| /admission/v1/verify | 上游 DERP 验证协议；每节点证书认证 |
| /derpmap.json | 已发布节点的公共连接信息，无凭据 |
| /healthz、/readyz | 控制器存活与依赖就绪，响应不含配置和秘密 |
| 内部 /metrics | 监控指标，限制访问 |

管理网页采用 OIDC，节点 API 和准入 API 默认采用 `NODE_AUTH_MODE=proof`，可与网页共用 EdgeOne HTTPS 域名。Agent 以原节点证书私钥生成短时 JWS，置于 `Authorization: DerpersProof ...`；绑定请求方法、原始 URI、请求体摘要和公开原点。控制器独立验证节点证书、签名、启用状态及防重放 nonce，不信任转发证书身份头。请求签名有效窗口 60 秒、允许时钟偏差 15 秒，代理不得改写请求或缓存响应。控制器还提供使用本机配置和数据库权限的管理 CLI，复用管理校验和审计。

默认控制器仅 HTTP 8080，节点 CA 签发材料仍必需；本机服务端证书和 TLS listener 可选。`hybrid` 只用于受控迁移，兼容真实 native mTLS 和应用签名，不能把普通代理的转发头当作 mTLS。先保留旧直连入口升级 Agent，再切换 CDN URL，全部升级后切 proof 并关闭旧 TLS。公开跨网络回源应在 Nginx 终止普通 HTTPS，受控私网回源可使用 HTTP。

门户导出官方 Tailnet 的 derpMap 策略片段，以及 Headscale 使用的 JSON URL / YAML。默认保留官方 DERP，导出时可选平台专用模式。第一版每节点一个稳定 RegionID，分配 900–999，正确生成 HostName、DERPPort、STUNPort、CanPort80。新节点通过检查后才发布；临时离线与发布状态分开。用户将配置应用到自己的控制平面；设备只读 OAuth 不自动修改其策略。

## 三、节点、DNS、证书与运维行为

- 管理员录入名称、地域、公网地址、DNS 账户、域名后缀、HTTPS / STUN 端口后生成部署包。节点默认 HTTPS 443/TCP、STUN 3478/UDP，支持改端口及关闭 STUN；HTTP 探测固定 80/TCP，可单独关闭。
- 公开 DERP 流量直接进入 derper；验证 URL 仍为 `http://caddy:9080/verify`，Caddy 转发到 Agent 私网 `:9081` relay，Agent 签名后通过公开 HTTPS 控制器入口请求准入。derper 的参数与协议不改。Caddy 的 80 端口只转发受支持的探测路径；Agent relay、内部验证、管理和采集端口不发布公网。
- 注册令牌绑定一个节点、单次使用、10 分钟过期；Agent 本机生成身份私钥并提交 CSR。证书自动续期，节点禁用状态使未过期证书也不能调用节点 API。Agent 主动访问后台，无公网管理端口。
- Agent 通过 Docker Engine API 只管理带本节点归属标签的 derper 和 Caddy。Docker socket 仅提供给 Agent，远程任务限于应用配置、读取状态/日志、重启和升级指定组件。
- 每 15 秒心跳，60 秒无心跳标记管理通道离线；另行展示中继健康。配置使用版本号，任务使用唯一 ID；重复投递不重复执行。应用前验证配置，失败保留或恢复上一个有效版本。
- 镜像升级按摘要执行，单节点健康检查失败回滚。证书写入使用原子替换；derper 证书续期后按受控重启加载，后台明确显示重连影响，并错开不同节点的操作。
- 旧节点迁移保留域名、端口和 DERP 私钥；检查镜像是否支持必须的验证参数。不符合要求时先迁移到平台提供的固定版本镜像。
- 首版支持 Cloudflare、阿里云 DNS、腾讯云 DNSPod。按服务商显示对应 Token / AccessKey / SecretId 等字段，为账户指定 DNS Zone 和后缀；按节点名生成域名。
- DNS 记录归属入库，只更新或删除平台管理的 A/AAAA，冲突时报告；Cloudflare 使用 DNS only。每个 DNS 账户独立实例化客户端，避免通过进程级环境变量切换并发账户凭据。
- 控制器复用 lego，通过 DNS-01 为每节点申请独立证书；每天检查，剩余有效期进入总有效期最后三分之一时续期。失败保留尚有效旧证书并告警；每节点仅能获取自己的材料。
- DNS / OAuth 凭据和证书私钥加密入库，主密钥从部署 Secret 提供。YAML 保存启动配置，网页运行配置入 PostgreSQL。备份包含数据库及独立保护的主密钥、节点 CA 恢复材料。
- Prometheus / Grafana 复用现成监控；`/metrics` 要求独立 Bearer 令牌或管理员会话，Nginx 公共入口拒绝该路径，Prometheus 私网采集并只读挂载令牌文件。记录准入、同步、审批和节点任务审计，默认保留 30 天。代理日志不含 Authorization、Cookie、令牌和请求体；后台按需获取近期日志并脱敏。

## 四、GitHub 交付与 GHCR 发布

代码交付仓库固定为 https://github.com/AS214933/derpers-contorller，默认分支 main。开发完成并通过本地可执行检查后推送代码，由 GitHub Actions 执行发布前 CI。空仓库首次初始化 main，后续功能改动通过 PR。

| 项目镜像 | GHCR 地址 |
| --- | --- |
| 控制器，包含网页构建产物与管理 CLI | ghcr.io/as214933/derpers-contorller-controller |
| Agent | ghcr.io/as214933/derpers-contorller-agent |
| 固定官方源码构建的 derper，无协议修改 | ghcr.io/as214933/derpers-contorller-derper |

Caddy、PostgreSQL 和 Nginx 引用上游标准镜像并固定摘要。Nginx 使用已核实的 stable 1.30.5 多架构索引。上述三套项目镜像发布 linux/amd64 和 linux/arm64；加上 source、revision、version 等 OCI 标签。GHCR 包关联目标仓库并设为 public，首次发布后验证匿名拉取；GitHub 的新包默认私有，不能只依据仓库公开就认为镜像公开。v0.2.0 的 derper 源码与验证参数保持原组合不变。

使用四个工作流职责：

- ci.yml：PR 和 main 推送时运行 Go 检查/测试、网页类型与构建检查、镜像构建，并调用真实 E2E；仅在可信 main 且所有检查通过后调用发布。
- e2e.yml：可复用且支持 workflow_dispatch，运行下一节真实服务测试，默认不依赖生产 OAuth、DNS 或 OIDC Secrets。
- publish.yml：可复用发布工作流，用 GITHUB_TOKEN 与 packages:write 发布 GHCR。PR 测试使用 contents:read，fork PR 无发布权限；第三方 Actions 固定完整 commit SHA。
- release.yml：v* 标签只提升对应提交已通过 main CI 的镜像摘要，校验来源、架构及版本顺序，不重新构建。

每个架构构建一次，镜像归档供对应 E2E 和发布复用；发布阶段直接推送测试通过的镜像产物，不重新构建替换它。两个端口矩阵复用相同架构产物。生成多架构清单后再次检查标签、摘要、架构和镜像来源信息。

标签规则：main 成功生成 edge 和 sha-<完整提交 SHA>。版本标签从该提交已通过 CI 的不可变 SHA 镜像提升摘要，不重新构建；稳定 vX.Y.Z 生成对应版本，latest 仅向更高稳定版本移动；预发布只生成自身版本。发布串行执行，edge 仅在远端 main 仍指向被测提交时更新。部署示例使用明确版本，生产升级使用摘要。交付同时提供 README、控制器/节点 Compose 示例、配置参考、备份恢复和 E2E 本地运行说明。

依据：[GitHub Actions 发布镜像](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)、[GHCR 身份、仓库关联与默认可见性](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)。

## 五、真实 E2E、发布门槛与实施顺序

### 环境与执行方式

在 GitHub Ubuntu VM 上启动真实服务，而非验证 API 的替身：

1. 一套本提交构建的 HTTP-only 控制器与 PostgreSQL；两个真实 Nginx 分别终止公开 TLS、转发 HTTP 源站请求，模拟 CDN 与普通反向代理。
2. 一个固定发布版 Headscale，关闭内嵌 DERP，配置仅含测试节点的 DERP Map。
3. 一个完整 DERP 节点：本提交 derper、标准 Caddy、本提交 Agent。
4. 两个固定版本 Tailscale 客户端，各自独立状态目录、容器网络命名空间、TUN 设备和所需网络权限。

默认矩阵为 ubuntu-24.04 / ubuntu-24.04-arm 两种原生架构，以及 443 / 8443 两种 DERP TLS 端口，共四组。每组最长 25 分钟；每个就绪/传播等待有独立上限并输出失败状态，不能以无界重试掩盖错误。Docker 镜像保存/加载兼容性在 runner 预检，必要时按已核查的 Docker 版本固定存储驱动。

每组运行时生成临时 CA、正确 SAN 的服务证书、节点注册令牌和 Headscale preauth keys；客户端与服务显式信任测试 CA。客户端不使用 InsecureForTests 或关闭 TLS 验证。用 CLI 导入测试来源及材料，仅为测试 Docker 网段明确允许 Headscale，再走真实 Agent 注册、配置、任务、上报、续期及准入签名路径。控制器 TLS_ADDR 留空，确认其 native TLS 端口无 listener；两级代理日志分别断言 HTTPS 与 HTTP 成功请求。测试身份 TTL 为 5 分钟以触发实际续期，生产默认 7 天。CI 不使用生产 EdgeOne 凭据，实际 EdgeOne 缓存、挑战与回源网络、ACME / 公网 DNS 单独验收。

### 正向路径与必须断言

1. 启动 PostgreSQL 和控制器，通过 CLI 创建节点及导入测试证书。Agent 使用单次令牌注册，获取配置，实际启动/协调 derper 和 Caddy。确认配置版本、心跳及 TLS 探测，发布节点并导出仅含该节点的 DERP Map。
2. 使用已导出的有效 DERP Map 启动 Headscale（避免空 Map 引导失败），创建用户和两个注册密钥，按正常校验启用 Headscale 授权源。
3. 两个客户端在 tailscaled 启动前安装容器内网络规则，拒绝底层网卡的 UDP 直连流量，保留 DNS。覆盖 IPv4 / IPv6。生产客户端不设置测试调试开关。
4. 两客户端登录同一 Headscale，等待双方出现在各自 peer 列表；检查实际收到的 DERP Map 仅含 RegionID=900、RegionCode=e2e 及本矩阵端口，无公共 DERP 或 peer relay 后备。
5. A 到 B、B 到 A 分别运行 tailscale ping --until-direct=false --c=5 <对方 Tailscale IPv4>。每次断言至少 3 个成功响应且所有成功响应都包含 via DERP(e2e)，发现 direct、peer-relay 或其他 Region 即失败。
6. 双向执行 tailscale ping --tsmp 验证 WireGuard 内部数据通信，再用系统 ping -c 3 验证 TUN / IP 通信。由前述网络限制和唯一 DERP Map 保证相同中继路径。
7. 同时检查控制器有两个公钥的允许审计、来源为本次 Headscale，DERP 连接/中继计数随测试增长。不能只以 CLI 返回码或容器 healthy 判定成功。
8. 通过管理服务创建日志任务，等待 Agent 拉取并上报 succeeded；等待真实 node identity 续期审计。两级代理日志对 enroll/config/tasks/report/renew/admission 分别记录成功状态、协议、签名存在标记及 no-store，不记录签名值；Origin Nginx 和 controller 之间无 TLS 客户端证书。

普通 tailscale ping 默认使用 DISCO 并可能转向直连；TSMP 和系统 ICMP 分别进一步覆盖加密隧道与操作系统网络路径。因此路径断言和真实网络限制必须一起存在。

### 反向路径与恢复

| 场景 | 注入方式 | 通过条件 |
| --- | --- | --- |
| 未知公钥 | 使用官方 DERP 客户端库生成临时密钥，发起真实 DERP 握手并读取协议消息 | TLS/HTTP 升级正常后连接关闭，没有 ServerInfo，控制器记录同一公钥 Allow=false；单凭 Connect 返回不能认定已准入，超时或基础设施错误不算通过 |
| 网络禁用 | 经控制器管理服务禁用该 Headscale 来源，随后重启 derper 断开已有连接 | Headscale 仍在线、客户端仍有 peer 信息，但新 DERP 准入被拒绝，互 ping 失败 |
| 控制器不可达 | 停止控制器，重启 derper 强制新握手 | DERP / TLS 服务仍正常，准入报错且互 ping 失败，没有 fail-open |
| 验证传输失败 | 保持 Caddy 和控制器运行，在 derper 网络命名空间阻断到 Caddy 验证端口的 TCP，主动断开两客户端原 DERP 连接 | derper 的 HTTP 请求发生真正传输错误，仍拒绝客户端；Caddy 返回 502 不能单独证明 fail-open=false |
| 故障恢复 | 恢复来源或控制器，等待重新就绪 | 两客户端重新通过 DERP 双向通信 |
| 内部接口隔离 | 访问公开调试路径，并检查管理/验证端口的外部连通性及 Docker 端口映射 | 调试请求被拒绝，内部端口未发布，内部采集仍正常 |
| 代理身份边界 | 公开入口发送未签名请求和伪造客户端证书转发头，访问 metrics | 节点/准入请求拒绝，metrics 不公开；私网令牌采集正常 |

安全用例必须主动关闭原连接再测试，不能要求官方 derper 在控制器故障时自动踢掉旧连接。每个故障前后检查已授权基线，故障期间检查 TLS、实际 DERP Map、客户端 daemon 和 peer 信息仍正常；命令、socket、证书及 peer 故障不得算作拒绝成功。不能靠删除 Headscale 设备作为唯一撤销测试，因为那会同时改变客户端 peer 信息。

### 证据、清理与覆盖边界

- 无论成功或失败都收集脱敏的两级 Nginx、控制器、Agent、derper、Caddy、Headscale、客户端日志，双向 ping 输出、status/netcheck/DERP Map、网络规则计数、镜像 ID、任务结果、身份续期审计、配置版本和各阶段结果。
- 在 Actions Summary 输出用例、架构、端口、耗时、镜像标识及失败原因；上传脱敏 artifacts，保留 7 天，不上传私钥、令牌、完整数据库或含秘密的 Compose 渲染结果。
- 始终清理本次 Compose project、网络和卷；不清理 runner 上无关资源。E2E 失败阻止该提交的 GHCR 发布。
- 此闭环验证一个 Headscale、一个 DERP 和两真实客户端；单 runner 不证明跨地区公网质量。多来源 OR、官方 OAuth 同步、缓存失效、OIDC 权限和 DNS 适配另有契约/集成测试，真实官方 Tailnet 与 DNS API 需要专用测试凭据后再验收。

实施顺序调整为：先完成最小控制器准入 API、管理 CLI、Agent 注册/应用配置，以及官方组件真实 DERP 通信闭环并建好 E2E；再实现 OIDC 门户、审批与多来源准入；接着完成 Agent 升级/回滚、三家 DNS 和 ACME、监控及迁移；最后将本地已检查的代码推送目标仓库，由 GitHub Actions 运行完整矩阵，全部通过后发布 GHCR。完成标准是源码、可拉取镜像、部署文档、可复现 E2E 和失败证据均齐备。

依据：[Headscale 的真实 Docker 集成测试方式](https://github.com/juanfont/headscale/blob/v0.29.5/integration/README.md)、[Tailscale ping 实现](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/tailscale/cli/ping.go)、[官方 Docker 客户端](https://tailscale.com/docs/features/containers/docker)、[GitHub 原生 x64 / ARM64 runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。
