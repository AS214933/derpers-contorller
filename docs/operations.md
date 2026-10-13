# 运维与恢复

## DNS 记录恢复

正在服务的节点更新证书后，控制器等待 Agent 确认配置版本及新鲜 TLS 探测，最多等待两分钟，并在处理下一个节点前至少间隔 20 秒。未确认应用会产生独立审计与告警，已签发证书保留供恢复；任务 ID 随证书材料一同持久化，控制器重启不会重复签发已经完成的同一任务。

DNS 服务商更新记录与数据库保存所有权无法组成同一事务。外部更新成功后若控制器中断，后续任务会报告冲突并停止自动修改。管理员应在服务商控制台核对节点域名、A/AAAA 值及记录 ID，再从节点页面显式认领这些记录；已有所有权的认领会刷新当前记录基线。平台拒绝认领另一节点已经管理的记录。

修改节点域名或 DNS 账户前，先取消发布并清理该节点管理的 DNS 记录。证书准备、记录认领、清理、节点编辑和删除按节点及 DNS Zone 串行执行，繁忙时返回冲突供稍后重试。

## 备份

在变更 DNS、升级或迁移前备份 PostgreSQL。将 `deploy/.env` 中的 MASTER_KEY、OIDC/DNS 凭据保管策略，以及 `deploy/secrets/node-ca.crt`、`node-ca.key` 单独加密备份；丢失主密钥将无法解密数据库里的网络和证书凭据。不要上传这些文件到 Git、Actions artifacts 或工单。

```bash
umask 077
docker compose --env-file deploy/.env -f deploy/compose.yaml exec -T postgres \
  pg_dump -U derpers -d derpers -Fc > derpers-backup.dump
```

恢复时停止 controller，建立空数据库并执行 `pg_restore --clean --if-exists`，恢复原 MASTER_KEY 和节点 CA 后启动相同版本控制器，确认 `/readyz`、源同步、节点心跳再恢复公开入口。先在隔离机器验证备份可恢复；官方来源内存快照重启后重新同步，未取得新快照前不能授权。

## 升级与回滚

部署示例默认 `IMAGE_VERSION=v0.1.0`。生产在 `deploy/.env` 设置完整的 `CONTROLLER_IMAGE`、`AGENT_IMAGE`、`DERPER_IMAGE` 引用，如 `ghcr.io/as214933/derpers-contorller-controller@sha256:<已核实的发布索引摘要>`；这些值优先于版本标签，留空时使用 `IMAGE_VERSION`。控制器同时使用覆盖后的 Agent/derper 引用生成节点配置和部署包；手工使用节点 Compose 时，将相同的 `AGENT_IMAGE` 写入 `deploy/node.env`。

通过管理员节点任务指定镜像摘要升级。先一个节点，检查配置版本、准入错误、两客户端中继通信，再升级其余节点。Agent 自动回滚失败的组件升级；控制器数据库迁移前保留备份，在需要数据库回退时用匹配版本和备份恢复，不能只更换旧镜像假设数据库向后兼容。

续期 DERP 证书会受控重启节点，现有连接会重连；错开地域节点，观察失败审计和证书剩余期限。来源同步失败不会延长官方设备快照 15 分钟时限。

## 旧节点迁移

保留原域名、TLS/STUN 端口及 derper 的 `-c` 私钥文件；先检查新镜像和控制器验证链路。准备 Agent 目录时将原私钥放入其 `derper-state/derper.key`，停止旧容器释放端口后启动 Agent 管理的节点。验证来源允许和未知密钥拒绝，再把节点发布到 Map。失败则停新节点、恢复旧部署；旧部署也必须显式关闭 fail-open。

## 监控与日志

控制器 `/metrics` 限制访问，Prometheus 通过可信私网采集；后台显示节点 CPU/内存/流量、连接与中继计数、心跳和错误。Agent 在 derper 网络命名空间内部通过正确 SNI/CA 读取受保护 metrics，不公开调试入口。审计默认保留 30 天；Docker 日志应配置轮转，避免磁盘耗尽。

STUN 为独立 UDP 服务，按环境决定是否开放。准入来源失效首先影响新连接；需要立即撤销所有既有连接时执行节点重启并记录影响。控制器单实例不可用会拒绝新准入，既有连接遵循官方生命周期。

## DNS 与 DNS-01 证书配置

在 `deploy/.env` 配置真实 `ACME_EMAIL`。初次验证可将 `ACME_DIRECTORY` 改为 `https://acme-staging-v02.api.letsencrypt.org/directory`，确认权限与 TXT 传播后再切换生产目录。Staging 证书不受普通 Tailscale 客户端信任，不能作为生产上线验收；不要为此关闭客户端 TLS 检查。[Let's Encrypt Staging](https://letsencrypt.org/docs/staging-environment/)

管理员在 DNS 账户页面选择服务商、实际托管 Zone（例如 `example.com`）和节点后缀（例如 `derp.example.com`），填写该账户凭据。系统同时需要管理节点 A/AAAA 与 `_acme-challenge.<节点域名>` TXT 记录。Zone 必须确实由该服务商托管，NS 委派和公网 DNS 查询须可达。

| 服务商 | 网页/管理 API 凭据字段 | 此实现调用的最小动作集合 |
| --- | --- | --- |
| Cloudflare | `api_token` | Zone Read、DNS Edit，限定实际 Zone；不使用 Global API Key |
| 阿里云 DNS | `access_key_id`、`access_key_secret` | `alidns:DescribeDomains`、`alidns:DescribeDomainRecords`、`alidns:AddDomainRecord`、`alidns:UpdateDomainRecord`、`alidns:DeleteDomainRecord` |
| 腾讯云 DNSPod | `secret_id`、`secret_key` | `dnspod:DescribeDomainList`、`dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:ModifyRecord`、`dnspod:DeleteRecord` |

上表由本项目的记录管理实现与固定版本 lego 适配器所调用的方法合并得到。使用独立 RAM/CAM 子用户，按服务商当前支持的资源级授权将变更动作限定到目标域名；域名发现的只读动作若必须使用账户级资源，应保留只读权限，不能因此授予账户管理员权限。Cloudflare 单 Token 同时拥有目标 Zone 的读取与 DNS 编辑权限即可。[Cloudflare 适配器](https://go-acme.github.io/lego/dns/cloudflare/)、[阿里云适配器](https://go-acme.github.io/lego/dns/alidns/)、[腾讯云适配器](https://go-acme.github.io/lego/dns/tencentcloud/)

Cloudflare A/AAAA 使用 DNS only。冲突的外部记录不会被直接覆盖；已存在的合法节点记录通过管理员的 DNS 记录导入流程登记归属，再由平台管理。删除或迁移时使用平台登记的记录 ID 清理，避免删除同域名下他人创建的记录。

节点页面选择 DNS 账户和合法域名、填写公网 IP 后执行 provision，查看任务及审计中的 DNS/ACME 结果。成功签发后 Agent 获取自己的证书、应用新版本并报告健康，再发布节点。凭据只保存在控制器的加密存储中，不分发给节点。自动续期每天检查；失败保持尚有效的旧证书，并由 Prometheus 的证书期限/签发失败规则提示。
