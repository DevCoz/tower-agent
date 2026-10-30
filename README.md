# Tower Agent v3

Tower Panel 协议 4 的 Linux 执行器。一个 Agent 管理一台服务器的服务，全程使用结构化任务，无远程 shell 接口。

| 协议 | 执行程序 |
| --- | --- |
| Snell V5 / V6 | 官方 v5.0.1 / v6.0.0rc2 |
| Shadowsocks AEAD 2022 AES-128 / AES-256 | sing-box 1.14.3 |
| Trojan / AnyTLS | sing-box 1.14.3 + Agent 管理的 TLS 证书 |

## 安装

需要 Linux amd64/arm64、root、systemd 247+、CA 证书、curl 或 wget、sha256sum。在面板“服务器”创建连接并执行生成的命令，在隐藏输入提示中粘贴专用 Agent 令牌。

```sh
sudo ./tower-agent-linux-amd64 install --url 'https://YOUR-PANEL.example' --id 'YOUR-SERVER-UUID'
```

安装先验证 HTTPS 面板和协议 4，再安装 Agent 自身。代理运行程序在首个服务任务中按需下载并校验固定 SHA-256，未知版本、架构或用户提供的下载地址不被接受。

[v3.0.0 已发布](https://github.com/DevCoz/tower-agent/releases/tag/v3.0.0)，产物来自通过原生 Linux amd64 / arm64 验证的 CI。执行 node scripts/build.mjs v3.0.0 只生成本地产物；正式发布由手动触发的 CI 在两种架构验证通过后完成。

## 生命周期

服务统一为 tower-proxy-<uuid>.service，私有配置在 /var/lib/tower-panel/services/<uuid>/。服务以 DynamicUser 运行，配置和 TLS 私钥通过 LoadCredential 读取。Agent 程序位于 /opt/tower-agent/tower-agent，连接配置位于 /etc/tower-agent/config.json。

创建和更新先检查输入、受管 unit/config 归属、端口和候选配置，再启动并检查进程与本地 TCP/TLS。Snell 使用严格生成的 INI；sing-box 候选运行 check 子命令。失败更新恢复原配置；重复任务核对摘要及健康后直接回报，不重复重启。

每 15 秒轮询，任务租约 15 分钟。回报包含任务 ID、修订和租约；命令诊断不回传，防止泄露密码。卸载确认服务停止后移除 unit、配置、证书和专用 ACME 资料。

仅支持协议 4。旧协议、旧 instances 目录与 tower-sing-box 单元不会自动接管，仅对新安装的面板和新节点执行结构化任务，不提供旧环境迁移。

## 证书

自签证书由 Go crypto 生成，续期复用私钥。ACME 使用主机已安装的 certbot，域名须解析到该服务器且 TCP 80 空闲可达。Agent 不自动安装系统依赖、修改 DNS 或防火墙。

约每 6 小时检查每个证书，剩余 30 天内续期。单次轮询最多处理一个证书。证书不变不重启；失败恢复原文件并上报 renewal_failed。TLS 健康检查校验证书名称、有效期，并比较本地握手指纹。面板不接收证书私钥。

域名和签发模式在服务创建后固定；修改这些身份字段需创建新服务。

## 开发与验证

```sh
go test ./...
go vet ./...
node scripts/build.mjs v3.0.0
```

构建使用 go.mod 指定版本，CGO_ENABLED=0，输出两个架构二进制、install.sh、manifest.json、checksums.txt。模板 scripts/install.sh.in 不可直接运行。

CI 在 Ubuntu 上执行 race 测试和四协议真实 systemd 创建/更新/回滚/卸载测试。仅在隔离 Linux runner 显式设置 TOWER_SYSTEMD_TEST=1 运行这些测试。Windows 本地单元测试不能替代 systemd 集成验证；ACME 的公网 DNS/HTTP-01 需要单独的可达测试环境。

```sh
sudo systemctl status tower-agent
sudo journalctl -u tower-agent
sudo systemctl status tower-proxy-<uuid>
```

GPL-3.0；参阅 LICENSE。
## 持久任务

任务携带 taskId、节点 revision、租约、精确运行版本和配置摘要。`/etc/tower-agent/tasks/` 保存任务摘要、结果及最高 revision，`pending-report.json` 保留待确认回执；均不保存服务密码。相同任务重新投递时返回已保存结果，旧 revision 被拒绝。更新期间 recovery.json 保存原 unit，供进程重启后的失败恢复使用。

阶段回报为 running、verifying、rolling_back。最终失败仅在原配置和本机健康都确认后标记 restored。服务主动回滚由面板发送新的 update 任务完成。
