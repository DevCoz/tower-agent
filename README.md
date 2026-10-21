# Tower Agent

Tower Panel 的独立 Linux Agent，通过 GitHub Releases 分发 Go 静态二进制。

通过专用 Agent 令牌连接面板，管理隔离的 sing-box 实例：创建、修改、失败回滚、删除，以及任务结果上报。只支持 Shadowsocks AEAD 2022 AES-128-GCM / AES-256-GCM。

## 安装

要求 Linux amd64 / arm64、root 权限、正在运行的 systemd 247+、CA 证书、curl 或 wget，以及 sha256sum。sing-box 默认下载固定的 1.14.3 并校验官方 SHA-256；也可自行预装 1.14.3+。

在 Tower Panel 的 Agent 页面生成连接信息，执行页面命令。通用格式：

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/DevCoz/tower-agent/releases/latest/download/install.sh -o tower-agent-install.sh &&
sudo sh tower-agent-install.sh install --install-sing-box --url 'https://YOUR-PANEL.example' --id 'YOUR-AGENT-UUID'
```

在终端隐藏输入提示处粘贴专用 Agent 令牌。不要把面板管理员密码、Cloudflare 或 GitHub 凭据填入此处。安装器先通过 `/api/agents/:id/probe` 验证令牌，再安装服务；不会在探测时领取任务。

## 运行与更新

```sh
sudo /opt/tower-agent/tower-agent version
sudo systemctl status tower-agent
sudo journalctl -u tower-agent -f
```

需要更新时重新运行指定 Release 的安装脚本。更新前下载、校验二进制；替换失败时恢复原 Agent 文件。需要轮换连接令牌时，在面板选择“重新连接”并重新执行安装命令。

| 内容 | 路径 |
| --- | --- |
| Agent 程序 | `/opt/tower-agent/tower-agent` |
| Agent 配置（权限 0600） | `/etc/tower-agent/config.json` |
| 服务 | `tower-agent.service` |
| 专用 sing-box | `/opt/tower-agent/sing-box-1.14.3/sing-box` |
| 实例配置 | `/var/lib/tower-panel/instances/<uuid>/config.json` |
| 实例服务 | `tower-sing-box-<uuid>.service` |

实例以 systemd DynamicUser 运行，通过 LoadCredential 读取密钥。更新先检查候选配置，启动失败时恢复原配置；删除先确认服务停止，再移除受管文件。Agent 不会覆盖内容不匹配的服务或配置。对面板的 Bearer 请求不跟随重定向，日志不输出令牌、密钥或命令诊断内容。

通信使用 Tower Agent 协议 2，每 15 秒轮询；没有入站监听端口。每台宿主安装一个 Agent，开放实例所需的 TCP / UDP 端口。

## 开发与发布

构建需要 `go.mod` 指定的 Go 版本及 Node.js 22+；运行服务器无需这些工具。

```sh
go test -race ./...
go vet ./...
node scripts/build.mjs v1.0.0
```

构建使用 `CGO_ENABLED=0`，输出 amd64 / arm64 静态二进制、含固定校验值的 `install.sh`、`manifest.json` 及 `checksums.txt`。`scripts/install.sh.in` 是模板，不能直接用作安装脚本。

CI 在临时目录验证任务、安装回滚和下载校验，并在独立 Ubuntu runner 上使用真实 systemd / sing-box 验证实例生命周期。标签 `vX.Y.Z` 触发同样检查，成功后才发布 GitHub Release。

安装与二进制分发方式参考 [cfsm-agent](https://github.com/huilang-me/cfsm-agent)；Tower 的实例编排与通信逻辑独立实现。

## 许可证

使用 GPL-3.0 许可证，完整条款见 [LICENSE](LICENSE)。
