# 宝塔证书续签器

用于批量管理多个宝塔面板站点证书的终端工具。工具会先对站点域名执行 HTTP-01 webroot 预检，只对公网可验证的域名执行续订或新申请，避免单个不可验证域名拖垮整站证书操作。

支持 Let's Encrypt 和 LiteSSL 免费证书。LiteSSL 需要宝塔面板 11.5.0 或更新版本。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -e .
```

## 配置

复制示例配置：

```powershell
Copy-Item baota.example.ini baota.ini
```

编辑 `baota.ini`，每个 `[panel.*]` 表示一个宝塔面板：

```ini
[panel.prod-a]
url = https://1.2.3.4:8888
api_key = xxxxxxxxx
verify_ssl = false
timeout = 15
```

要求：

- 宝塔面板已开启 API。
- 宝塔 API 白名单已放行运行本工具的 IP。
- `url` 必须和面板实际协议一致，HTTP 面板不要写成 HTTPS。

## 常用命令

默认读取当前目录的 `baota.ini`。需要指定其他配置文件时，加 `--config <path>`。

查看证书、站点域名和证书覆盖状态：

```powershell
btr cert status
```

执行证书申请/续订预检，不提交任何变更：

```powershell
btr cert plan
```

演练完整申请/续订流程，不提交到宝塔：

```powershell
btr cert apply --dry-run
```

正式执行证书续订或新申请：

```powershell
btr cert apply
```

查看 webroot 验证失败的域名：

```powershell
btr cert status --probe-webroot --only webroot-failed
```

批量开启或关闭强制 HTTPS：

```powershell
btr https enable --yes
btr https disable --yes
```

## 证书策略

`cert apply` 的执行顺序：

1. 先扫描面板站点、绑定域名和当前证书。
2. 按站点逐个执行完整流程：webroot 预检 -> 决策 -> 续订或新申请。
3. 当前站点的域名验证或申请失败只记录该站点结果，不阻塞后续站点。
4. 如果出现接口 404、参数无效、返回结构异常等程序/API 逻辑错误，立即停止整批流程。
5. 跳过不可访问域名、通配符域名和 LiteSSL 不支持的 IP 域名。
6. 如果所有可访问域名都已被当前证书覆盖，则尝试续订。
7. 如果任一可访问域名未被当前证书覆盖，则用全部可访问域名新申请证书。
8. 如果宝塔返回“当前没有可以续订的证书”，则改为新申请证书。
9. 新申请成功后调用 `/site?action=SetSSL` 保存证书到站点。

新申请证书使用宝塔 ACME 接口：

```text
POST /acme?action=apply_cert_api
```

核心参数：

```text
domains, auth_type, auto_to, auto_wildcard, id, ca
```

## Webroot 预检

工具会在站点根目录创建临时验证文件：

```text
.well-known/acme-challenge/<token>
```

然后从公网访问：

```text
http://domain/.well-known/acme-challenge/<token>
```

只有返回 `200` 且内容匹配的域名才会参与证书操作。

常见失败原因：

- 域名未解析到当前站点。
- 站点 80 端口不可访问。
- CDN、WAF、反向代理或重写规则拦截了 `/.well-known/acme-challenge/`。
- 站点根目录和实际 Web 服务目录不一致。
- 通配符域名需要 DNS-01，不能通过 HTTP-01 webroot 验证。

## 命令结构

推荐使用新命令：

- `cert status`：查看证书覆盖和域名状态。
- `cert plan`：执行 webroot 预检并展示 `renew` / `issue` / `skip` 计划。
- `cert apply --dry-run`：完整演练，不提交申请或续订。
- `cert apply`：按计划执行续订或新申请。
- `https enable`：批量开启强制 HTTPS。
- `https disable`：批量关闭强制 HTTPS。

旧命令 `scan`、`status`、`tui`、`renew` 保留兼容，但建议使用 `cert` 和 `https` 命令组。

旧入口 `baota-ssl-renewer` 保留兼容，新文档统一使用短命令 `btr`。
