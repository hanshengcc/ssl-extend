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
default_ca = letsencrypt
ca_fallbacks = buypass
```

要求：

- 宝塔面板已开启 API。
- 宝塔 API 白名单已放行运行本工具的 IP。
- `url` 必须和面板实际协议一致，HTTP 面板不要写成 HTTPS。
- `default_ca` 用于没有证书的新站点，命令行 `--ca` 可临时覆盖。
- `ca_fallbacks` 仅在当前 CA 返回限速或配额错误时自动切换，不会对 webroot 验证失败、参数错误、接口错误兜底。
- 不配置 `ca_fallbacks` 且不传 `--ca-fallback` 时，工具会使用内置备用顺序：`buypass, letsencrypt, litessl, zerossl, google, sslcom`，并自动跳过当前主 CA。

内置 ACME CA：

- `letsencrypt`
- `letsencrypt-staging`
- `litessl`
- `buypass`
- `buypass-staging`
- `zerossl`
- `google`
- `sslcom`

`zerossl`、`google`、`sslcom` 通常需要 External Account Binding，在对应 `[panel.*]` 中配置：

```ini
acme_eab_kid = your-kid
acme_eab_hmac_key = your-hmac-key
```

需要接入其他 ACME 服务商时，可配置：

```ini
acme_directory_url = https://acme.example.com/directory
```

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

指定免费 CA 申请新证书：

```powershell
btr cert apply --ca buypass
```

当前 CA 限速时自动切换到备用 CA：

```powershell
btr cert apply --ca letsencrypt
btr cert apply --ca letsencrypt --ca-fallback buypass
btr cert apply --ca letsencrypt --ca-fallback buypass,zerossl
```

按域名在所有宝塔面板中搜索并处理匹配站点，支持重复传入和逗号分隔：

```powershell
btr cert apply --domain example.com
btr cert apply --domain example.com --domain example.net
btr cert apply --domains example.com,example.net
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

新申请证书使用内置 ACME HTTP-01 客户端。证书签发成功后，工具会调用 `/site?action=SetSSL` 将证书保存到宝塔站点。

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
