# 宝塔证书续签器

一个终端工具，用一个 `baota.ini` 管理多个宝塔面板，扫描站点证书状态，并在续签前通过公网 HTTP-01 webroot 探测过滤掉无法验证的域名。

支持 Let's Encrypt 和 LiteSSL 免费证书。LiteSSL 需要宝塔面板 11.5.0 或更新版本。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -e .
```

## 配置

复制 `baota.example.ini` 为 `baota.ini`，为每个宝塔面板添加一个 `[panel.*]` 配置段：

```ini
[panel.prod-a]
url = https://1.2.3.4:8888
api_key = xxxxxxxxx
verify_ssl = false
timeout = 15
```

宝塔面板需要在“面板设置 -> API 接口”中开启 API，并放行运行本工具的 IP。

## 使用

```powershell
baota-ssl-renewer --config baota.ini
```

常用命令：

```powershell
baota-ssl-renewer scan --config baota.ini
baota-ssl-renewer tui --config baota.ini
baota-ssl-renewer tui --config baota.ini --only webroot-failed
baota-ssl-renewer status --config baota.ini
baota-ssl-renewer status --config baota.ini --probe-webroot
baota-ssl-renewer status --config baota.ini --probe-webroot --only webroot-failed
baota-ssl-renewer status --config baota.ini --only unbound
baota-ssl-renewer renew --config baota.ini --dry-run
baota-ssl-renewer renew --config baota.ini
```

## 行为说明

- 默认只尝试续签 Let's Encrypt 和 LiteSSL 免费证书。
- LiteSSL 不支持 IP 证书，IP 域名会在续签前自动跳过。
- 通配符域名不能通过 HTTP-01 webroot 验证，会被跳过。
- 工具会先在站点根目录写入 `.well-known/acme-challenge/<token>` 探测文件，再从公网访问 `http://domain/.well-known/acme-challenge/<token>`。
- 只有探测成功的域名会参与续签；失败域名会在结果中显示原因。
- `renew` 会在提交续签前集中执行 webroot 预检，先输出成功/失败汇总；如果没有任何域名通过预检，会直接跳过续签。
- 宝塔 SSL 续签使用面板内部接口，已集中封装，若面板版本不兼容，需要按抓包结果调整续签端点或参数。

## 状态查看

`status` 命令会输出汇总和域名明细：

- `Sites`：站点数。
- `Site-bound domains`：宝塔站点绑定的域名数。
- `Certificate SAN domains`：当前证书里包含的域名数。
- `Domains bound in certificate`：站点域名中已被当前证书覆盖的数量。
- `Domains not bound in certificate`：站点域名中未被当前证书覆盖的数量。
- `--probe-webroot`：同时检测每个域名是否能通过 webroot 验证。
- `--only bound|unbound|webroot-ok|webroot-failed`：只显示指定类别。
