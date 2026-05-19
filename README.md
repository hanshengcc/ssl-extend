# 宝塔证书续签器

一个终端工具，用一个 `baota.ini` 管理多个宝塔面板，扫描站点证书状态，并在续签前通过公网 HTTP-01 webroot 探测过滤掉无法验证的域名。

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
baota-ssl-renewer renew --config baota.ini --dry-run
baota-ssl-renewer renew --config baota.ini
```

## 行为说明

- 默认只尝试续签 Let's Encrypt 证书。
- 通配符域名不能通过 HTTP-01 webroot 验证，会被跳过。
- 工具会先在站点根目录写入 `.well-known/acme-challenge/<token>` 探测文件，再从公网访问 `http://domain/.well-known/acme-challenge/<token>`。
- 只有探测成功的域名会参与续签；失败域名会在结果中显示原因。
- 宝塔 SSL 续签使用面板内部接口，已集中封装，若面板版本不兼容，需要按抓包结果调整续签端点或参数。
