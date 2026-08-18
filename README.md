# fenliu-rule-catalog

Fenliu 的公开应用规则仓库。路由器不直接解析各上游的 Clash/V2Fly 格式；本仓库每天拉取上游、转换成统一格式、校验变化、使用 usign 签名，再通过 GitHub Pages 发布。

固定接口：

```text
stable/manifest.json
stable/manifest.json.sig
stable/catalog.tar.gz
```

`catalog.tar.gz` 内只有 `apps/<id>.conf` 和来源审计文件 `sources.json`。规则文件只接受：

```text
# fenliu-catalog-v1
domain:example.com
cidr4:203.0.113.0/24
cidr6:2001:db8::/32
```

## 部署到自己的 GitHub 仓库

1. 在 GitHub 新建一个名为 `fenliu-rule-catalog` 的公开空仓库，不要预先添加 README。
2. 把本目录作为该仓库根目录推送到 `main`，确保 `.github/workflows/publish.yml` 也在仓库中。
3. 在仓库的 `Settings → Secrets and variables → Actions` 新增 Repository secret：
   - 名称：`FENLIU_CATALOG_SECRET_KEY_B64`
   - 值：本机 `catalog.sec` 文件的 Base64 单行编码。
4. 私钥只能放在 GitHub Secret。不要提交 `catalog.sec`、复制到 Actions artifact、粘贴到日志或交给 Pages。仓库中的 `catalog.pub` 必须与软件包 `/etc/fenliu/catalog.pub` 一致。
5. 打开 `Actions → Build and publish Fenliu rule catalog → Run workflow`，手动执行首次发布。
6. 首次成功后会出现 `catalog` 分支。到 `Settings → Pages`，选择 `Deploy from a branch`，分支选 `catalog`，目录选 `/ (root)`。
7. 等 Pages 生效后检查以下三个 URL 均为 HTTP 200：

```text
https://<OWNER>.github.io/fenliu-rule-catalog/stable/manifest.json
https://<OWNER>.github.io/fenliu-rule-catalog/stable/manifest.json.sig
https://<OWNER>.github.io/fenliu-rule-catalog/stable/catalog.tar.gz
```

Linux 生成 Secret 值：

```sh
base64 -w 0 /secure/path/catalog.sec
```

macOS 可使用 `base64 < /secure/path/catalog.sec | tr -d '\n'`。PowerShell 可使用：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secure\catalog.sec'))
```

这些命令会把私钥编码输出到当前终端，请只在可信终端操作，不要把结果写入仓库。Base64 是编码，不是加密。

## 路由器配置

在 x64 legacy 插件的“全局设置”中填写仓库根地址，不要附加 `/stable/manifest.json`：

```text
https://<OWNER>.github.io/fenliu-rule-catalog
```

先在“应用规则”页面手动检查并确认差异，再启用“每周自动更新”。路由器每周检查一次，只会应用通过内置公钥验签、SHA-256、归档路径和规则格式校验的版本。GitHub 每天构建不代表路由器每天修改配置。

## 维护应用列表

应用列表由 `catalog-sources.json` 人工精选；规则内容由上游自动维护。每个应用格式如下：

```json
{
  "id": "youtube",
  "name": "YouTube",
  "category": "video",
  "sources": [
    {
      "type": "clash",
      "url": "https://raw.githubusercontent.com/example/project/main/youtube.yaml"
    }
  ]
}
```

- `id` 是稳定接口，只能用小写字母、数字、`_`、`-`，最长 32 字符；发布后不要随意改名。
- `name` 是界面显示名称，`category` 用于分类。
- 一个应用可配置多个来源，结果会合并去重。
- `clash` 支持 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`IP-CIDR6`。
- `v2fly` 支持普通域名、`domain:`、`full:`；正则和 include 会记为 unsupported，不进入发布规则。
- `fenliu` 用于已经符合 `domain:`、`cidr4:`、`cidr6:` 的纯文本来源。
- `path` 仅适合本地构建和测试；正式自动更新应使用 HTTPS `url`。

新增或删除应用 ID 会被所有未手动放行的任务拦截。确认这是有意变更后，在 Actions 页面手动运行工作流并勾选 `allow_large_change`。此开关只能放行应用集合和规则数量变化，不能绕过格式、路径穿越、跨应用冲突、哈希或签名校验。

## 自动更新和安全门槛

工作流每天北京时间 11:17（UTC 03:17）运行，不缓存上游文件。也会在 PR 中构建和生成报告，但 PR 不读取私钥、不签名、不发布。

CI 使用 OpenWrt 23.05 同版的官方 `openwrt/usign` 固定提交 `f1f65026a94137c91b5466b149ef3ea3f20091e9` 构建签名工具；不会跟随 usign 仓库的浮动分支。

发布版本为 `YYYY.MM.DD.<GITHUB_RUN_NUMBER>`。若规则归档与当前线上版完全相同，则不访问私钥，也不产生无意义的新版本。变化达到以下条件会阻断发布：

- 单个应用减少超过 30% 或增加超过 100%，并且绝对变化至少 20 条；
- 全目录减少超过 20% 或增加超过 75%；
- 定时任务中应用 ID 有增删；
- 出现重复/冲突规则、非法路径、非法格式、计数/哈希不一致或验签失败。

失败候选、JSON 报告和 Markdown 报告在 Actions artifact 中保留 14 天。上游临时不可用会直接失败并保留当前线上版本。

## 本地构建与验证

```sh
python3 build_catalog.py \
  --version 2026.08.18.1 \
  --generated-at 2026-08-18T03:17:00Z \
  --output dist/stable

python3 validate_release.py \
  --candidate dist/stable \
  --report-json candidate-report.json \
  --report-markdown candidate-report.md

python3 -m unittest discover -s tests -v
```

正式签名后强制反向验签：

```sh
usign -S -m dist/stable/manifest.json -s /secure/path/catalog.sec \
  -x dist/stable/manifest.json.sig
python3 validate_release.py --candidate dist/stable \
  --public-key catalog.pub --require-signature
```

## 回退

`catalog` 分支保留每次实际发布的提交历史。在 GitHub 或本地对错误发布提交执行 `git revert` 并推送 `catalog`，Pages 就会重新提供上一版三个文件。随后在路由器“应用规则”页面执行检查和应用；路由器本身也保留一次目录版本回退能力。

如果怀疑私钥泄露，不能只回退规则：应立即停用 Actions Secret、生成新密钥，并发布包含新公钥的软件包。旧软件内置的公钥无法信任新私钥签名，密钥轮换必须随插件升级完成。
