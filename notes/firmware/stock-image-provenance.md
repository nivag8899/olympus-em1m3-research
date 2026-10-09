# E-M1 Mark III 机身固件 v1.6（原厂镜像）溯源

## 文件

- 文件名：`OLY_E_139_1600_0000_0000.BIN`
- 存放路径：`firmware/stock/OLY_E_139_1600_0000_0000.BIN`
- 类型：机身（body）固件，非镜头固件（OMDS 目录 `0001` 段为机身；`0003`/`0004` 段为镜头）
- 版本：v1.6（最终版，2023-01-19 发布）
- 字节数：109,838,336（约 104.75 MiB）
- 下载日期：2026-10-09

## 哈希

- SHA-256：`4f9ea315a2f2280dd5746abc39b5e4b038f183836eadfbe9d96b266e49a09aac`
- SHA-1：`146819e4b34c7ee8a000f6b15181d91caff66865`
- `file` 输出：`data`
- 前 64 字节（xxd）：

```
00000000: 4f45 1390 0000 0000 0000 8040 c0ff 9f01  OE.........@....
00000010: 0016 0000 0001 0000 0000 0000 0000 0000  ................
00000020: 0005 0f03 3401 3407 3f00 0303 ffff ff07  ....4.4.?.......
00000030: 0701 01fb 0356 0300 07ff ffff 0301 fb21  .....V.......!
```

头部 `4f45`（"OE" 魔数）+ `1390`（E-M1 Mark III 型号代码，十六进制 0x1390），确认是 E-M1 Mark III 机身固件。

## 完整性交叉验证

Wayback Machine CDX API 记录的该 URL 归档摘要（base32 SHA-1）为
`CRUBTZFTJR7ORIAA62YVDAOZDSX7M2DF`，base32 解码后为
`146819e4b34c7ee8a000f6b15181d91caff66865`，与本地文件的 SHA-1 完全一致，
证明本次下载与 2025-02-01 Wayback 爬虫从 OMDS 官方服务器抓取的原始字节逐位相同。

## 链接路径（复现步骤）

1. **官方入口页（联合更新服务）**：
   `https://support.jp.omsystem.com/en/support/imsg/digicamera/download/software/firm/e1/`
   表格中 "E-M1 Mark III / 1.6 / Click here"（发布日期 Jan. 19, 2023，与 v1.6 相符）
   → 指向 `https://dl01.om-digitalsolutions.net/ww/ud2/ENU/0001/1390/index06a.html`

2. **版本说明页**：上列 URL 仅有 v1.1–v1.6 的更新日志，无下载直链
   （官方现在只通过 OM Workspace 走签名下载）。该页可确认 1390 即 E-M1 Mark III 的型号目录代码。

3. **固件原始直链（OMDS 官方 CDN，文件命名规律 `OLY_E_<型号>_<版本>...`）**：
   `https://dl01.om-digitalsolutions.net/OMDS/FIRMWARES/0001/1390/OLY_E_139_1600_0000_0000.BIN`
   （通过 Wayback CDX API 对 `dl01.om-digitalsolutions.net/*` 的归档索引发现）
   该 URL 现已返回 CloudFront 403（需签名 URL），但历史上开放过。

4. **实际下载源（Wayback Machine 存档快照，2025-02-01 20:39:57 UTC 抓取，HTTP 200）**：
   `https://web.archive.org/web/20250201203957if_/https://dl01.om-digitalsolutions.net/OMDS/FIRMWARES/0001/1390/OLY_E_139_1600_0000_0000.BIN`

## 其他已尝试但不需要的路径（备忘）

- 中国官网 `https://om-digitalsolutions.cn/support/verup.php`：固件信息列表只链到 PDF 升级说明，无固件二进制。
- OM Workspace 下载页 `https://download.omsystem.com/pages/owdownload/`：`OWSetup.dmg` 走 `/api/signed/` 接口且需 9 位相机序列号，无法也不应伪造；且 OM Workspace 本体不含固件，故未采用此路径。
- 目录探测（`index06b.html`、`EM1M3*.BIN` 等猜测文件名）：全部 404。

## 结论

`OLY_E_139_1600_0000_0000.BIN` 为 OM Digital Solutions 官方分发的 E-M1 Mark III
机身固件 v1.6 原始镜像（经 Wayback Machine 存档中转获取，字节级校验一致），
可直接用于静态逆向分析。
