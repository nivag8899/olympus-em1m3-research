# E-M1 III v1.6 容器格式：初步解码（2026-10-09）

> 依据：`firmware/stock/OLY_E_139_1600_0000_0000.BIN` 前 32 字节，
> 对照 E-PL3 容器格式（`notes/02-epl3-prior-art.md` §1.3）。
> **结论：格式同构，E-PL3 的解析器/工具链大概率可直接复用。**

## 文件身份

- 109,838,336 字节 = 0x068C0040（E-PL3 总长 0x2C70040，同为 `…0040` 结尾，符合 section 链 + 末尾 tail 规律）
- SHA-256 `4f9ea315…a09aac`（溯源见 `stock-image-provenance.md`）

## Section 0 Header 逐字段解码（E-PL3 布局，LE）

```
00000000: 4f45 1390 0000 0000 0000 8040 c0ff 9f01
00000010: 0016 0000 0001 0000 0000 0000 0000 0000
```

| Offset | 字段（E-PL3 布局） | 值 | 解读 |
|--------|--------------------|----|------|
| 0x00 | sig[2] | `4f 45` "OE" | ✅ 魔数一致 |
| 0x02 | model[2] (LE) | 0x1390 | E-M1 Mark III 机身型号代码（文件名 `OLY_E_139_…` 吻合） |
| 0x04 | unk1[4] | 0 | |
| 0x08 | load_address (LE32) | **0x40800000** | 主代码装载地址（E-PL3 各 section 亦有各自 load addr） |
| 0x0C | body_length (LE32) | **0x019FFFC0** (27,262,912 ≈ 26MB) | section 0 主代码体量 |
| 0x10 | version (LE16) | 0x1600 | "1600" ↔ 文件名版本段 `1600` = v1.6 ✅ |
| 0x12 | unk2[2] | 0 | |
| 0x14 | flags (LE16) | **0x0100** | ⚠️ 落在 E-PL3 的 scramble 标志区间 (0x0100–0x0106)：body 按 16B lane 置换 `(1,3,0,2,6,4,7,5,11,10,9,8,13,14,12,15)` + 逐字节 XOR 0xFF |
| 0x16 | unk3[6] | 0 | |
| 0x1C | checksum (LE32) | 0 | ✅ header 的 checksum 字段必须为 0（E-PL3 规则） |

## 全链解析结果（2026-10-09，`tools/parse_em1m3.py`，报告 `work/parse-report.md`）

原待验证清单 4 项：**(1)(2)(3) 全部通过；(4) 部分解决**（见 `notes/firmware/em1m3-arch-map.md`）。

| # | 文件偏移 | load | body_length | ver | flags | checksum | 性质 |
|---|---------|------|-------------|-----|-------|----------|------|
| 0 | 0x00000000 | 0x40800000 | 0x019fffc0 (27MB) | 0x1600 | 0x0100 | PASS | uITRON 主控（疑似 MN103 系） |
| 1 | 0x01a00000 | 0x42400000 | 0x01afffc0 (28MB) | 0x0100 | 0x0101 | PASS | 数据镜像/本地化（UTF-16LE + olycompress） |
| 2 | 0x03500000 | 0x43f00000 | 0x0323ffc0 (53MB) | 0x0100 | 0x0106 | PASS | ARM A9 (DC13)：zImage + dc13.dtb + rootfs + 15MB 6-bit 区 |
| 3 | 0x06740000 | 0x00000000 | 0x0003ffc0 (256KB) | 0x0001 | 0x010e | PASS | "luke" 双核驱动子系统（0x12345678 魔数头） |
| 4 | 0x06780000 | 0x47140000 | 0x000fffc0 (1MB) | 0x1000 | 0x0102 | PASS | JPEG 参数资源（DHT 表） |
| 5 | 0x06880000 | 0x08000000 | 0x0003ffc0 (256KB) | 0x1000 | 0x0107 | PASS | SCPU = ARM Cortex-M（电源/按键/USB-PD/固件解压） |

- **EOF 覆盖 PASS**：6 个 section 恰好铺满文件，无残余字节
- **checksum 全 PASS**：checksum 覆盖解扰后 body，6/6 通过 ⇒ E-PL3 的
  `DESCRAMBLE_ORDER` 置换表 + XOR 0xFF 在 E-M1 III 上**逐字节相同**（§1.4 的担忧关闭）
- **flags 扩展**：0x0107/0x010e 超出 E-PL3 白名单 0x0100–0x0106，
  但 checksum PASS 证明置乱方案相同，仅编号扩展
- 解码产物：`firmware/work/section_NN_<load>.bin`（gitignored）
- ⚠️ 库的 `decode_container`/`verify_source` 不可直接用（前者有 E-PL3 假设，后者绑 registry），
  脚本自写了链式循环

## 意义

- E-PL3 工具链核心（header/descramble/checksum 语义）**完全复用成功**，Phase 0 最难的部分已解决
- flags=0x0100 系说明 OMDS 在 2020 年机型上仍沿用同一套加扰（安全性几乎为零），
  host parser 大概率同样只做 checksum 不做签名 —— 对 Phase 1（探针镜像）是利好
- 下一瓶颈：架构认证（section 0 是不是 MN103）与 ARM 载荷切分（见 arch-map 笔记）
