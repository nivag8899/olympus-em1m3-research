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

## 待验证清单（下一步：跑 e-pl3-research 的 source.py）

1. **全文件 section 链解析**：从 offset 0 依次读 32B header → body → 32B tail，
   确认各 section 边界与总数（文件 0x068C0040，section 0 body 0x019FFFC0，
   后面应还有数个 section —— 期待类似 E-PL3 的 数据/资源/H8 结构）
2. **tail checksum 校验**：`(-Σ LE32 words) mod 2³²`，覆盖 header(0) ++ 解扰后 body ++ tail 前 28B
3. **descramble 验证**：section 0 flags=0x0100，用 E-PL3 的逆变换解出 body，
   若出现规律性代码/字符串 → 架构与变换全部复用成功
4. **架构确认**：0x40800000 处的指令流是 MN103 还是别的（objdump -m mn10300 试译）

## 意义

- 若 (1)-(4) 全部通过：E-PL3 的 `source.py`（换 registry）+ binutils mn10300 objdump + Reko
  工具链即插即用，Phase 0 最难的部分直接省掉
- flags=0x0100 说明 OMDS 在 2020 年机型上仍沿用同一套加扰（安全性几乎为零，但求个麻烦），
  也说明 host parser 的 checksum boundary 大概率同样没有签名 —— 对 Phase 1（探针镜像）是利好
