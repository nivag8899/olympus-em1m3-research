# E-PL3 前人成果消化（olympus-e-pl3-research）

> 来源：`third_party/olympus-e-pl3-research`（sympho-ru/olympus-e-pl3-research，shallow clone @ main）
> 对象机型：Olympus E-PL3（2011，Pen Lite，TruePic VI 世代），Body firmware 1.6
> 消化日期：2026-10-09。仓库性质：**byte-free 证据库**——公开的只有坐标/长度/SHA-256/反汇编文本，
> 不含任何固件字节；容器格式的权威定义在 `src/epl3_research/source.py`（约 250 行，可直接复用）。
> 文档行文极度保守（每个结论都带 hedging），本笔记已把可操作的硬事实抽出，hedging 只保留在结论边界处。

## 0. 项目目标与总体结论（TL;DR）

- 前人目标与我们的同构：给 E-PL3 刷自定义固件（"second life with custom firmware"）。
- **容器格式已完全逆向**：5 个 block 顺序拼接，每 block = 32B header + body + 32B tail（tail 是 header 的副本，仅 checksum 字段不同）；body 有 16 字节 lane 置换 + XOR 0xFF 的 scramble；完整性仅一个 **32-bit 加法 checksum**（对 header+解扰后 body+tail 前 28B 求和取负），**无任何密码学签名**。
- **数据区修改已实证可刷入、可启动、可被相机使用**（EXP-001/007/008）；代码区修改一次失败变砖（EXP-010），但 **SD 卡 + 官方镜像成功救回**。
- 完整的 host-command → new-capture → download 路径**没有打通**（这是他们的失败教训，见 §5/§6）。
- 对 E-M1 III：方法论、工具链思路、SD 救砖通道大概率可复用；容器格式细节（scramble 表、header 字段、block 划分）必须重新验证；CPU 架构 2020 年很可能已换（见 §6）。

---

## 1. 容器格式详解（最重要）

### 1.1 文件命名与身份

| 项 | 值 |
|---|---|
| Filename | `OLY_E_086_1600_0000_0000.BIN` |
| Size | 46,596,160 bytes (0x2C70040) |
| SHA-256 (parent) | `89b70dd65c6739de1cd762777205953ee15864df73369b84815df7ed8a0eb4b1` |

命名规律：`OLY_E_<body 代码 086>_<版本 1600 = 1.6.00?>_0000_0000.BIN`。`086` 应为 E-PL3 body 型号代码；后两组 `0000` 疑似 region/language 占位（未证实）。E-M1 III 的对应文件名规律（如 `OLY_E_...`）拿到官方镜像后即可对照。

### 1.2 容器组织：没有集中式 block table

**关键事实：文件不是"文件头里有一张 block table"，而是 5 个 section 顺序链式拼接**。解析器从 offset 0 开始，读 32B header → 按 `body_length` 跳过 body → 读 32B tail 校验 → tail 结束处就是下一个 block 的 header，直到文件末尾。`decode_container()`（source.py:154）就是这么循环的。

每个 section = `header(0x20) + body(body_length) + tail(0x20)`，五个 section 的精确边界（由 body 长度推得，已用脚本核算）：

| Block | section 起点 | header | body 范围 | body 长度 | tail |
|---:|---:|---:|---|---:|---|
| 0 | 0x00000000 | 0x00000000 | 0x00000020..0x00D7FFE0 | 0xD7FFC0 (14,155,712) | 0x00D7FFE0..0x00D80000 |
| 1 | 0x00D80000 | 0x00D80000 | 0x00D80020..0x0237FFE0 | 0x15FFFC0 (23,068,608) | 0x0237FFE0..0x02380000 |
| 2 | 0x02380000 | 0x02380000 | 0x02380020..0x025DFFE0 | 0x25FFC0 (2,490,304) | 0x025DFFE0..0x025E0000 |
| 3 | 0x025E0000 | 0x025E0000 | 0x025E0020..0x02C5FFE0 | 0x67FFC0 (6,815,680) | 0x02C5FFE0..0x02C60000 |
| 4 | 0x02C60000 | 0x02C60000 | 0x02C60020..0x02C70020 | 0x10000 (65,536) | 0x02C70020..0x02C70040 |

规律：每个 section 起点都是整齐的 0x...0000；block 0–3 的 body 都是"整兆减 0x40"，block 4 恰为 0x10000。

### 1.3 Header/Tail 字节级布局（32 字节，多字节整数全部 little-endian）

依据 `Header.parse()`（source.py:96-113）：

| Offset | 长度 | 字段 | Endianness | 说明 |
|---:|---:|---|---|---|
| 0x00 | 2 | `signature` | bytes | magic（具体值需镜像确认） |
| 0x02 | 2 | `model` | bytes | 型号代码 |
| 0x04 | 4 | `unknown1` | bytes | 未解析 |
| 0x08 | 4 | `load_address` | **LE32** | 加载地址（但见 §1.6 的"地址视图"警告） |
| 0x0C | 4 | `body_length` | **LE32** | body 字节数（链式解析的依据） |
| 0x10 | 2 | `version` | **LE16** | 版本 |
| 0x12 | 2 | `unknown2` | bytes | 未解析 |
| 0x14 | 2 | `flags` | **LE16** | 0 = 明文；0x0100–0x0106 = body 加扰 |
| 0x16 | 6 | `unknown3` | bytes | 未解析 |
| 0x1C | 4 | `checksum` | **LE32** | **header 中必须为 0x00000000**；真正的 checksum 存在 tail 同位置 |

**Tail（trailer）规则**（source.py:172-179）：

1. tail 的前 28 字节（`without_checksum()` 覆盖的所有字段）必须与 header 逐字节相同；
2. header 的 `checksum` 字段必须为 0（否则报错）；
3. tail 的 `checksum` 字段（tail 偏移 0x1C..0x20）存放该 block 的真 checksum。

即：**header 与 tail 互为副本，header 的 checksum 位清零、tail 的 checksum 位为真值**——这是 E-PL3 容器最反直觉的设计，写 repack 工具时最容易搞错。

### 1.4 Scramble/Descramble 算法（body 加扰）

依据 `descramble()`（source.py:129-137）。仅当 `flags != 0`（0x0100–0x0106）时 body 加扰；body 长度必须是 16 的倍数（五个 block 全部满足）。

对每 16 字节一组做 **byte lane 置换 + 全体 XOR 0xFF**：

```
DESCRAMBLE_ORDER = (1, 3, 0, 2, 6, 4, 7, 5, 11, 10, 9, 8, 13, 14, 12, 15)

decoded[i::16]  = scrambled[DESCRAMBLE_ORDER[i]::16]  每字节 ^ 0xFF
```

展开即：`decoded[j] = scrambled[ORDER[j]] ^ 0xFF`（j = 0..15，逐组循环）。
XOR 是自反的，所以 **scramble（repack）就是逆置换**：`scrambled[ORDER[j]] = decoded[j] ^ 0xFF`。

⚠️ 前人在 host-parser 测试里"修改 block 4 → rescramble the body → 更新 tail checksum"被接受，说明至少 block 4 是加扰的；各 block 的 flags 具体值（哪些是 0x0100..0x0106、哪个是 0）文档未记录，需拿镜像实测——**E-M1 III 上这张置换表大概率不同，必须重新求逆**（对已知明文/零填充区做差分即可推出）。

### 1.5 Checksum 算法与覆盖范围（"host parser's checksum boundary"）

依据 `source_checksum()` + `decode_container()`（source.py:140-190）：

- **算法**：把输入按 **LE32 word** 切分，`checksum = (-Σ words) mod 2^32`（求和取负的补码和，非 CRC、非加密 hash）。
- **覆盖范围**：`header_32B(其 checksum 字段=0) ++ decoded_body(解扰后的 body) ++ tail_前28B(即 tail 去掉 checksum 字段)`。注意覆盖的是**解扰后的逻辑内容**，不是文件里的原始加扰字节。
- 校验：`source_checksum(header_bytes + decoded + tail_bytes[:-4]) == tail.checksum`。

**"host parser's checksum boundary" 的含义**（BLOCKS.md#container-integrity）：前人实现了 byte-identical 的 unpack/repack 模型，并做过一个决定性实验——修改 decoded block-4 offset 0 的一个字节 → 重新 scramble body → 按上述算法重算 tail checksum → 产出的同尺寸五 block 镜像**被 host parser（官方更新器侧的解析器）接受**；不修 checksum 的对照组被拒。结论：

1. host 侧解析器对镜像的完整性校验**只有这个加法 checksum**，改任何内容后重算即可通过 host 侧；
2. 但"host parser 接受"≠"设备接受/能启动"——设备端（bootloader/updater 在机内的验证机制）**未逆向、未知**。物理实验（§4）证明数据区改动确实能刷入并生效，说明设备端对数据区至少没有超出 checksum 的强校验；代码区一次实验变砖，无法区分是"被拒绝"还是"写坏了代码自己起不来"。

### 1.6 Block 0–4 内容与格式

| Block | 解码后内容 | 关键结构事实 |
|---:|---|---|
| **0** | 主固件，**MN103（mn10300，little-endian）代码 + 数据** | startup、对象生命周期、release-control（快门释放候选）、PTP-adjacent dispatch；14 MB。已认证 13,203 个 range / 53,425 条指令。**地址视图不唯一**：同一 source offset 在不同窗口有不同 runtime 地址（见下） |
| **1** | 数据镜像 + 本地化资源 | 开头 69 条连续 16B `(source, length, 0, 0)` 记录表（到 0x7e0，后补零），随后 69 个数据镜像，`image offset = source - 0x42700020`；source 覆盖 `0x42700800..0x42fb9400`。block-0 代码用三条 materializer 路径（默认目的地址 `0xaf966000`、`0xaff7d000`、`0xaff21000`，公共属性 `0x0101`）请求搬运（copy/DMA/映射未区分）。内含 34 资源 UTF-16LE 字符串字典（`@A000@..@A0EE@` token 族）+ 239 条 affine descriptor 索引 + 34 张单调表 |
| **2** | 未知 payload | header 两词 `0x00240000`（=payload 长度）和 `0x43d00400`（= base 0x43d00000 + 0x400）；`0x3e0` 处开始 0x240000 字节 payload，字节值只用了 `0x00..0x3f`（除 0x3c）——像 6-bit 编码但常见打包/压缩/delta 变换全被排除；消费者未找到（开放问题） |
| **3** | JPEG 资源包 | 8 项索引（0x0..0x80）+ 8 条带 16B 前缀的完整 baseline JFIF JPEG（0x3e0 起）；JPEG span 不重叠，尾部全零。用途（UI 资源？）未定 |
| **4** | **H8 兼容（big-endian）辅助 MCU 镜像**，恰 64 KB | 向量表 + 代码 + 表 + 字符串；内部 relocation delta `0x003f2042`；有 70 项 dispatch table（0xe898..0xe9b0）、公共 dispatch 目标 0x122a；块内 0x34 处有 8 字节 `E. Munch` 字面量，与 block-0 0x00338a80（紧邻 firmware-update 与 ID-check 文本）字节相同——**暗示 block 4 与固件更新流程有关**，但 transfer/owner/start 边均未建立。具体 H8 芯片型号、外部 loader、硬件归属全未知 |

**Block 0 的"地址视图"警告**（READING.md#coordinates，对做 E-M1 III 反汇编极重要）：E-PL3 的 block 0 不能套一个全局 base。已知的条件性视图至少有：

| 视图 | delta（local addr = source offset + delta） | 用于 |
|---|---|---|
| CODE-local | `+ 0x6e5fffe0` | 大多数代码 |
| DATA-local | `+ 0x6e601420` | 字符串/表等数据 |
| Startup | `+ 0x402bffe0` | 早期启动代码 |
| 另一低视图 | `+ 0x6e600420` 等 | 个别对象 |

同一 runtime 地址在不同视图下指向不同 source 窗口；文档反复强调"Never derive a target from a global block-0 base"。原因大概率是 overlay/分段加载（block 0 被拆成多个运行时段映射）。**E-M1 III 若是 ARM + 单一映射，这个问题会简单得多；若仍是分段 overlay，需要同样的多视图纪律。**

### 1.7 可直接复用的实现

`src/epl3_research/source.py` 是无第三方依赖（纯 stdlib）的完整解析器：`verify_source()` / `decode_container()` / `descramble()` / `source_checksum()` / `Header.parse()`。对 E-M1 III：把 registry（filename/size/SHA-256/块表）换成新镜像的，先假设 header 结构/scramble 表/checksum 相同跑一遍，失败点直接指示哪一层变了。

---

## 2. 获取与校验流程

### 2.1 官方镜像获取

- 项目**不提供镜像、不提供下载器**："Obtain the official E-PL3 Body 1.6 image through a lawful source available to you. Upstream availability is not guaranteed."
- E-PL3 时代官方通道是 Olympus 官网的 firmware 页面（Digital Camera Updater / 含 updater 的 Olympus Viewer）；仓库文档只说实验时 host 为 macOS、"attended update"，未点名具体 updater 软件与版本（还特意声明不保证对其他 host/updater 版本可移植）。
- 对 E-M1 III：官方支持页仍有固件（OM Digital Solutions），`*.BIN` 直链可下载——**这比前人条件好**，我们已在 Phase 0 安排（`firmware/stock/`）。

### 2.2 verify-source 三层校验

```
epl3-research verify-source --image .private/OLY_E_086_1600_0000_0000.BIN
```

1. **容器身份**：filename == `OLY_E_086_1600_0000_0000.BIN`、size == 46,596,160、整文件 SHA-256 == parent hash。改名不够，必须逐字节相同。
2. **容器结构**：`decode_container()` 按链式 header→body→tail 解出恰好 5 个 block（header/tail 一致性、header checksum 位为 0、flags 合法、加法 checksum 匹配）。
3. **块身份**：逐 block 比对 size + SHA-256（见下表）。

| Block | Size | SHA-256 |
|---:|---:|---|
| 0 | 14,155,712 | `c291722827a5120fc06ca288b439cae82ebf597ac2cd83eba30a7f0fe6a72687` |
| 1 | 23,068,608 | `af5a35e02304183c9e716af99b9fb619abb13f5a71e41146986bf9d833e2e20f` |
| 2 | 2,490,304 | `ae9d7a1cc5f0d3bfeedb4dfecedc70be8a423e9bea7070cee16363fb30eaacfb` |
| 3 | 6,815,680 | `218b6003e490efc432851e831086cf8f1237f2fde3fade4be93dd89425459941` |
| 4 | 65,536 | `e131370def9d69fe4484592f0cf4bc84c865162007c0cae11405a4911c8b07a2` |

### 2.3 "Authenticated ranges" 机制（byte-free 证据）

这是整个仓库的方法论核心：**公开证据 = 坐标 + 切片哈希，永远不公开字节**。

- `evidence/ranges.jsonl`：每行 `{"block", "offset", "length", "sha256"}`（offset 相对**解码后**的 block，不是容器文件偏移！），按 `(block, offset, length)` 排序且唯一。
- `evidence/instructions.jsonl`：每行再加 `{"address"（十进制的反汇编地址）, "instruction"（反汇编文本）}`。
- `epl3-research source-range --image ... --block N --offset X --length L`：对已验证镜像输出切片 SHA-256（绝不打印字节）——这就是"引用固件内容"的合规方式。
- 任何持有相同官方镜像的人可以重算每个哈希 → 证据可复核、可 fail-closed（坐标/长度/哈希任一不符即拒绝）。
- 覆盖量（认证 range 数 / canonical 指令数）：block 0 = 13,203/53,425；block 1 = 827/0；block 2 = 4/0；block 3 = 35/0；block 4 = 3,230/0（覆盖全部 65,536 字节；H8 译码冲突未决所以无 canonical 指令）。覆盖是稀疏、非连续的。
- `check`（structural/source/release 三档）+ `check-contribution`/`accept-contribution`：incoming 文件必须内容寻址命名（`incoming/(ranges|instructions)-<file-sha256>.jsonl`）、切片要对得上镜像、指令行过 MN103 objdump 译码门（§3.4）、canonical 证据未被改动；release 档再扫 git 历史防字节泄漏。这套东西对本项目过重，但"坐标+哈希引用"的纪律值得在笔记/复现脚本里保留。

---

## 3. CPU 架构与工具链

### 3.1 MN103 是什么

- 主核（block 0）是 **Panasonic(Matsushita) MN103S 系列**，GNU 目标名 **`mn10300`**（`--target=mn10300-elf`，`elf32-mn10300`），**little-endian**，指令最长 7 字节（binutils `opcodes/m10300-dis.c` 的 FMT_D9 与最长格式），寄存器 `d0-d3`（数据）/`a0-a3`（地址），常见指令形如 `movm [d2,a2],(sp)`、`calls`、`ret [d2],8`。
- 2011 年 Olympus 机身（E-PL3 及同期）用 MN103 是已知事实；**2020 年 E-M1 III（TruePic VIII）大概率不再是 MN103**——需 Phase 3 实测（若换 ARM，Ghidra/objdump 直接支持，工作量骤降）。
- Block 4 是另一颗 MCU 的固件：**big-endian、H8 兼容**（Renesas H8 族指令形状），64 KB 平铺镜像含向量表。具体芯片、由谁加载、管什么硬件（电源？USB？media controller？）全部未知；block-0 里紧邻 firmware-update/ID-check 文本的 `E. Munch` 字面量暗示与更新流程有关。**E-M1 III 的容器里是否有对应的小核 block，拿到镜像后第一件事就是找。**

### 3.2 GNU binutils mn10300 objdump 的获取（有现成构建命令，ANALYSIS.md 全文照抄）

```sh
mkdir -p .private/toolchains
tar -xf /path/to/binutils-2.45.tar.xz -C .private/toolchains
mkdir .private/toolchains/binutils-2.45-build
cd .private/toolchains/binutils-2.45-build

../binutils-2.45/configure \
  --target=mn10300-elf \
  --disable-nls --disable-werror \
  --disable-gdb --disable-sim --disable-gas --disable-ld \
  --disable-gprof --disable-gold --disable-libctf \
  --with-system-zlib --disable-shared

make all-binutils          # 只构建 binutils，不构建整个工具链
```

验证（仓库根目录）：

```sh
MN103_OBJDUMP=.private/toolchains/binutils-2.45-build/binutils/objdump
"$MN103_OBJDUMP" --version        # 必须是 GNU objdump (GNU Binutils) 2.45
"$MN103_OBJDUMP" -i | grep mn103  # 必须列出 elf32-mn10300 / mn10300 / binary
```

要点：**必须 2.45**（decoding.py:74 硬编码版本字符串比对，其他版本直接拒）；macOS arm64 本地编译即可（需要 C compiler、make、zlib 头文件：`brew install zlib` 或用 `--with-system-zlib`）。反汇编窗口的标准姿势：

```sh
dd if=.private/decoded/block-0.bin of=window.bin bs=1 skip=$((0xOFFSET)) count=$((LEN))
"$MN103_OBJDUMP" -z -b binary -m mn10300 -D --insn-width=16 \
  --adjust-vma=0x<local-address-anchor> window.bin
```

### 3.3 Reko 交叉验证

- Reko 作为**独立**的 MN103 边界/控制流交叉检查；必须用包含 E-PL3 修正的 revision：**Reko PR #1370**（`github.com/uxmal/reko/pull/1370`，修正 full-width `(d32,SP)` 操作数和 PC-relative d32 `CALLS` 的译码）。
- 用法：以 raw MN103 code 导入同一窗口，赋相同 local base，**先比对指令地址和长度**，再看高层控制流。GNU 是命令行 baseline，Reko 是可选复核。

### 3.4 指令译码验证门（contextual decode gate）

`check-contribution` / `accept-contribution` / `screen-instructions` 共用的机械门（decoding.py），思路可借鉴到我们自己的证据流水线：

1. 认证切片（SHA-256 对上镜像）→ 合并相邻 interval → 用 objdump 带 **6 字节 lookahead** 译码（7 字节最长指令 − 1）；
2. 每行的长度与指令文本必须与 objdump 输出完全一致（whitespace 归一化后）；unknown/pseudo 指令不算指令；
3. **重叠检测**：任何 source interval 相交的行对（含不同 address view、不同长度）必须显式裁决（`--overlap-review` 给 reason），防止"截断旧行"与"全宽新行"共存；
4. 边界声明：`decode_only_start_anchors_not_proven`——译码成功 ≠ 可执行 ≠ reachable。block 4（H8）没有 verifier，指令行不接受。

---

## 4. 部署实验实录与安全经验（docs/observations/DEPLOYMENT.md）

### 4.1 实验总表（EXP-001…010；EXP-002..005 未公开记录）

所有 candidate 都从官方 Body 1.6（parent SHA-256 89b70d…）派生；host = macOS；"attended update" = 有人在场的官方更新流程（LCD 显示完成后人工 power cycle）。公开文档**未点名**使用的更新器软件。

| EXP | 日期 | 改了什么 | 结果 | Candidate SHA-256 |
|---|---|---|---|---|
| **001** | 2026-07-13 | **纯数据 marker**：block 0 offset `0x00d59706`（在 canonical range `(0, 0x00d596fb, 13)` 内）改 DeviceInfo version 字符串 `1.00`→`1.01` | ✅ **刷入成功、重启后 Print 模式 DeviceInfo 返回 1.01**——修改数据在运行中被相机使用。host gate 记录 `marker_confirmed` + 事务 ID 匹配 | `c892065b…f90ebb` |
| 006 | 2026-07-14 | 尝试把 `GetStorageIDs (0x1004)` 直接调用重定向到 DeviceInfo 响应（代码区改动） | ❌ LCD 完成、Print session 正常，但 `0x1004` 返回普通 8 字节 StorageIDs 数据 + `0x2001`；未验证 marker 是否激活 | `33c63c8b…283a` |
| 007 | 2026-07-14/15 | 同上重定向 + marker `1.03`（Print/MTP 双模式都确认 marker 激活） | ❌ **marker 已激活但重定向无效**——两种 personality 都返回普通 StorageIDs。排除了"没装上"的解释，就是这条静态改法不生效 | `86ece3d8…b129` |
| **008** | 2026-07-18 | **改 DeviceInfo operation list**：block 0 offset `0x00d59892`，slot 10 广告 `0x100e`（InitiateCapture）替代 stock `0x100b` | ✅ 数据生效：sessionless GetDeviceInfo 返回 20 个操作、slot 10 = 0x100e。随后 session 内发 `InitiateCapture(0,0)`（opcode 0x100e，参数 [0,0]）→ ❌ 相机回 `0x2005 OperationNotSupported`，无新 handle、无图像 | `48def97d…32ab7` |
| 009 | 2026-07-18 | object-handle proxy（marker 1.04 + 同样广告 0x100e），请求 `0x100e [65537,0,0]` | ❌ `0x2005`、零 payload，session 正常关闭 | `abc6a7b1…e302` |
| **010** | 2026-07-18 | **executable-table 改动**（细节未公开，"unproven executable-table change"） | 💀 **变砖**：LCD 更新完成 → power cycle 后无法正常启动、无 USB 枚举、无 PTP。无 crash trace、无失败镜像回读 | `72b16a80…4b2` |

EXP-011..016：EXP-010 之后的设计稿，**未做物理实验即全部撤销**，不构成证据。

**三个层级的结论强度**（这是前人最宝贵的经验框架）：
1. **纯数据改动**（字符串/表）：可刷入、可启动、改动在运行时可见——已两次实证（001/007/008）；
2. **静态代码重定向**（改 call target / 广告表 + 请求）：能刷入能启动，但想激活的操作被拒（006-009）——**"advertisement 改了"≠"handler 活了"**，live dispatch 有额外检查/路径，静态改法不够；
3. **executable-table 改动**：一次样本即变砖（010）——代码区修改安全性完全未建立，构造/传送/LCD 成功都不保证能 boot。

### 4.2 变砖恢复（EXP-010 的救回流程）

- **通道：SD 卡 + 官方 Body 1.6 镜像**。用户把官方 `OLY_E_086_1600_0000_0000.BIN` 放到物理 SD 卡上执行恢复（E-PL3 的已知恢复机制：卡带官方镜像插入后按特定方式上电进入强制更新；公开记录只说"successful SD recovery using the official Body 1.6 image"，未给按键组合——E-PL3 时代社区通用做法是**关机插卡 + 按住 Playback/OK 等组合键上电**，具体组合需另行考证）。
- 结果：恢复正常启动与操作。**用户 attestation 级别**（无卡上文件哈希、无恢复后菜单版本读数）；是一次样本，**不证明有保证的 rollback/dual-bank 机制**。
- 对我们的意义：刷砖的第一救援通道是 SD 强制更新模式；E-M1 III 有没有同机制要提前考证（OM System 时代机身一般也有 SD 恢复，可在无风险状态下先用官方镜像演练一次流程）。

### 4.3 "Host gate" 方法论

EXP-001 的 D2 记录叫 "post-boot host gate"。方法论：

1. **刷之前**在镜像里埋一个**唯一数据 marker**（这里是 DeviceInfo version 字符串改成独特值如 1.01/1.03/1.04）；
2. 刷完 + power cycle 后，**不信任 LCD "更新完成"**，而是从 host 侧发起 PTP 会话查询（GetDeviceInfo），核对 marker 值 + 响应事务 ID；
3. host gate 记录 `marker_confirmed` → 才能断言"修改镜像在运行、且其数据被使用"。

配套纪律（USB_AND_MEDIA.md）：host 工具报错 ≠ 相机拒绝（可能根本没发出去）；LCD 完成 ≠ 安装成功；DeviceInfo version ≠ 机身菜单版本；Print 与 MTP 是不同 personality（payload 长度都不同：167 vs 171 字节），不能拿一个的 payload 验另一个。**E-M1 III Phase 1 的"数据区标记探针"应完全照抄这套 gate 设计**（marker 可选：DeviceInfo version / 厂商字符串 / 某资源字符串）。

---

## 5. PTP / USB 静态发现（对照我们的 libgphoto2 0x9xxx 表）

### 5.1 他们的静态发现（block 0，全部标注"PTP-adjacent"，ingress 未打通）

| 结构 | 位置（local addr / block-0 offset） | 事实 |
|---|---|---|
| **16 字节记录 FIFO** | `0xa07b81cc`（runtime 数据地址） | 初始化：清 256 字节（即 16 条 × 16B）；`0x6f330fba` 追加、`0x6f3307f5` 取队首并压缩；count halfword 在 `0xa07b82cc`（≤16 条）；相邻 `0xa07b82d0` 与 FIFO 同步复位但用途不明。initializer 可用 `dd`+objdump 复现（offset `0x00d30925`） |
| **主 selector dispatcher** | `0x6f32d60c` | 读 `a1+8` 的 halfword 分派，8 个数字臂：**0x1001..0x1008**（= PTP 标准 opcodes：GetDeviceInfo/OpenSession/GetStorageIDs…）；0x1001/02/07/08 臂经 `0x6e61fd8d` 构造/发布 12 字节 descriptor；0x1005/0x1006 臂加载指针 global `0xa07b7058` |
| **厂商扩展 selector 向量** | dispatcher `0x6f33362c`；向量表 `0x6f359da8`（block-0 offset `0x00d58988`，28 词） | 接受 **0x5001..0x501c**，`(sel-0x5001)*4` 索引跳转；slot 0 → `0x6f334a8c`（构造 stack descriptor → `0x6e61fd8d`）。**0x50xx 是 E-PL3 的 Olympus 厂商扩展区段** |
| **注册 caller** | `0x6f330528`（offset `0x00d30548`） | 传 keys **0x100c/0x100d**（d0，各配 d1=2、a1=0）+ callback 字面量 `0x6f33a684`/`0x6f33a805`（a0）→ 调 builder `0x6f3349de` |
| **status 分派** | `0x6f32d9dc` | record `+8` 作 status：0→descriptor builder、1/2/3→各自 bounded body；安装的 callback `0x6f33aa63`（写 `0xa07b702c`）与 `0x6f33e38f`（写 `0xa07b7030`），但 `0x6f33aa63` 的入口无条件跳过内部 `0x5001` selector——**静态相邻 ≠ 执行相连** |
| **handler banks** | 5 组各 16 个 8 字节 slot：`0x6f358b44`/`b c4`/`cc4`/`d44`（+status 0..3） | slot `+0` = sequence、`+4` = handler 指针；record `+8` 序号 mod 16 匹配后 `jmp *(slot+4)`；候选 writer（`0x6e681503`/`0x6e68150d`）写的第二字段是常量 0x1000/0x8000/0，**没有已证的 executable handler** |
| **17 条 descriptor 表** | block-0 offset `0x0008f0e0`，28B/条，keys `0x1001,0x1002,0x100b..0x1019` | `0x100e` 行 = `(0x100e, 0, 3, 0x6e69e7cb, 5, 0x1000, 0)`；共享 target `0x6e69e7cb` 经 `d2+24` 对象 slot `+20` 间接分派。**表存在但无 runtime owner 选择它**——恰与 EXP-008"广告 0x100e 但请求被 0x2005 拒"呼应 |
| **66 条表** | block-0 offset `0x0008b300`，28B/条 | key `0x4e` 行指向 `0x6e708fa2`（某 body 内部 +3），另一条静态 table→interior-entry 边 |
| **reply 打包** | `0xbb02` 字面量 ×5 处 | 16B request 布局 → selector 分派 → 12B reply 打包 → 动态 queued/circular storage（经 `0x6e68939a`，索引 `(d0 & 0x7000) >> 12` 选 owner，owner `+0x3c` 给 queue 指针）；另有 2 个 0x40000 字节的静态 buffer pool（first-fit checkout/release） |
| **MTP lifecycle** | `api_comm_Start/End_Communication_MTP`（block-0 offset `0x00258ccb`/`0x00258d2f`，名字来自固件内符号串） | start/end 各自调用 mount-status helper（d0=1/0）、receive-record submitter（`0x6e85ef16`→`0x6e85f180`，测试 `sp+40` 对 `0x02000100/01/0x02010100/01` 等）与 pump 形 helper；**与上面 FIFO 的 join 未建立** |
| **USB personalities** | — | 静态：23×23 USB 状态转移矩阵（offset `0x00b0e964`）+ 状态名序列；protocol-selection body 比较 `*P` 与 `R+388/392` 选 MassStorage/MTP/PC Link。实测：Storage = `07b4:012c`（mass storage），MTP/Print = `07b4:0113`（still imaging） |

### 5.2 与我们 libgphoto2 Olympus 0x9xxx 表的对照

- E-PL3（2011）固件里发现的厂商 opcode 区段是 **0x100b..0x1019（MTP 标准+Olympus 扩展混排）和 0x5001..0x501c**；**没有 0x9xxx**。0x50xx 段在 E-M1 III 时代应该已被 0x9xxx（OMD 扩展，vendor extension 0xfffd）取代。
- 方法论直接迁移：在 E-M1 III 固件里搜 **以 0x9481/0x911C/0x9121…0x9126 为 key 的 28 字节（或类似定宽）descriptor 表**和 **`(opcode - base) * 4` 形状的跳转表**。前人的教训是：找到表 ≠ 找到 handler；关键缺口永远是 **ingress（谁从 USB transport 把请求喂进来）** 和 **handler admission（dispatch 前的合法性检查）**——EXP-008 证明广告了 0x100e 也会被 `0x2005` 拒，说明 admission 检查在别处。
- 对我们最有价值的目标其实与前人不同：我们要的不是"host 触发拍照"，而是 **0x911C/0x9121–0x9126（固件更新 PTP 命令）的机内实现**——如果 E-M1 III 的更新走 PTP 而非纯 SD，则更新器的校验逻辑（有没有 RSA/signature）就在这些 opcode 的 handler 链上。这是 E-PL3 研究里没有的角度（E-PL3 更新走 SD/官方 updater，不走 PTP vendor 命令）。
- 已实证可用的 read path：MTP 下 OpenSession → GetStorageIDs → GetObjectHandles → GetObjectInfo → GetObject（E-PL3 实测下载 1.95 MB JPEG 成功）；E-M1 III 我们也实测过 download 可用（notes/01）。gphoto2 的 trigger/capture/preview 在 E-PL3 上全是 unsupported——与 E-M1 III 的 Image Capture ❌ 一致；真正的遥控是 OMD 0x9481/0x9484 等命令（Olympus Capture/OI.Share 用）。

---

## 6. 对 E-M1 III 的适用性评估

### 6.1 可直接复用（置信度高）

| 项 | 依据 | 动作 |
|---|---|---|
| **方法论**：byte-free 坐标+哈希引用、host gate marker 验证、三档结论强度（数据✅/静态重定向❓/代码表💀）、实验前写 candidate SHA-256 | 全仓库 | 照搬进 Phase 1 实验设计 |
| **`source.py` 解析器骨架**：链式 header/tail 解析、LE32 加法 checksum、16B lane 置换+XOR 0xFF 的 scramble 框架 | §1 | 换 registry 直接试跑 E-M1 III 镜像；失败点=格式差异所在 |
| **探针策略**：先做纯数据 marker（如 DeviceInfo version / 资源字符串）验证"可刷入+可启动+数据被使用"，再谈代码 | EXP-001 是唯一两次以上成功的通道 | Phase 1 镜像设计 |
| **SD 救砖预期**：官方镜像 + SD 强制更新可救 executable-table 级变砖 | EXP-010 | 刷任何修改镜像前，先用官方镜像在 E-M1 III 上演练一遍 SD 恢复流程（无损） |
| **PTP 静态分析方法**：找 opcode-keyed 定宽 descriptor 表 + `(op-base)*4` 向量 + FIFO/handler-bank 形状 | §5 | 在 E-M1 III 固件里对 0x9xxx 键值搜索 |
| **objdump/Reko 双工具纪律**、7 字节 lookahead、重叠裁决 | §3 | 若 E-M1 III 是 ARM 则换成 objdump -m arm + Ghidra，纪律照搬 |

### 6.2 必须重新验证（不可假设沿用）

| 项 | E-PL3 (2011) | E-M1 III (2020) 风险 | 验证方法 |
|---|---|---|---|
| **CPU 架构** | MN103 (LE) 主核 + H8 (BE) 辅核 | TruePic VIII 世代很可能 ARM（或 ARM+DSP 混合）；block 4 类似物可能不存在/换成别的核 | Phase 3：熵曲线 + 已知指令 pattern（ARM Thumb push/prologue、MN103 `movm`）+ objdump 试译 |
| **Header 字段语义** | 32B，§1.3 布局 | 字段可能增删（如新增签名段、版本字段位宽变化） | hexdump 头 0x40 字节对照；用已知 body 长度交叉验证 `body_length` 字段位置 |
| **Scramble 表** | 16B lane 置换 + XOR 0xFF，flags 0x0100-0x0106 | 置换表几乎必然不同，可能换成 AES | 对零填充区/已知 JPEG（block 3 类资源）做已知明文差分求置换；若差分无结构 → 疑似加密 |
| **Checksum 算法/覆盖** | LE32 加法和，覆盖 header+decoded body+tail[:-4] | 2020 年很可能升级（HMAC/RSA，尤其若有 secure boot） | 改 1 字节重打包试探 host 侧（OM Workspace）是否接受——**只在 host 侧做，不碰相机**；再找更新器二进制里的验签代码 |
| **Block 划分/数量** | 5 块：代码/数据/未知/JPEG/H8 | 块数与角色可能全变（E-M1 III 镜像 ~50MB 级） | 链式解析直接得出；块数不同本身就是信息 |
| **部署通道** | 官方 updater（macOS，"attended update"）+ SD 恢复 | E-M1 III 官方通道 = OM Workspace / OI.Share，且 PTP 侧存在 0x911C/0x9121-0x9126 更新命令 | 抓 OM Workspace 更新时的 USB 流量，确认走 MTP vendor 命令还是 Storage 直写 |
| **签名强度** | host 侧仅加法 checksum（已证）；设备侧未知 | 可能已加 secure boot/RSA | Phase 1 数据 marker 探针直接实测设备端态度 |

### 6.3 前人的失败教训 → 我们的差异化机会

1. 前人卡死在 **ingress/admission**：改静态表和广告都不激活 handler。我们不需要通用的 host-triggered capture——只需要**固件更新命令链**（0x911C/0x9121-26）和**图像管线配置落点**（Picture Mode/色彩矩阵），两个都是"既有功能找实现"，不是"无中生有加功能"，难度低一个量级。
2. 前人的 **block 2（6-bit payload）和 block 4（H8）始终没找到消费者**——提醒我们 E-M1 III 容器里也可能有"看不懂的块"，别在不产生配置接口的块上死磕。
3. 前人 **EXP-010 一发变砖**的教训：executable-table 改动在没有任何仿真/回读手段时等于赌博。我们的顺序必须是：数据探针 → host 侧更新器逆向（看它验什么）→ 再考虑代码区。

---

## 附：本笔记的证据锚点速查

- 容器格式实现：`src/epl3_research/source.py`（HEADER_SIZE/DESCRAMBLE_ORDER/Header.parse/descramble/source_checksum/decode_container）
- 镜像身份 registry：`src/epl3_research/data/source.json`
- 校验流程：`docs/OBTAINING_FIRMWARE.md`、`README.md`（quick start）
- 工具链：`docs/ANALYSIS.md`（binutils 2.45 构建、dd+objdump 窗口、Reko PR #1370）、`docs/DECODING.md`（译码门）、`src/epl3_research/decoding.py`
- 容器完整性/host parser 边界：`docs/firmware/BLOCKS.md#container-integrity`
- 实验实录：`docs/observations/DEPLOYMENT.md`（EXP 表 + D1-D9 源记录哈希）、`docs/observations/USB_AND_MEDIA.md`（U1-U12）
- PTP 静态发现：`docs/firmware/PTP.md`、`MTP_LIFECYCLE.md`、`USB_LIFECYCLE.md`、`USB_STATE.md`、`USB_POLICY.md`
- 坐标/证据约定：`docs/firmware/READING.md`、`docs/EVIDENCE.md`
- 开放问题全表：`docs/RESEARCH.md`（stable ID：r-integrity、r-ptp-ingress、r-block-1..4 等）
