# 会话状态（供新 session 接续）

> 这是 agent 之间的交接文件。**开始工作前先读本文件 + `notes/00-roadmap.md`**；
> 完成一个工作单元后立即更新本文件（含 git commit 状态）。
> 最后更新：2026-10-09 session 2

## 项目一句话

E-M1 Mark III 固件逆向，目标机内自定义 Picture Mode（1D LUT + 3x3 矩阵近似 3D LUT）。
路线：Phase 0 容器/协议 → Phase 1 探针镜像验签强度 → Phase 2（备用）硬件 dump → Phase 3 图像管线 hook。

## 当前阶段：Phase 0

| # | 任务 | 状态 | 备注 |
|---|------|------|------|
| 1 | 官方 v1.6 固件获取 | ✅ | `firmware/stock/OLY_E_139_1600_0000_0000.BIN`（109,838,336 B, gitignored） |
| 2 | E-PL3 前人成果消化 | ✅ | `notes/02-epl3-prior-art.md` |
| 3 | 容器全链解析 + descramble | ✅（session 2, subagent 完成） | `tools/parse_em1m3.py`；6 section 全 checksum PASS、EOF 铺满；产物 `firmware/work/section_*.bin` |
| 4 | CPU 架构确认 | 🔄 大半完成 | 架构图 `notes/firmware/em1m3-arch-map.md`（uITRON 主控 + ARM A9 Linux + Cortex-M SCPU + luke）；**剩：section 0 主控 ISA 认证（需 mn103 反汇编器）** |
| 5 | OM Workspace 更新器静态分析 | 待 | PTP 0x911c/0x9121–0x9126 |
| 6 | Phase 1 探针镜像实验设计 | 待 4 | 数据区标记，验证签名校验强度 |
| 7 | section 2 ARM 载荷切分 + rootfs 侦察 | 待（优先，性价比最高） | 11 条记录逐块导出 → binwalk/dtc |
| 8 | olycompress 逆向 / SCPU 反汇编 / luke 头格式 | 待 | 详见 arch-map 下一步清单 |

## session 2 战果（已 commit）

- 任务 3 完成：容器格式确认与 E-PL3 同构，置乱表逐字节相同
- 新发现：多 CPU 混合架构（roadmap 问题 3/4 部分回答）
- 工具：`tools/parse_em1m3.py`（注意库的 decode_container 有 E-PL3 假设，脚本自写循环）

## 环境备忘（macOS, darwin）

- python3 = /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 (3.11.9)
- E-PL3 解析库：`third_party/olympus-e-pl3-research/src/epl3_research/`
  可复用纯函数：`source.py: Header.parse / descramble / source_checksum`（decode_container 不可用，有 E-PL3 假设）
  `verify_source` / CLI 绑死 E-PL3 registry，不可用
- 反汇编工具现状（session 2 检查）：/usr/bin/objdump（无 mn10300 target）、brew 有 binutils
  （gobjdump 待查是否带 mn10300）、无 ghidra/radare2/arm-none-eabi。
  **待办：装 mn103 反汇编途径**（候选：brew binutils 查 target / Ghidra+MN103 插件 / Reko）
- 产物目录：`firmware/work/`（解析输出）、`work/`（临时）、`tools/`（脚本，要 commit）
- git：main 分支，remote origin = github.com/nivag8899/olympus-em1m3-research；
  firmware/third_party/work 均 gitignored；notes/tools/tasks 是核心资产要 commit；
  **milestone 必须 commit + push（用户要求）**

## 已确认关键事实

- E-M1 III v1.6 容器与 E-PL3 同构：OE 魔数 / model 0x1390 / 32B header / version 0x1600 /
  flags 0x0100 系（置乱表与 E-PL3 逐字节相同）/ 6 section 恰好铺满 0x68c0000
- 多 CPU：S0 uITRON 主控 @0x40800000（疑似 MN103）/ S1 数据+本地化 /
  S2 ARM A9 (DC13) zImage+dtb+rootfs / S3 luke 双核 / S4 JPEG 参数 / S5 Cortex-M SCPU
- 详见 `notes/firmware/em1m3-v16-container.md` + `notes/firmware/em1m3-arch-map.md`

## 下一session接续点

1. **首选：任务 7**（section 2 ARM 载荷切分）——纯明文，工具现成（file/binwalk/dtc 可 brew 装），
   delegate subagent 干；产出 `notes/firmware/em1m3-arm-payload.md`。
   看点：rootfs 里有没有图像管线用户态/驱动（决定 LUT hack 面）
2. 任务 4 收尾：先 `gobjdump --info | grep -i mn103` 查 brew binutils；没有就装 Ghidra（brew install --cask ghidra）+ MN103 插件，或 Reko
3. 并行可做：任务 5（OM Workspace app bundle 静态分析，third_party 里拉 app）/
   任务 8（olycompress：S1 rec[0] 有 (0x000c9cec 压缩, 0x005a549e 解压) 样本对）
4. 每完成一任务：更新本文件 + roadmap，commit + push

## 工作约定

- 每完成一个任务：更新本文件 + `notes/00-roadmap.md`，git commit + push（milestone 必推）
- 探索性脏活（跑解析、批量 strings、熵分析）尽量 delegate subagent，主 session 只做决策和笔记；
  ⚠️ subagent 偶发静默失败（session 2 第一次派发返回空且无文件）——验收产出文件，
  失败就重派或自己干
- 任何刷机实验前重读 README 安全红线
