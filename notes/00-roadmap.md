# Phase 0 路线图与状态

> 目标：搞清 E-M1 Mark III 固件容器格式 + 更新机制校验强度，
> 为「机内 3D LUT / 自定义 Picture Mode」铺路。

## 任务清单

| # | 任务 | 状态 | 产出 |
|---|------|------|------|
| 1 | 官方 v1.6 固件获取 | ✅ 完成 | `firmware/stock/OLY_E_139_1600_0000_0000.BIN` + `notes/firmware/stock-image-provenance.md` |
| 2 | E-PL3 前人成果消化（容器格式/工具链/救砖经验） | ✅ 完成 | `notes/02-epl3-prior-art.md` |
| 3 | 容器分析：binwalk / 熵曲线 / strings / 块结构对照 | 🔄 初步：header 同构确认（`notes/firmware/em1m3-v16-container.md`），待跑 source.py 全链解析 | 同左 |
| 4 | CPU 架构确认（MN103? ARM? 混合?）与工具链 | 待 3 | `tools/` + 笔记 |
| 5 | OM Workspace 更新器静态分析（PTP 0x911c/0x9121–0x9126） | 待 | `notes/03-omworkspace-recon.md` |
| 6 | Phase 1 实验设计：数据区标记探针镜像 | 待 3 | `notes/04-phase1-experiment.md` |

## 关键待验证问题（按优先级）

1. **E-M1 III 固件容器是否与 E-PL3 同构？** ✅ **初步确认同构**（2026-10-09）：
   "OE" 魔数 / model 0x1390 / 32B header 布局 / version "1600" / flags 0x0100（scramble）/
   header checksum=0 全部吻合 E-PL3 格式；待 source.py 跑全链 + descramble 最终确认
2. **签名校验强度**：E-PL3 上改数据区可刷入可启动（EXP-001），改代码区一次变砖但 SD 恢复成功。
   E-M1 III 是否引入 secure boot / RSA 验签？→ Phase 1 用数据区标记探针验证
3. **主 CPU 架构**：若仍是 MN103，binutils mn10300 objdump + Reko 可直接复用；
   若换 ARM（2020 年有可能），Ghidra 直接支持，工作量反而降低
4. **图像管线在哪个核上**：TruePic 的 ISP 部分若是独立 DSP，MN103/ARM 侧只下配置 →
   3D LUT 落点只能是配置表（1D 曲线 + 3x3 矩阵），这决定最终形态

## 已知事实（2026-10-09 侦察）

- 相机：E-M1 Mark III，S/N BJDA37782，USB VID 0x07B4 (OLYMPUS) PID 0x012F（MTP 模式）
- MTP 模式下 gphoto2 可通信（读到电量 85%、DeviceInfo version "1.00"），
  但无存储暴露、无 capture 能力 → 遥控/文件要走 Storage 模式或 WiFi API
- 固件 v1.6 (2023-01-19) 为最终版，官方渠道仍可下载
- libgphoto2 ptp.h 已收录 Olympus OMD 私有命令集：
  - 0x94xx：遥控/取景/MF驱动/变焦（Olympus Capture 逆向产物）
  - **0x911c, 0x9121–0x9126：固件更新相关（Get FW Update Mode / Firmware Check / Trans Firmware 等，未深入研究）**
- 前人项目：`sympho-ru/olympus-e-pl3-research`（E-PL3 固件逆向，活跃，方法论可复用）
