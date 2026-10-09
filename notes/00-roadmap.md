# Phase 0 路线图与状态

> 目标：搞清 E-M1 Mark III 固件容器格式 + 更新机制校验强度，
> 为「机内 3D LUT / 自定义 Picture Mode」铺路。

## 任务清单

| # | 任务 | 状态 | 产出 |
|---|------|------|------|
| 1 | 官方 v1.6 固件获取 | ✅ 完成 | `firmware/stock/OLY_E_139_1600_0000_0000.BIN` + `notes/firmware/stock-image-provenance.md` |
| 2 | E-PL3 前人成果消化（容器格式/工具链/救砖经验） | ✅ 完成 | `notes/02-epl3-prior-art.md` |
| 3 | 容器分析：binwalk / 熵曲线 / strings / 块结构对照 | ✅ 完成（2026-10-09） | `tools/parse_em1m3.py` + `notes/firmware/em1m3-v16-container.md`（6 section 全 PASS、EOF 铺满、置乱表与 E-PL3 相同） |
| 4 | CPU 架构确认（MN103? ARM? 混合?）与工具链 | 🔄 大半完成：多 CPU 架构图已出（`notes/firmware/em1m3-arch-map.md`）；section 0 主控 ISA 待指令级认证 | 同左 |
| 5 | OM Workspace 更新器静态分析（PTP 0x911c/0x9121–0x9126） | 待 | `notes/03-omworkspace-recon.md` |
| 6 | Phase 1 实验设计：数据区标记探针镜像 | 待 4 | `notes/04-phase1-experiment.md` |
| 7 | section 2 ARM 载荷切分（zImage/dtb/rootfs）+ rootfs 内容侦察 | 待（新增，性价比最高） | `notes/firmware/em1m3-arm-payload.md` |
| 8 | olycompress 逆向 / SCPU (Cortex-M) 固件反汇编 / luke 头格式 | 待（新增） | — |

## 关键待验证问题（按优先级）

1. **E-M1 III 固件容器是否与 E-PL3 同构？** ✅ **确认同构**（2026-10-09 全链解析）：
   6 section 全部 checksum PASS、EOF 恰好铺满；置乱表（lane 置换 + XOR 0xFF）逐字节相同；
   flags 扩展至 0x0107/0x010e 但方案不变 → `tools/parse_em1m3.py` 可重复产出
2. **签名校验强度**：E-PL3 上改数据区可刷入可启动（EXP-001），改代码区一次变砖但 SD 恢复成功。
   E-M1 III 是否引入 secure boot / RSA 验签？→ Phase 1 用数据区标记探针验证；
   已知 SCPU 侧有 `ID_TSK_FIRMUP_COMP_EXEC`（更新含解压步骤），校验主体待定位
3. **主 CPU 架构**：✅ 混合架构确认（`notes/firmware/em1m3-arch-map.md`）：
   uITRON 主控（疑似 MN103 系，待认证）+ ARM Cortex-A9 ×2 Linux（DC13）+ Cortex-M SCPU
   + luke 双核驱动子系统。工具链：Cortex-M/ARM 载荷现成；主控需 mn103 途径
4. **图像管线在哪个核上**：⬆️ 优先级提升——若管线部分在 ARM Linux 侧（rootfs 内
   用户态服务/驱动），LUT hack 面从裸机配置表扩展到 Linux 用户态，工作量可能大降；
   先切 section 2 rootfs 看内容（新任务 7）

## 已知事实（2026-10-09 侦察）

- 相机：E-M1 Mark III，S/N BJDA37782，USB VID 0x07B4 (OLYMPUS) PID 0x012F（MTP 模式）
- MTP 模式下 gphoto2 可通信（读到电量 85%、DeviceInfo version "1.00"），
  但无存储暴露、无 capture 能力 → 遥控/文件要走 Storage 模式或 WiFi API
- 固件 v1.6 (2023-01-19) 为最终版，官方渠道仍可下载
- libgphoto2 ptp.h 已收录 Olympus OMD 私有命令集：
  - 0x94xx：遥控/取景/MF驱动/变焦（Olympus Capture 逆向产物）
  - **0x911c, 0x9121–0x9126：固件更新相关（Get FW Update Mode / Firmware Check / Trans Firmware 等，未深入研究）**
- 前人项目：`sympho-ru/olympus-e-pl3-research`（E-PL3 固件逆向，活跃，方法论可复用）
