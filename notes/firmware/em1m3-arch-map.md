# E-M1 Mark III 多 CPU 架构图（v1.6 固件解析，2026-10-09）

> 依据：`work/parse-report.md`（`tools/parse_em1m3.py` 全链解析 + strings/熵分析）。
> 结论：E-M1 III 是**多 CPU 混合架构**，比 E-PL3（MN103 主控 + H8 辅助）复杂得多，
> 对"3D LUT 落点"是重大利好（图像管线可能部分在 ARM Linux 侧）。

## 处理器总图

| 处理器 | 固件载体 | 证据（strings） | 职能 |
|---|---|---|---|
| **主控 uITRON**（疑似 MN103 系，待指令级认证） | section 0 @0x40800000 | `E-M1MarkIII`、`- uITRON Error Code -`、`[SYS WANA] ... De Reboot!`、`<arm load/start/shell/jtag>` 调试命令、OIShare 4.40 XML、RCS 标签 `2006/02/20 vova Exp` | flash/NAND 管理（`[FLSH]`、`NACH(0-3)`）、多 CPU 启停 + WDT、WiFi/BLE/OIShare 远程 API、调试 shell |
| **ARM Cortex-A9 ×2**（SoC/板代号 **DC13**） | section 2 @0x43f00000 | `ARM Cortex-A9 start`、`Uncompressing Linux...`、`dc13.dtb`、`/lib/ld-linux.so.3`、`GCC 4.8.4`、`/home/oly/DEV_ENV/stbsp-dc13`、开发路径 `C:\TARGET\zImage`/`rootfscp`/`rootfssq` | Linux + ITRON 双启动载荷（zImage + dtb + rootfs） |
| **SCPU = ARM Cortex-M** | section 5 @0x08000000 | 教科书级 Cortex-M 向量表（SP=0x20020000, Thumb reset 0x0801cf61）、`C:\work\S0118_S0092\Scpu\dev_pack\...`、`ID_TSK_USB_PD_*`/`ID_TSK_CHARGE`/`ID_TSK_FIRMUP_COMP_EXEC` | 按键/转盘/摇杆、USB-PD、充电、电池、电源时序、**固件解压（更新流程关键路径）**。角色 = E-PL3 的 H8 辅助 MCU 演进 |
| **"luke" 双核子系统**（cpu0=mscmd / cpu1=drive） | section 3 @load 0（疑占位） | `0x12345678` 魔数头、`.\luke_main\cpu0\ms\mscmd\task_cmd.c`、`.\luke_main\cpu1\cmd\task_drive.c`、`!NMI!cpu:` | 疑似镜头/机械驱动控制，加载基址待解 |
| CPU1/CPU2（A/D 监控）、WiFi、BLE、TaCPU | 未定位 | `[SYS WANA] CPU1/CPU2 ADDEC De Reboot!` 等仅提及 | — |

主控的调试命令族说明 boot 流程：主控先起 → `load arm linux`/`load arm itron`（from flash 或
`load arm linux from sd`）→ `ARM Cortex-A9 start` → WDT 互相监护（任一 CPU 卡死 → `[SYS WANA] ... De Reboot!`）。

## 对项目路线的影响

1. **3D LUT 落点出现新候选**：原假设图像管线在 MN103/TruePic 专用侧只能改配置表；
   现在 ARM A9 跑 Linux + glibc 用户态，若图像管线（或其配置 UI/参数管理）有部分在
   Linux 侧，hack 面从裸机汇编扩展到 Linux 用户态（ELF 动态链接、脚本、甚至 rootfs 替换），
   工作量可能大幅下降。**待验证：rootfs 里有什么（IPU/ISP 驱动？图像管线服务？）**
2. **Phase 1 探针镜像的落点选择**：数据区（section 1 本地化资源、section 4 JPEG 参数）
   仍是最低风险探针；SCPU 的 `ID_TSK_FIRMUP_COMP_EXEC` 说明更新流程含解压步骤，
   改代码区前必须先搞清 host 端（SCPU? 主控?）到底校验什么
3. **工具链**：
   - section 5 Cortex-M：arm-none-eabi 直接反汇编，门槛最低
   - section 2 ARM 载荷：明文 zImage/dtb/rootfs，binwalk/dtc 即可切，性价比最高
   - section 0 主控：本机暂无 mn103 反汇编器（macOS objdump 无该 target），
     备选：brew binutils 是否带 mn10300 / Ghidra + MN103 插件 / Reko（E-PL3 同款路线）

## 与 E-PL3 容器谱系对照

| E-PL3 (2011) | E-M1 III (2020) | 演进 |
|---|---|---|
| block 0：MN103 主固件 | section 0：uITRON 主控（疑似 MN103 系） | 同角色延续 |
| block 1：数据镜像+本地化（69 条 16B 记录表） | section 1：同构（70 条记录表 + olycompress + UTF-16LE 字典） | 同构放大 |
| block 2：6-bit 编码 payload @0x400 | section 2 rec[0]：同构 @0x400（15MB） | 同构放大 |
| block 3：JPEG 资源包 | section 4：JPEG 参数表 | 同角色 |
| block 4：H8 大端辅助 MCU（64KB） | section 5：Cortex-M SCPU（256KB） | H8 → Cortex-M |
| （无） | section 3：luke 双核驱动子系统 | 新增 |
| （无） | section 2 rec[1..10]：ARM Linux 载荷 | 新增（DC13） |

## 下一步（优先级）

1. 切分 section 2 ARM 载荷（11 条记录逐块导出 → binwalk/dtc/file 识别 zImage/dtb/rootfs）
2. 认证 section 0 ISA（mn103 反汇编途径）
3. 逆向 olycompress（S1 rec[0]/rec[69] 已有 (压缩长, 解压长) 样本对）
4. SCPU 固件反汇编（arm-none-eabi），优先 `sys_firmup_comp.c` 解压路径
5. luke 子系统头格式（0x12345678 魔数）与真实加载基址
