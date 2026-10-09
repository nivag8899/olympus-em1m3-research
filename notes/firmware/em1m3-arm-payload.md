# E-M1 Mark III ARM (DC13) 载荷解包（v1.6 固件，2026-10-09）

> 依据：`tools/split_arm_payload.py`（顶层切分，前次工作）+ `tools/split_arm_chunks.py`（本次，
> 嵌套子表切分，516 子块）+ `dtc` / `unsquashfs` / `cpio` / `zlib` 解包分析。
> 工作区：`firmware/work/arm/`（子块 `chunks/`、深度分析 `analysis/`、rootfs `../rootfs-cpio/` `../rootfs-sq/`）。
> 关联笔记：`em1m3-arch-map.md`（多 CPU 总图）。本笔记回答其悬置问题：**rootfs 里没有图像管线，
> ARM Linux 侧是纯网络伴随系统；3D LUT 落点不在此侧**。详见 §6–§8。

## 1. 顶层记录表（回顾）

section 2（0x3240000 字节，已解扰）开头 0x400 为顶层表：16B 条目 `(ARM 地址 LE32, 长度 LE32, 0, 0)`，
随后 11 条记录顺序平铺（cursor 起始 0x400）：

| rec | ARM 基址 | 大小 | 内容 |
|---|---|---|---|
| 00 | 0x43f00400 | 0xf00400 | 15MB 6-bit 编码区（**未解**，疑似图像引擎/ITRON 载荷） |
| 01 | 0x44e00000 | 0x200000 | 175 个参数小表（曲线类） |
| 02 | 0x45000000 | 0x40000 | 137 个参数小表 |
| 03 | 0x45040000 | 0x40000 | 45 个参数小表 |
| 04 | 0x45080000 | 0x40000 | 126 个参数小表（**BE 浮点系数**） |
| 05 | 0x450c0000 | 0xc00000 | 1 个 1MB 稀疏索引表 |
| 06 | 0x45cc0000 | 0x240000 | 19 个 0x40B 记录块 |
| 07 | 0x45f00000 | 0x40000 | 2 个映射表 |
| 08 | 0x45f40000 | 0xc0000 | 1 个 MODE_* 枚举表（ASCII 标签） |
| 09 | 0x46000000 | 0xe00000 | **Linux 启动集**：3×ARM 代码 + zImage + dtb + rootfs.cpio.gz + squashfs |
| 10 | 0x46e00000 | 0x80000 | 3 个 GIF89a UI 位图 |

## 2. 嵌套子表格式（本次逆向结论）

每个 rec 开头是**嵌套子记录表**，与顶层同构：16B 槽 `(ARM 地址 LE32, 长度 LE32, 0, 0)`。

**表区大小可变**，等于 `条目0.地址 − rec基址 − 0x20`（实测：rec01–04 = 0xbe0/190 槽，
rec05/09 = 0x7e0/126 槽，rec06/07/08/10 = 0x3e0/62 槽）。表区后为子块净荷区，子块**无缝平铺**。

**0x20 偏移规律（已验证成立）**：子块净荷在文件中的起点 = `表内地址 − rec基址 − 0x20`。
四项独立证据（rec09）：

- sub[3] zImage：净荷起点 0x137e0 处为标准 NOP sled（`00 00 a0 e1`×8），
  zImage 魔数 `0x016f2818` 恰在 净荷+0x24 = 0x13804 ✓
- sub[4] dtb 魔数 `D00DFEED` @0x1d0fe0 = 0x1d1000−0x20 ✓
- sub[5] gzip `1f 8b 08` @0x1d1fe0 = 0x1d2000−0x20 ✓
- sub[6] squashfs `hsqs` @0x4887e0 = 0x488800−0x20 ✓

相邻条目地址严格衔接（`addr[i+1] = addr[i] + len[i]`），整段净荷区连续无缝。
语义推测：表内地址 = 真实净荷位置 + 0x20，即加载器可能在每块前预留/附加 0x20 字节描述头
（静态数据无法进一步区分"加载时补头"与"打包时去头"）。

**垃圾槽过滤**：rec09 表区外 0x7e0/0x7f0 处的 `0xeaffffxe` 实为 sub[0] 净荷的前 0x20 字节
（ARM 向量表 `b .` 指令），并非表项——按"地址/长度越界即过滤"规则天然排除，全 516 块无一误判。

**每 rec 文件尾 0x40 尾巴**：两个 0x20 记录 `4F451390 魔数 | 0 | 本rec基址 | 大小−0x40 | 0x100 | 6 | Unix时间戳 | 0`
（第二记录描述下一个 rec）。时间戳全部落在 **2022-12-19 02:34 UTC**（v1.6 打包时刻，
31 秒内连续完成）；Linux rootfs 组件本身构建于 **2020-03-03**（初代开发期，未随 v1.6 重编）。

## 3. 子块识别汇总（516 块）

| 类别 | 数量 | 位置 | 说明 |
|---|---|---|---|
| zImage 内核 | 1 | r09_c03（0x1bd800） | Linux 4.4.127，详见 §4 |
| dtb | 1 | r09_c04（0x1000） | panasonic,dc13，详见 §4 |
| gzip rootfs.cpio（initramfs） | 1 | r09_c05（0x2b6800） | 5.5MB 解压后，详见 §5 |
| squashfs | 1 | r09_c06（0x467000） | 4.6MB lzo，挂 /usr，详见 §5 |
| ARM 代码（无 strings） | 3 | r09_c00/c01/c02 | 0x800/0x12000/0x800，向量表开头；疑似 A9 boot/monitor 段（或 ITRON 残段），待反汇编 |
| GIF89a UI 位图 | 3 | r10_c00/c01/c02 | 1×920 竖条 / 626×180 / 638×57，灰度调色板，启动/界面图形 |
| 参数/资源表 | 506 | rec01–08 | 详见 §7 |

索引：`firmware/work/arm/chunks/index.tsv`（rec/槽位/地址/长度/偏移/类型/文件名）。

## 4. 内核与设备树

**zImage**（r09_c03_0x46013800.bin，piggy gzip @0x4698 已解出 `analysis/vmlinux.bin` 3.56MB）：

```
Linux version 4.4.127 (oly@oly-virtual-machine) (gcc version 4.8.4 (20150619)) #1 PREEMPT Tue Mar 3 13:20:05 JST 2020
```

**dtb**（反编译为 `analysis/r09_c04.dts`，v17，2496B）关键节点：

- `compatible = "panasonic,dc13"`；单核 `cpu@0`（arm,cortex-a9）——dtb 只描述 1 核，
  双核中另一核可能跑裸机/ITRON（见 arch-map）
- GIC @0xa0001000；L2（panasonic,l2-system-cache）@0xa10c/d/2c00000；全局定时器 @0xa0000200
- **内存 `memory@10000000`：0x2400000（36MB）**
- `mmc@99002000`（SDIO0，status=disabled）与 `mmc@9a302000`（SDIO1，okay）→ WiFi 模组 SDIO
- `serial@9a500400`（panasonic,mn-sio，ttyS0=console）与 `serial@98400000`（mn-sioext，ttyS1→BLE）
- `irqcon@99200000`（panasonic,irqcon）
- `chosen.bootargs = "console=ttyS0,115200 rw initrd=0x01000000,0x00340000 slram=mtd0,0x02400000,+0x006A0000 debug"`
  ——initrd 即 r09_c05；slram 把 0x2400000+0x6A0000 映射为 mtd0，承载 squashfs

**dtb 中没有任何 ISP/图像/显示/传感器/v4l2 节点**——该 Linux 不接图像外设。

## 5. rootfs：类型与结构

两份文件系统按 `/etc/fstab` 分工：**cpio initramfs = 根 `/`，squashfs（mtdblock0）= `/usr`**。

**cpio 根（513 项）**：busybox + glibc 2.18 + Olympus 守护进程（全在 `/root/`，ARM EABI5 动态链接 ELF）：
`sccore`（7KB，ISC 主管程序：ISC_attach_mem/ISC_dcache_inv_range 共享内存 API，拉起 wifi 脚本）、
`isc_socket`、`isc_olnet`（OI.Share 网络侧：`manufacturer=Olympus`、**`model_name=IM010`**（E-M1 III 型号码）、
WPS/SSID 配置命令）、`remocon`（遥控）、`blebridge`、`sd_reader`（示例串 `sd_reader r C:/DCIM/100OLYMP/P0000001.JPG /tmp/...`
——主侧文件系统桥）、`wifi_mdns`、`wifi_upnp`、`dc13_rtc`、**`hhhr`**（43KB，见 §6）、
`file`（sem_fileif 文件 ISC 服务）、`wl_test`；`/var/www/fcgi-bin/isc_cgi + isc_file`
（lighttpd+FastCGI 相机 HTTP API；isc_file 含 MIME `image/jpeg`、**`image/x-olympus-orf`**、`video/quicktime`）；
`/lib/firmware/`：BCM4345C0 蓝牙 hcd + **cyw43455** sta/softap 固件 + olympus NVRAM 文本；
`/lib/modules/4.4.127/`：`bcmdhd.ko`（Broadcom WiFi）、`mn-sdmmc.ko`（Panasonic SDIO）、
**`iscdrv.ko`**（author=Panasonic Corporation，构建路径
`/home/feng/linux_project/190221-dc13_nep1_isc_test/5_test_config2/isc-dc13/build/linuxdrv/iscdrv_linux.c`，
模块参数 `config_isc_mem_addr/cb_addr/cb_size/channel_nr/drv_lock_id` = 与主处理器的共享内存通道配置）。

**squashfs /usr（264 inode）**：纯网络工具链——curl/wget/telnet/tftp、hostapd/wpa_supplicant、
dnsmasq/miniupnpd/mdnsd（mDNS/Bonjour）、iptables、lighttpd 全家桶、libbsa（Broadcom 蓝牙）、`wl`。

**启动流程**（init → rcS）：
`S01logging` → `S20isc`（insmod iscdrv.ko，mknod /dev/isc）→ `S20urandom` → `S40network` →
`wifi`（BLE：bsa_server@ttyS1 + blebridge；WiFi：modprobe mn-sdmmc + lighttpd + dnsmasq +
isc_socket + remocon + isc_olnet + wifi_upnp + wifi_mdns）→ `S99oly`（dc13_rtc 对时 + sccore + **hhhr &**）。
无 /home/oly（该串只出现在构建路径里）；`/home/default`、`/home/ftp` 为空目录。

## 6. 图像管线搜索结论（核心问题）

**ARM Linux 侧不存在图像管线。** 证据：

1. **内核**：vmlinux 解包后 strings 检索 `v4l2` 命中 **0** 次；无任何 media/ISP/fb 驱动痕迹；
   dtb 无图像外设节点（§4）。
2. **rootfs 文件名+内容**全量扫描（isp/ipu/image/pipe/lut/gamma/matrix/color/picture/jpeg/raw/
   develop/movie/video/dram/v4l2/media/liveview/preview）：命中的全部是假阳性——
   libm 的 `gamma` 数学函数、busybox 子串、lighttpd `mime.conf`、dhcpcd hostname、
   iptables 工具——无一是图像代码。
3. 图像数据最多**流经**此侧而不被处理：`isc_file` 只是按 MIME 把主侧生成的 JPEG/ORF/MOV
   经 HTTP 送出（OI.Share 下载服务），`sd_reader` 是主侧 DCIM 文件搬运工。
   liveview 推测同理（ISC 转发，本侧无编码/解码代码）。

**唯一例外——`hhhr`**：43KB 守护进程，含矩阵乘法例程（`(MulMat) input/output matrix size error`）、
`/dev/mem` 物理内存访问、sem 信号量 + ISC 收发（ISC_receive_wait / ISC_send_timeout /
ISC_dcache_clean_range）。即：主处理器通过 ISC 把**矩阵运算卸载到 A9**。
进程名与 E-M1 III 招牌功能 **HHHR = Handheld High Res（手持超高像素）** 高度吻合——
手持像素合成需要对齐/运动矩阵运算。待反汇编确认（下一步）。
这说明 A9 是主侧的**数学协处理器**（至少对 HHHR），但仍不是色彩/色调管线。

## 7. rec01–rec08 参数表初析（506 块）

这些是**图像处理风味的结构化参数表**，但消费者不在此 Linux rootfs（无任何进程读取它们；
最可能的主顾是 rec00 解码后的图像引擎载荷，或主控）。初步分类：

- **rec01**（175 块，0x200–0x3600）：曲线/查表类。头部形如 `00 01 00 00 00 04 06 0a 06 …`，
  递进小值序列；c80 尾部有一段单调递减 ASCII 序列（u→t→s→…→!，疑似 ASCII 编码的渐变映射）与
  `WWWW` 填充。
- **rec02**（137 块）：`08 01`/`08 05`/`08 06` 型头部 + 递进字节 + `ff xx` 差分式曲线数据。
- **rec03**（45 块）：头部含 **LE16 断点 20/60/100/150/250/300**（增益/百分比分档）+
  5-bit 输入斜坡（00 06 0d 13 19 1f）+ **递减字节多元组**（如 `5a 3e 29 18 0b 07`、`5a 41 2c 1c 0d`）
  ——疑似多通道色调/混色表。
- **rec04**（126 块）：**大端 float32 系数数组**。断点头 `00 00 05 0a 0f` 后接 BE 浮点：
  `3f 80 40 00` = 1.00390625、`3f 80 20 00` = 1.001953125（≈1+1/256 的增益簇），
  `bb xx xx xx` ≈ −0.005 簇、`39 xx xx xx` ≈ +3e-4 簇——**色调曲线/彩色矩阵系数表的最强候选**。
- **rec05**（1 块 1MB）：稀疏 LE32 索引/标志库（194 个 0x600–0x1800 非零区，间隔 ~0x1c00）。
- **rec06**（19 块，0x600–0x5b200）：0x40B 定长记录，`e0 ff ff ff`/`00 80 82 ff` 标记 + 0xff 填充
  ——校准/波形类，格式未定。
- **rec07**（2 块）：4 字节组，第二字段单调递增（09,11,18,1d,22,26,…）——位置/时序映射表
  （疑似镜头驱动）。
- **rec08**（1 块 0x60000）：**ASCII 标签枚举表**，每 0x34 字节一项：MODE_DRIVE、MODE_AE、
  MODE_EXPREV、MODE_APERTURE、MODE_SHUTTER、MODE_AUTOBKT、MODE_ISO、MODE_SHARP、MODE_CONTRAST、
  MODE_WB、MODE_QUALITY（SHQ/HQ/SQ1/SQ2）、MODE_STROBE、…、**MODE_RAW**、MODE_MEDIA、MODE_EXPOSE、
  MODE_FOCUS、MODE_CAMERA、MODE_THROUGH、MODE_PLAYZOOM、MODE_DIGITAL_ZOOM、MODE_NR、
  MODE_DIAL_MAIN、MODE_FOCUS_RING、MODE_WB_REV……——拍摄菜单/远程控制模式全集，
  与 OI.Share 遥控参数面（或主控菜单资源）对应。

## 8. 对 3D LUT 项目的影响判断

**结论：3D LUT hack 不可能落在 ARM Linux 侧，落点仍在主图像处理器侧。**

理由：
1. 内核无 media/V4L2/显示子系统，dtb 无图像外设——Linux 侧物理上碰不到图像数据通路；
2. rootfs 是纯网络伴随系统（WiFi/BLE/HTTP/文件桥），无任何色彩代码；
3. 图像数据仅以"成品文件"形式流经（isc_file/sd_reader 转发），本侧无解码/处理能力；
4. hhhr 证明 A9 可被主侧当数学协处理器用，但其职责是几何/运动矩阵，不是颜色。

**但有两条积极副产物**：
- rec04 的 **BE-float 曲线/矩阵表**与 rec03 的多通道分档表是全固件里最像"色彩科学参数"的
  结构化数据。它们存放在 ARM 载荷 section 里、按 ARM 地址编址，但 Linux 不消费——
  消费者极可能是 **rec00（15MB 6-bit 编码区）解码后的图像引擎**。破解 rec00（olycompress）
  后应优先比对 rec03/rec04 表格式与引擎内引用，那里才是 3D LUT 的家。
- ARM 侧 rootfs 是**完全可替换/可改造面**（gzip+dtb+内核都在明文区，且 `<arm load linux from sd>`
  调试命令存在于主控 shell）：未来做遥测/自定义遥控 API、甚至借 ISC 通道读主侧内存做
  LUT 探针，这条 Linux 侧是低风险的实验入口。

## 9. 下一步

1. **解码 rec00**（15MB 6-bit/olycompress）：验证是否 ARM ITRON/图像引擎载荷；比对 rec03/rec04
   表格格式的引用者（3D LUT 项目主线索）。
2. 反汇编 `hhhr`（+ `iscdrv.ko` 的 `config_isc_*` 参数默认值）：绘制主↔A9 共享内存通道图，
   确认 HHHR 数据流；顺带为"从 Linux 侧读主侧内存"铺路。
3. 从 `analysis/vmlinux.bin` 提取 kallsyms，反汇编 r09_c00/c01/c02（无 strings 的 ARM 代码段，
   疑似 boot/monitor，也可能与双核 ITRON 启动有关）。
4. rec06（0x40B 记录）与 rec05（稀疏索引）格式逆向；rec07 与镜头驱动表的关联。
5. rec10 GIF 与 UI 资源的对应关系（低优先级）。

## 附：产出物清单

| 文件 | 说明 |
|---|---|
| `tools/split_arm_chunks.py` | 嵌套子表切分器（含 0x20 偏移规律实现与垃圾槽过滤） |
| `firmware/work/arm/chunks/`（516 + index.tsv） | 全部子块 + TSV 索引 |
| `firmware/work/arm/analysis/r09_c04.dts` | dtb 反编译 |
| `firmware/work/arm/analysis/vmlinux.bin` / `.strings` | 内核解包（4.4.127） |
| `firmware/work/arm/analysis/rootfs.cpio(.gz)` / `cpio-listing.txt` | initramfs 解包与清单 |
| `firmware/work/rootfs-listing.txt` | squashfs 目录树（264 项） |
| `firmware/work/rootfs-cpio/`、`firmware/work/rootfs-sq/` | 两套文件系统解包树 |
