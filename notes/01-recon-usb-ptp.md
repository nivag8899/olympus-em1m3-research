# 侦察笔记：USB / PTP / 前人工作（2026-10-09）

## 1. USB 连接实测（MTP 模式）

- macOS `ioreg -p IOUSB`：
  - `E-M1MarkIII`, vendor `OLYMPUS`, idVendor=1972 (0x07B4), idProduct=303 (0x012F),
    serial `BJDA37782`, bcdDevice=256
- gphoto2 2.5.32（brew）连接成功（识别为 "Olympus E-M5"，型号 DB 条目串了，无碍）：
  - Manufacturer: OLYMPUS, Model: E-M1MarkIII, Version: 1.00（DeviceInfo 版本，非机身菜单版本）
  - Vendor Extension ID: **0xfffd**（= PTP_VENDOR_GP_OLYMPUS_OMD）
  - 能力：File Download ✅ / File Deletion ✅ / **File Upload ❌ / Image Capture ❌**
  - **Storage Devices Summary 为空**（MTP 模式不暴露卡，当时也没插卡）
  - 设备属性：BatteryLevel 85%，DateTime，Microsoft MTP 扩展属性 d405/d406/d407
- 结论：MTP 模式 = OI.Share 手机通道，对 Mac 基本无用。
  文件访问走 Storage（PC）模式；遥控走 WiFi API 或 Olympus Capture 的 USB 通道

## 2. libgphoto2 中的 Olympus 私有 PTP 命令（camlibs/ptp2/ptp.h）

### OMD 系列（0xfffd 扩展，来自 Olympus Capture macOS 客户端逆向）

| Opcode | 名称 | 备注 |
|--------|------|------|
| 0x9481 | OMD_Capture | |
| 0x9482 | GetDateTime | |
| 0x9483 | OMD_MagnifyLiveViewPoint | Capture UI 0x03 |
| 0x9484 | GetLiveViewImage | liveview |
| 0x9485 | OMD_GetImage | 从 capture/SDRAM 取 JPEG |
| 0x9486 | OMD_ChangedProperties | 重轮询 (~42 props) |
| 0x9487 | OMD_MFDrive | 手动对焦驱动 |
| 0x9488 | OMD_MagnifyLiveViewArea | Capture UI 0x08 |
| 0x9489 | OMD_SetProperties | 16bit prop 列表批量设置 |
| 0x948A | OMD_PollProperties | 轻轮询 (~15 props) |
| 0x948B | OMD_SetProperties2 | 第二组属性通告 |
| 0x948C | （推测 Record Video） | |
| 0x948D | OMD_OpticalZoomDrive | 变焦驱动 |
| 0x948F–0x9492 | 未知 | 在 Capture UI map 中 |
| 0x9493 | 旧版变焦驱动 | |
| 0x9495 | Set/Clear AF Point? | |
| 0x94A0 | Set/Clear AE Point? | |
| 0x94A1 | OMD_DetectOneTouchWB | Capture UI 0x18 |
| 0x94A4/05 | Get Direct Item Buffer/Info | |
| 0x94B7 | Get Recording Folder List? | |
| 0x94BA | TransferModeStartStop | |
| 0x94BB/BC/BD/BE | UnTransferList / LocalObject 系列 | |
| 0x94BF–C1 | Set/Get/ClearConnectPcInfo | |
| 0x94C2 | GetOTWBKelvin | |
| 0x94C4 | GetAFTargetFrames | |

### ⭐ 固件更新相关（从未被 libgphoto2 实现，注释里全是问号）

| Opcode | 猜测含义 |
|--------|----------|
| 0x911C | Get Firmware Update Mode? |
| 0x9121 | Firmware Check? |
| 0x9122 | Get Firmware Status? |
| 0x9123 | Firmware Update Initiate? |
| 0x9124 | Get Firmware Language? |
| 0x9125 | Get Firmware Status? (2) |
| 0x9126 | **Trans Firmware?** |

> 这些命令的存在说明：**固件可以经由 USB/PTP 传输**（OM Workspace / Digital Camera
> Updater 的更新路径），宿主端协议逆向 = 本地分析 OM Workspace 即可。
> 注意 0x911c/0x912x 与 MTP 扩展区间重叠（MTP_WPDWCN_ProcessWFCObject=0x9122），
> 具体归属需抓包确认。

### E 系列老命令（0x9101–0x9581，E-PL3 世代用）

Capture 0x9101 / SelfCleaning 0x9103 / SetRGBGain 0x9106 / GetDeviceInfo 0x9301 /
SetCameraID 0x9501 / GetCameraID 0x9581 等 —— 与 e-pl3-research 项目的
PTP dispatch 分析可以互相对照。

## 3. 固件分发渠道（E-M1 Mark III）

- 最终版 **v1.6，2023-01-19**（OM System 联合更新服务页，JP 站）
- 分发方式：OM Workspace（macOS/Win）via USB；OI.Share app via WiFi（E-M1 III 支持）
- 老款用 SD 卡 .BIN 直刷（E-PL3 即此路），E-M1 III 待确认（"backup function" 机型列表含 E-M1 III）

## 4. 前人项目索引

- **sympho-ru/olympus-e-pl3-research** — E-PL3 Body 1.6 固件逆向（详见 `02-epl3-prior-art.md`）
  - MN103 主 CPU + H8 辅助 MCU，5 块容器结构
  - 关键实证：修改数据区的镜像成功刷入并启动（EXP-001）；改代码区一次变砖，SD 刷官方镜像救回
  - GNU binutils mn10300 objdump 2.45 + Reko 做指令级分析，有完整证据链方法论
- WiFi API 逆向（可作遥控替代路径，与固件逆向互补）：
  - joergmlpts/olympus-wifi（Python，liveview/拍照/下载/设置/关机）
  - mauriciojost/olympus-photosync、gvalkov/olympus-photosync、evanfoster/py-omd 等
- OM Workspace / Olympus Capture macOS 客户端 = 宿主端协议逆向的本地素材

## 5. gphoto2 环境备忘

```
brew install gphoto2   # 2.5.32, /opt/homebrew
gphoto2 --auto-detect  # 相机需在 MTP 模式；Storage 模式会挂载成磁盘
```

下一步：见 `00-roadmap.md`。
