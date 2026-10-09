# olympus — E-M1 Mark III 固件逆向

目标：给 Olympus OM-D E-M1 Mark III（TruePic VIII）做固件逆向，
最终在机内图像管线支持自定义 3D LUT（现实形态：1D LUT + 3x3 矩阵 + 1D LUT 近似，
劫持 Picture Mode 曲线/矩阵表，从 SD 卡加载）。

## 目录结构

```
notes/        研究笔记（核心资产，随时更新）
firmware/
  stock/      官方固件镜像（gitignored）
  work/       解包/修改的工作镜像（gitignored）
tools/        分析与构建脚本
third_party/  参考仓库、app bundle 等（gitignored）
work/         临时工作区（gitignored）
```

## 阶段路线

- Phase 0（当前）：拿到 v1.6 官方固件，容器格式分析，摸清更新协议
- Phase 1：数据区标记探针镜像，验证 E-M1 III 的固件签名校验强度
- Phase 2：（若校验强）硬件路线：拆机 dump flash / UART
- Phase 3：Ghidra/objdump 映射图像管线，实现 LUT hook

## 安全红线

- 任何刷机实验前：官方镜像放 SD 卡备好（E-PL3 前例：变砖可 SD 恢复）
- 数据区先行，代码区改动必须有 recovery 预案
- 电池满电，全程看守
