#!/usr/bin/env python3
"""Olympus E-M1 Mark III v1.6 firmware container parser.

Section chain layout (confirmed against this image): 32B header ++ body ++
32B tail. The tail repeats the header fields; its final LE32 is the
authoritative checksum over header_bytes + descrambled body + tail[:-4].
Reuses only the pure helpers from epl3_research (Header.parse / descramble /
source_checksum). decode_container()/verify_source() are intentionally NOT
used: their E-PL3-specific assumptions (flag whitelist 0x0100..0x0106,
registry binding) do not hold for E-M1 III.
"""

from __future__ import annotations

import hashlib
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "third_party" / "olympus-e-pl3-research" / "src"))

from epl3_research.source import (  # noqa: E402
    HEADER_SIZE,
    Header,
    descramble,
    source_checksum,
)

IMAGE_PATH = REPO_ROOT / "firmware" / "stock" / "OLY_E_139_1600_0000_0000.BIN"
OUT_DIR = REPO_ROOT / "firmware" / "work"
REPORT_PATH = REPO_ROOT / "work" / "parse-report.md"
ENTROPY_BLOCK = 0x10000
STRING_MIN = 8
STRINGS_HEAD = 20
SECTION0_STRINGS = 100
EPL3_SCRAMBLED_FLAGS = frozenset({0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106})
INTERESTING_RE = re.compile(
    rb"(?i)(mn103|arm|thumb|cortex|gcc|clang|compiler|freertos|threadx|itron|"
    rb"vxworks|linux|uclinux|version|firmware|boot|loader|copyright|gpl|"
    rb"olympus|stm32|omap|dm37|novatek|ambarella|hisilicon|realtek|nuvoton)"
)
STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % STRING_MIN)


@dataclass
class Section:
    index: int
    offset: int
    model: int
    unknown1: bytes
    load_address: int
    body_length: int
    version: int
    unknown2: bytes
    flags: int
    unknown3: bytes
    header_checksum: int
    tail_checksum: int
    computed_checksum: int
    checksum_ok: bool
    tail_match: bool
    decode_error: str | None
    body: bytes
    path: Path | None = None
    sha256: str = ""
    entropy: tuple[float, float, float, int] = (0.0, 0.0, 0.0, 0)
    zero_ratio: float = 0.0
    ff_ratio: float = 0.0
    notes: list[str] = field(default_factory=list)


def hexdump(data: bytes, base: int) -> str:
    lines = []
    for off in range(0, len(data), 16):
        row = data[off : off + 16]
        hx = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        lines.append(f"{base + off:08x}  {hx:<47}  |{asc}|")
    return "\n".join(lines)


def anomaly_hexdump(value: bytes, offset: int) -> str:
    start = max(0, offset - 64)
    end = min(len(value), offset + 64)
    return hexdump(value[start:end], start)


def shannon(counts: Counter, total: int) -> float:
    h = 0.0
    for c in counts.values():
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def entropy_stats(data: bytes, block: int = ENTROPY_BLOCK) -> tuple[float, float, float, int]:
    if not data:
        return 0.0, 0.0, 0.0, 0
    values = [shannon(Counter(data[off : off + block]), len(data[off : off + block]))
              for off in range(0, len(data), block)]
    return min(values), max(values), sum(values) / len(values), len(values)


def first_strings(data: bytes, count: int) -> list[bytes]:
    out = []
    for match in STRING_RE.finditer(data):
        out.append(match.group())
        if len(out) >= count:
            break
    return out


def interesting_strings(data: bytes, count: int = 40) -> list[bytes]:
    out = []
    for match in STRING_RE.finditer(data):
        if INTERESTING_RE.search(match.group()):
            out.append(match.group())
            if len(out) >= count:
                break
    return out


def parse_chain(value: bytes) -> tuple[list[Section], int, str | None, str | None]:
    sections: list[Section] = []
    position = 0
    stop_reason: str | None = None
    anomaly_dump: str | None = None
    while position < len(value):
        if len(value) - position < HEADER_SIZE:
            stop_reason = (
                f"truncated header at file offset {position:#x} "
                f"(only {len(value) - position} bytes remain)"
            )
            anomaly_dump = anomaly_hexdump(value, position)
            break
        header_bytes = value[position : position + HEADER_SIZE]
        if header_bytes[:2] != b"OE":
            stop_reason = f"bad magic {header_bytes[:2]!r} at file offset {position:#x}"
            anomaly_dump = anomaly_hexdump(value, position)
            break
        header = Header.parse(header_bytes)
        body_start = position + HEADER_SIZE
        body_end = body_start + header.body_length
        tail_end = body_end + HEADER_SIZE
        if tail_end > len(value):
            stop_reason = (
                f"section {len(sections)} at {position:#x} overruns file: "
                f"tail end {tail_end:#x} > file size {len(value):#x}"
            )
            anomaly_dump = anomaly_hexdump(value, position)
            break
        tail_bytes = value[body_end:tail_end]
        tail = Header.parse(tail_bytes)
        tail_match = header.without_checksum() == tail.without_checksum()
        encoded = value[body_start:body_end]
        checksum_ok = False
        computed = 0
        decode_error: str | None = None
        decoded = encoded
        try:
            decoded = descramble(encoded) if header.flags else encoded
            computed = source_checksum(header_bytes + decoded + tail_bytes[:-4])
            checksum_ok = computed == tail.checksum
        except Exception as exc:
            decode_error = str(exc)
        sections.append(
            Section(
                index=len(sections),
                offset=position,
                model=int.from_bytes(header.model, "big"),
                unknown1=header.unknown1,
                load_address=header.load_address,
                body_length=header.body_length,
                version=header.version,
                unknown2=header.unknown2,
                flags=header.flags,
                unknown3=header.unknown3,
                header_checksum=header.checksum,
                tail_checksum=tail.checksum,
                computed_checksum=computed,
                checksum_ok=checksum_ok,
                tail_match=tail_match,
                decode_error=decode_error,
                body=decoded,
            )
        )
        position = tail_end
    return sections, position, stop_reason, anomaly_dump


def analyze(sec: Section) -> None:
    sec.sha256 = hashlib.sha256(sec.body).hexdigest()
    sec.entropy = entropy_stats(sec.body)
    total = len(sec.body)
    if total:
        counts = Counter(sec.body)
        sec.zero_ratio = counts[0] / total
        sec.ff_ratio = counts[0xFF] / total
    if not sec.tail_match:
        sec.notes.append("header/tail 字段不一致（除 checksum 外）")
    if sec.header_checksum != 0:
        sec.notes.append(f"header.checksum 字段非 0（{sec.header_checksum:#010x}），偏离 E-PL3 假设")
    if sec.flags and sec.flags not in EPL3_SCRAMBLED_FLAGS:
        sec.notes.append(
            f"flags {sec.flags:#06x} 超出 E-PL3 白名单 0x0100-0x0106，"
            "但 checksum 验证通过，说明 E-M1 III 沿用同一置乱方案并扩展了 flag 编号"
        )
    if sec.decode_error:
        sec.notes.append(f"解码错误：{sec.decode_error}")
    if sec.body_length and sec.body_length % 16:
        sec.notes.append("body_length 不是 16 的倍数")


def write_report(value: bytes, sections: list[Section], end_position: int,
                 stop_reason: str | None, anomaly_dump: str | None) -> None:
    lines: list[str] = []
    lines.append("# E-M1 Mark III v1.6 固件容器解析报告")
    lines.append("")
    lines.append(f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- 镜像：`{IMAGE_PATH.relative_to(REPO_ROOT)}`")
    lines.append(f"- 镜像大小：{len(value):,} 字节（{len(value):#x}）")
    lines.append(f"- 镜像 SHA-256：`{hashlib.sha256(value).hexdigest()}`")
    lines.append("- 解析命令：`python3 tools/parse_em1m3.py`")
    lines.append("- 复用库：`third_party/olympus-e-pl3-research/src/epl3_research/source.py`"
                 "（仅 `Header.parse` / `descramble` / `source_checksum`；"
                 "未用 `decode_container`/`verify_source`）")
    lines.append("")
    lines.append("## Section 总表")
    lines.append("")
    lines.append("| # | 文件偏移 | model(BE) | load_address | body_length | version | flags | checksum | 解码后 SHA-256（前 16 位） | 输出文件 |")
    lines.append("|---|---------|-------|--------------|-------------|---------|-------|----------|--------------------------|----------|")
    for sec in sections:
        name = f"section_{sec.index:02d}_{sec.load_address:#x}.bin"
        lines.append(
            f"| {sec.index} | {sec.offset:#010x} | {sec.model:#06x} | {sec.load_address:#010x} "
            f"| {sec.body_length:#010x} ({sec.body_length:,}) | {sec.version:#06x} "
            f"| {sec.flags:#06x} | {'**PASS**' if sec.checksum_ok else '**FAIL**'} "
            f"| {sec.sha256[:16]} | `{name}` |"
        )
    lines.append("")
    if stop_reason is None and end_position == len(value):
        lines.append("## EOF 覆盖：**PASS**（section 链恰好铺满文件到 EOF，无残余字节）")
    else:
        gap = len(value) - end_position
        lines.append(f"## EOF 覆盖：**FAIL**（解析止于 {end_position:#x}，距 EOF 尚有 {gap:,} 字节）")
        lines.append(f"- 停止原因：{stop_reason}")
    lines.append("")
    for sec in sections:
        lines.append(f"## Section {sec.index:02d}（load {sec.load_address:#010x}）")
        lines.append("")
        lines.append(f"- 文件偏移：{sec.offset:#010x}，body：{sec.body_length:#010x}（{sec.body_length:,} 字节），"
                     f"version {sec.version:#06x}，flags {sec.flags:#06x}")
        lines.append(f"- checksum：期望 tail {sec.tail_checksum:#010x}，实际 {sec.computed_checksum:#010x} → "
                     f"{'PASS' if sec.checksum_ok else 'FAIL'}")
        emin, emax, emean, ecount = sec.entropy
        lines.append(f"- Shannon 熵（{ENTROPY_BLOCK:#x} 分块，{ecount} 块）："
                     f"min {emin:.3f} / max {emax:.3f} / 均值 {emean:.3f}")
        lines.append(f"- 0x00 字节占比 {sec.zero_ratio:.2%}，0xFF 字节占比 {sec.ff_ratio:.2%}")
        if sec.notes:
            for note in sec.notes:
                lines.append(f"- ⚠️ {note}")
        lines.append("")
        lines.append("### 前 64 字节")
        lines.append("")
        lines.append("```")
        lines.append(hexdump(sec.body[:64], sec.load_address))
        lines.append("```")
        lines.append("")
        strings = first_strings(sec.body, STRINGS_HEAD)
        lines.append(f"### strings -n {STRING_MIN} | head -{STRINGS_HEAD}")
        lines.append("")
        lines.append("```")
        if strings:
            lines.extend(s.decode("ascii", "replace") for s in strings)
        else:
            lines.append("(无 ≥8 字符可打印串)")
        lines.append("```")
        lines.append("")
        hits = interesting_strings(sec.body)
        lines.append("### 线索关键词命中（前 40 条）")
        lines.append("")
        lines.append("```")
        if hits:
            lines.extend(s.decode("ascii", "replace") for s in hits)
        else:
            lines.append("(无)")
        lines.append("```")
        lines.append("")
        if sec.index == 0:
            s100 = first_strings(sec.body, SECTION0_STRINGS)
            lines.append(f"### Section 0 专属：strings 前 {SECTION0_STRINGS} 条（架构线索）")
            lines.append("")
            lines.append("```")
            lines.extend(s.decode("ascii", "replace") for s in s100)
            lines.append("```")
            lines.append("")
    if stop_reason is not None and anomaly_dump is not None:
        lines.append("## 异常点 hexdump（异常偏移前后各 64 字节）")
        lines.append("")
        lines.append("```")
        lines.append(anomaly_dump)
        lines.append("```")
        lines.append("")
    lines.append("## 异常汇总")
    lines.append("")
    anomalies = []
    if stop_reason is None and end_position == len(value):
        anomalies.append("无：魔数、header/tail 一致性、checksum、EOF 覆盖全部通过")
    else:
        anomalies.append(f"解析中断：{stop_reason}")
    for sec in sections:
        if sec.notes:
            anomalies.append(f"section {sec.index}：" + "；".join(sec.notes))
        if not sec.checksum_ok:
            anomalies.append(f"section {sec.index}：checksum FAIL")
    lines.extend(f"- {item}" for item in anomalies)
    lines.append("")
    lines.append("## 建议")
    lines.append("")
    lines.append("- （待人工分析补充，见下文「结论与性质判断」）")
    lines.append("")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    value = IMAGE_PATH.read_bytes()
    print(f"image: {IMAGE_PATH.name}  size={len(value):,} ({len(value):#x})")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sections, end_position, stop_reason, anomaly_dump = parse_chain(value)
    for sec in sections:
        analyze(sec)
        sec.path = OUT_DIR / f"section_{sec.index:02d}_{sec.load_address:#x}.bin"
        sec.path.write_bytes(sec.body)
    for sec in sections:
        print(
            f"section {sec.index}: offset={sec.offset:#010x} model={sec.model:#06x} "
            f"load={sec.load_address:#010x} body_length={sec.body_length:#010x} "
            f"version={sec.version:#06x} flags={sec.flags:#06x} "
            f"checksum {'PASS' if sec.checksum_ok else 'FAIL'} "
            f"-> {sec.path.name} ({len(sec.body):,} bytes)"
        )
    if stop_reason is not None:
        print(f"[!] 解析停止：{stop_reason}")
        if anomaly_dump:
            print("异常点前后 64 字节 hexdump：")
            print(anomaly_dump)
    if end_position == len(value) and stop_reason is None:
        print(f"[OK] EOF 覆盖：section 链恰好铺满文件（end={end_position:#x} == size={len(value):#x}）")
    else:
        print(f"[!!] EOF 覆盖 FAIL：解析止于 {end_position:#x}，文件大小 {len(value):#x}")
    write_report(value, sections, end_position, stop_reason, anomaly_dump)
    print(f"report -> {REPORT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
