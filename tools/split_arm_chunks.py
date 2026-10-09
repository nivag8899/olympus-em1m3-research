#!/usr/bin/env python3
"""Split each ARM payload record (rec01..rec10) into sub-chunks via nested tables.

Nested sub-record table format (validated on rec09 / rec01):
  - 16-byte slots: (arm_addr LE32, length LE32, 0, 0)
  - table region is variable-sized and ends where the payload area begins;
    payload_start = entry0.arm_addr - rec_base - 0x20
    (rec09: 0x7e0 = 126 slots, rec01: 0xbe0 = 190 slots, rec06/07/08/10: 0x3e0)
  - sub-chunk payload file offset = arm_addr - rec_base - 0x20
    0x20 bias verified by four independent magics on rec09:
      sub[3] zImage magic 0x016f2818 at payload+0x24 (0x13804)
      sub[4] dtb D00DFEED, sub[5] gzip 1f 8b 08, sub[6] squashfs hsqs
    all exactly at (table_addr - base - 0x20); chunks tile contiguously.
  - garbage slots (e.g. ARM branch words 0xeaffffxe after the table region)
    are filtered by address/length sanity checks; zero slots are padding.
"""
from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARM_DIR = ROOT / "firmware/work/arm"
CHUNKS = ARM_DIR / "chunks"
ADDR_BIAS = 0x20  # table addr -> stored payload offset delta


def classify(blob: bytes) -> list[str]:
    tags = []
    if len(blob) >= 0x28:
        if struct.unpack_from("<I", blob, 0x24)[0] == 0x016F2818:
            entry = struct.unpack_from("<I", blob, 0x28)[0]
            tags.append(f"ARM-zImage(entry=0x{entry:08x})")
    if blob[:4] == b"\xd0\x0d\xfe\xed":
        size = struct.unpack_from(">I", blob, 4)[0]
        tags.append(f"dtb(totalsize=0x{size:x})")
    if blob[:4] == b"hsqs":
        tags.append("squashfs(le)")
    if blob[:4] == b"sqsh":
        tags.append("squashfs(be)")
    if blob[:3] == b"\x1f\x8b\x08":
        tags.append("gzip")
    if blob[:4] == b"\x7fELF":
        tags.append("ELF")
    if blob[:4] == b"\x27\x05\x19\x56":
        tags.append("uImage")
    if blob[:6] == b"070701":
        tags.append("cpio")
    if blob[:6] == b"\xfd7zXZ\x00":
        tags.append("xz")
    if blob[:4] == b"CRAM":
        tags.append("cramfs")
    return tags


def file_type(path: Path) -> str:
    try:
        out = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip()
    except Exception as exc:  # pragma: no cover
        return f"file-error: {exc}"


def main() -> int:
    CHUNKS.mkdir(parents=True, exist_ok=True)
    recs = sorted(p for p in ARM_DIR.glob("rec*_0x*.bin") if not p.name.startswith("rec00"))
    index_rows = ["rec\tslot\tarm_addr\tlen\tfile_off\tclass\tfile_type\tpath"]

    for rec_path in recs:
        data = rec_path.read_bytes()
        base = int(rec_path.stem.split("_0x")[1], 16)
        a0, l0 = struct.unpack_from("<II", data, 0)
        # entry0 must be sane, else treat the whole rec as table-less blob
        if not (base < a0 <= base + len(data) and 0 < l0 <= len(data)):
            print(f"{rec_path.name}: no nested table (entry0 = 0x{a0:08x}/0x{l0:x}), skipped")
            continue
        payload_start = a0 - base - ADDR_BIAS

        entries: list[tuple[int, int, int]] = []  # (slot, addr, len)
        for slot in range(payload_start // 16):
            addr, length = struct.unpack_from("<II", data, slot * 16)
            if addr == 0 and length == 0:
                continue
            off = addr - base - ADDR_BIAS
            sane = (
                base <= addr < base + len(data) + ADDR_BIAS
                and 0 < length <= len(data)
                and off >= payload_start
                and off + length <= len(data)
            )
            if sane:
                entries.append((slot, addr, length))
            else:
                print(
                    f"  {rec_path.name}: slot {slot} filtered "
                    f"(addr=0x{addr:08x} len=0x{length:x})"
                )

        # tiling check
        cursor = payload_start
        for slot, addr, length in entries:
            off = addr - base - ADDR_BIAS
            if off != cursor:
                print(
                    f"  {rec_path.name}: slot {slot} not contiguous "
                    f"(off=0x{off:x}, expected 0x{cursor:x})"
                )
            cursor = off + length

        print(
            f"\n{rec_path.name}: base=0x{base:08x} size=0x{len(data):x} "
            f"table=0x{payload_start:x} ({payload_start // 16} slots) "
            f"entries={len(entries)} blocks end=0x{cursor:x} "
            f"leftover=0x{len(data) - cursor:x}"
        )

        for slot, addr, length in entries:
            off = addr - base - ADDR_BIAS
            blob = data[off : off + length]
            path = CHUNKS / f"r{rec_path.stem[3:5]}_c{slot:02d}_0x{addr:08x}.bin"
            path.write_bytes(blob)
            tags = classify(blob)
            ftype = file_type(path)
            print(
                f"  c{slot:02d} 0x{addr:08x} len=0x{length:06x} off=0x{off:06x} "
                f"[{', '.join(tags) if tags else '-'}] {ftype} "
                f"head={blob[:16].hex(' ')}"
            )
            index_rows.append(
                f"{rec_path.stem[3:5]}\t{slot}\t0x{addr:08x}\t0x{length:x}"
                f"\t0x{off:x}\t{';'.join(tags) if tags else '?'}\t{ftype}\t{path.name}"
            )

        # magic scan of any unindexed leftover tail
        tail = data[cursor:]
        if len(tail) > 0x100:
            hits = []
            for magic, name in (
                (b"\xd0\x0d\xfe\xed", "dtb"),
                (b"hsqs", "squashfs"),
                (b"\x1f\x8b\x08", "gzip"),
                (b"\x7fELF", "ELF"),
                (b"070701", "cpio"),
            ):
                start = 0
                while True:
                    idx = tail.find(magic, start)
                    if idx < 0:
                        break
                    hits.append(f"{name}@0x{cursor + idx:x}")
                    start = idx + 1
            if any(tail.strip()):
                nz = len(tail) - next(
                    (i for i in range(len(tail) - 1, -1, -1) if tail[i]), -1
                ) - 1
                print(
                    f"  leftover tail: 0x{len(tail):x} bytes "
                    f"(last nonzero at +0x{len(tail) - nz:x}), magics: {hits or 'none'}"
                )

    (CHUNKS / "index.tsv").write_text("\n".join(index_rows) + "\n")
    total = len(index_rows) - 1
    print(f"\nwrote {total} chunks + {CHUNKS / 'index.tsv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
