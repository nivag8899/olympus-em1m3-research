#!/usr/bin/env python3
"""Split section 2 (ARM DC13 payload) into per-record blocks and scan magics."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "firmware/work/section_02_0x43f00000.bin"
OUT = ROOT / "firmware/work/arm"
TABLE_END = 0x400

MAGICS: list[tuple[str, bytes, int]] = [
    ("dtb", struct.pack(">I", 0xD00DFEED), 0),
    ("squashfs", b"hsqs", 0),
    ("squashfs(BE)", b"sqsh", 0),
    ("cramfs", struct.pack(">I", 0x28CD3D45), 0),
    ("cramfs(LE)", struct.pack("<I", 0x28CD3D45), 0),
    ("ELF", b"\x7fELF", 0),
    ("uImage", struct.pack(">I", 0x27051956), 0),
    ("gzip", b"\x1f\x8b\x08", 0),
    ("xz", b"\xfd7zXZ\x00", 0),
    ("lzma_legacy", b"\x5d\x00\x00", 0),
    ("cpio", b"070701", 0),
    ("zImage_arm", b"ARM\x9c", 0x24),
    ("u-boot fb", b"U-Boot ", 0),
]


def read_table(data: bytes) -> list[tuple[int, int]]:
    records = []
    for off in range(0, TABLE_END, 16):
        arm_addr, length = struct.unpack_from("<II", data, off)
        if arm_addr == 0 and length == 0:
            continue
        if not (0x40000000 <= arm_addr < 0x50000000) and length < 0x100:
            continue
        records.append((arm_addr, length))
    return records


def scan_magics(blob: bytes) -> list[tuple[int, str]]:
    hits = []
    for name, magic, fixed_off in MAGICS:
        if fixed_off:
            if blob[fixed_off : fixed_off + len(magic)] == magic:
                hits.append((fixed_off, name))
        else:
            start = 0
            while True:
                idx = blob.find(magic, start)
                if idx < 0:
                    break
                hits.append((idx, name))
                start = idx + 1
                if len(hits) > 200:
                    break
    return sorted(hits)


def main() -> None:
    data = SRC.read_bytes()
    OUT.mkdir(parents=True, exist_ok=True)
    records = read_table(data)
    print(f"source={SRC.name} size={len(data):#x} records={len(records)}")

    cursor = TABLE_END
    for idx, (arm_addr, length) in enumerate(records):
        blob = data[cursor : cursor + length]
        path = OUT / f"rec{idx:02d}_0x{arm_addr:08x}.bin"
        path.write_bytes(blob)
        hits = scan_magics(blob)
        head = blob[:16].hex(" ")
        print(
            f"rec[{idx:2d}] arm=0x{arm_addr:08x} len=0x{length:08x} "
            f"@in-section 0x{cursor:08x} -> {path.name} head=[{head}]"
        )
        for off, name in hits[:15]:
            print(f"         magic {name} @0x{off:x}")
        if len(hits) > 15:
            print(f"         ... {len(hits) - 15} more magic hits")
        cursor += length
    print(f"end cursor=0x{cursor:x} (expect 0x2f80000; file ends 0x{len(data):x})")


if __name__ == "__main__":
    sys.exit(main())
