#!/usr/bin/env python3
"""Split rec00 (15MB 6-bit/olycompress suspect) via its nested sub-record table.

rec00 = firmware/work/arm/rec00_0x43f00400.bin, ARM base 0x43f00400, size 0xeffc00.
Same nested format as other recs (see tools/split_arm_chunks.py):
  - 16B slots: (arm_addr LE32, length LE32, 0, 0)
  - payload_start = entry0.arm_addr - base - 0x20  (0x3e0 here = 62 slots)
  - chunk file offset = arm_addr - base - 0x20 (0x20 bias, validated on rec09)
Differences vs other recs: table entries occupy only slots 0..40, rest zero-padded;
chunks tile 0x3e0..0x877278 but file body is nonzero up to 0x88081e (leftover tail
data beyond the table), then zeros; 0x40 tail trailer records at 0xeffbc0.

Per-chunk recon printed: file(1) type, head16 hex, Shannon entropy, 6-bit value
stats (fraction of bytes <= 0x3f, value range, missing values), compression magic
tests + direct zlib/lzma/gzip decompress attempts, ARM/Thumb instruction features.
"""
from __future__ import annotations

import lzma
import math
import struct
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARM_DIR = ROOT / "firmware/work/arm"
REC_PATH = ARM_DIR / "rec00_0x43f00400.bin"
OUT_DIR = ARM_DIR / "rec00_chunks"
BASE = 0x43F00400
ADDR_BIAS = 0x20
TRAILER = 0x40  # two 0x20 records w/ magic 0x4F451390 at file end


def shannon_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    n = len(blob)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def value_stats(blob: bytes) -> str:
    """6-bit style check: bytes limited to <= 0x3f."""
    present = sorted(set(blob))
    le3f = sum(1 for b in blob if b <= 0x3F)
    frac = le3f / len(blob)
    if frac > 0.999:
        missing = sorted(set(range(present[0], present[-1] + 1)) - set(present))
        return (
            f"6bit OK: 100%<=0x3f, range [{present[0]:#04x},{present[-1]:#04x}], "
            f"{len(present)}/64 values, missing={len(missing)}"
            + (f" first-miss={[hex(m) for m in missing[:6]]}" if missing else "")
        )
    if frac > 0.95:
        hi = [b for b in blob if b > 0x3F]
        return f"6bit-ish: {frac:.1%}<=0x3f, {len(hi)} bytes >0x3f (max={max(hi):#04x})"
    return ""


def classify_magic(blob: bytes) -> list[str]:
    tags = []
    if blob[:4] == b"\x1f\x8b\x08":
        tags.append("gzip")
    if blob[:4] == b"\x7fELF":
        tags.append("ELF")
    if blob[:4] == b"\xd0\x0d\xfe\xed":
        tags.append("dtb")
    if blob[:4] == b"hsqs":
        tags.append("squashfs")
    if blob[:2] == b"BZ":
        tags.append("bzip2?")
    if blob[:4] == b"\xfd7zXZ\x00"[:4]:
        tags.append("xz")
    if blob[:4] == b"\x04\x22\x4d\x18":
        tags.append("lz4")
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        tags.append("zstd")
    if blob[:1] == b"\x78" and len(blob) > 2 and blob[1] in (0x01, 0x5E, 0x9C, 0xDA):
        tags.append("zlib?")
    if blob[:6] == b"CRAM":
        tags.append("cramfs")
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        tags.append("PNG")
    if blob[:3] == b"GIF":
        tags.append("GIF")
    if blob[:2] == b"BM":
        tags.append("BMP?")
    return tags


def try_decompress(blob: bytes) -> list[str]:
    """Direct decompress attempts (whole-buffer) for zlib/lzma/gzip."""
    results = []
    try:
        d = zlib.decompressobj()
        out = d.decompress(blob)
        if out:
            results.append(f"zlib-ok({len(out)}B)")
    except Exception:
        pass
    try:
        out = lzma.decompress(blob)
        if out:
            results.append(f"lzma-ok({len(out)}B)")
    except Exception:
        pass
    import gzip as _g

    try:
        out = _g.decompress(blob)
        if out:
            results.append(f"gzip-ok({len(out)}B)")
    except Exception:
        pass
    return results


def arm_features(blob: bytes) -> list[str]:
    feats = []
    nops = blob.count(b"\x00\x00\xa0\xe1")  # nop (ARM)
    if nops >= 4:
        feats.append(f"ARM-nop x{nops}")
    loops = blob.count(b"\xfe\xff\xff\xea")  # 'b .' idle loop
    if loops:
        feats.append(f"b. x{loops}")
    # ARM vector table: first words all 0xeaffffxx (branch w/ small offset)
    if len(blob) >= 32:
        words = struct.unpack_from("<8I", blob, 0)
        if all((w >> 24) == 0xEA for w in words):
            feats.append("ARM-vector-table(b xx)")
    # generic ARM code density: cond-field distribution
    if len(blob) >= 0x400:
        sample = blob[:0x1000]
        cond_ok = 0
        for i in range(0, len(sample) - 4, 4):
            w = struct.unpack_from("<I", sample, i)[0]
            c = w >> 28
            if c == 0xE or c in (0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD):
                cond_ok += 1
        ratio = cond_ok / (len(sample) // 4)
        if ratio > 0.9:
            feats.append(f"ARM-cond-density {ratio:.0%}")
    return feats


def file_type(path: Path) -> str:
    try:
        out = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip()
    except Exception as exc:  # pragma: no cover
        return f"file-error: {exc}"


def main() -> int:
    data = REC_PATH.read_bytes()
    a0, l0 = struct.unpack_from("<II", data, 0)
    if not (BASE < a0 <= BASE + len(data) and 0 < l0 <= len(data)):
        print(f"entry0 insane: 0x{a0:08x}/0x{l0:x}")
        return 1
    payload_start = a0 - BASE - ADDR_BIAS
    n_slots = payload_start // 16
    print(
        f"{REC_PATH.name}: size=0x{len(data):x} base=0x{BASE:08x} "
        f"table=0x{payload_start:x} ({n_slots} slots)"
    )
    print(f"entry0 = (0x{a0:08x}, 0x{l0:x}) -> payload @0x{payload_start:x}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # --- full table dump ---
    print(f"\n=== nested table dump ({n_slots} slots) ===")
    entries: list[tuple[int, int, int, int]] = []  # (slot, addr, length, off)
    filtered = []
    for slot in range(n_slots):
        addr, length = struct.unpack_from("<II", data, slot * 16)
        if addr == 0 and length == 0:
            continue
        off = addr - BASE - ADDR_BIAS
        sane = (
            BASE <= addr < BASE + len(data) + ADDR_BIAS
            and 0 < length <= len(data)
            and off >= payload_start
            and off + length <= len(data) - TRAILER
        )
        mark = "OK" if sane else "FILTERED"
        print(
            f"  slot {slot:2d}: addr=0x{addr:08x} len=0x{length:06x} "
            f"off=0x{off:06x} end=0x{off + length:06x} [{mark}]"
        )
        if sane:
            entries.append((slot, addr, length, off))
        else:
            filtered.append((slot, addr, length))
    print(f"sane entries: {len(entries)}, filtered: {len(filtered)}")

    # --- tiling check ---
    cursor = payload_start
    for slot, addr, length, off in entries:
        if off != cursor:
            print(
                f"  !! slot {slot} not contiguous: off=0x{off:x} "
                f"(expected 0x{cursor:x}, gap=0x{off - cursor:x})"
            )
        cursor = off + length
    print(f"chunks tile 0x{payload_start:x}..0x{cursor:x}")

    # --- export + recon ---
    index_rows = [
        "idx\tarm_addr\tlen\tin_rec_off\tclass\tfile_type\thead16\tentropy\tpath"
    ]
    print("\n=== per-chunk recon ===")
    for slot, addr, length, off in entries:
        blob = data[off : off + length]
        path = OUT_DIR / f"c{slot:02d}_0x{addr:08x}.bin"
        path.write_bytes(blob)
        tags = classify_magic(blob)
        dec = try_decompress(blob)
        feats = arm_features(blob)
        v6 = value_stats(blob)
        ent = shannon_entropy(blob)
        zero_tail = len(blob) - len(blob.rstrip(b"\x00"))
        ftype = file_type(path)
        klass = ";".join(tags + dec + feats) if (tags or dec or feats) else (
            "6bit" if v6.startswith("6bit OK") else ("6bit-ish" if v6 else "?")
        )
        if zero_tail == len(blob):
            klass = "zero-fill"
        elif zero_tail > 0x100:
            klass += f" +zero-tail(0x{zero_tail:x})"
        print(
            f"  c{slot:02d} 0x{addr:08x} len=0x{length:06x} off=0x{off:06x} "
            f"ent={ent:.2f} [{klass}] {ftype}\n"
            f"        head={blob[:16].hex(' ')}"
            + (f"\n        {v6}" if v6 else "")
        )
        index_rows.append(
            f"{slot}\t0x{addr:08x}\t0x{length:x}\t0x{off:x}\t{klass}"
            f"\t{ftype}\t{blob[:16].hex()}\t{ent:.2f}\t{path.name}"
        )

    # --- leftover between last chunk end and trailer ---
    tail = data[cursor : len(data) - TRAILER]
    nz = len(tail.rstrip(b"\x00"))
    print(
        f"\nleftover after table chunks: 0x{len(tail):x} bytes "
        f"(nonzero prefix 0x{nz:x} @0x{cursor:x}..0x{cursor + nz:x})"
    )
    if nz:
        lb = tail[:nz]
        lpath = OUT_DIR / f"leftover_0x{cursor + BASE + ADDR_BIAS:08x}.bin"
        lpath.write_bytes(lb)
        print(
            f"  -> {lpath.name} ent={shannon_entropy(lb):.2f} "
            f"head={lb[:16].hex(' ')} tail={lb[-16:].hex(' ')}"
        )
        index_rows.append(
            f"leftover\t0x{cursor + BASE + ADDR_BIAS:08x}\t0x{nz:x}\t0x{cursor:x}"
            f"\tleftover\t{file_type(lpath)}\t{lb[:16].hex()}\t"
            f"{shannon_entropy(lb):.2f}\t{lpath.name}"
        )

    # --- trailer records ---
    print("\n=== trailer (0x40) ===")
    for i in range(2):
        rec = data[len(data) - TRAILER + i * 0x20 : len(data) - TRAILER + (i + 1) * 0x20]
        magic, _a, addr, size = struct.unpack_from("<IIII", rec, 0)
        ts = struct.unpack_from("<I", rec, 0x18)[0]
        import datetime

        when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        print(
            f"  [{i}] magic=0x{magic:08x} addr=0x{addr:08x} size=0x{size:08x} "
            f"ts={ts} ({when:%Y-%m-%d %H:%M:%S} UTC)"
        )

    (OUT_DIR / "index.tsv").write_text("\n".join(index_rows) + "\n")
    print(f"\nwrote {len(entries)} chunks + leftover + {OUT_DIR / 'index.tsv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
