# patch_lv0_tb_clk_static.py
# Changes the hardcoded 79,800,000 Hz timebase literal to match the actual hardware frequency at a given overclock speed
# Only modifies 4 bytes total (2 bytes in lis, 2 bytes in ori)

import struct
import sys
import os

SYSCON_FREQ_TABLE = {
    300: 300_000_000,
    325: 325_000_000,
    350: 350_000_000,
    367: 366_503_851,
    375: 375_000_000,
    383: 383_328_213,
    400: 400_000_000,
    417: 416_671_787,
    425: 425_000_000,
    433: 433_343_573,
    450: 450_000_000,
    467: 466_656_427,
    475: 475_000_000,
    483: 483_328_213,
    500: 500_000_000,
    517: 516_671_787,
    533: 533_343_573,
    550: 550_000_000,
    567: 566_656_427,
    583: 583_328_213,
    600: 600_000_000,
    617: 616_656_427,
    633: 633_328_213,
    650: 650_000_000,
    667: 666_656_427,
}

CCM = 8
STOCK_TB_CLK = 79_800_000
STOCK_TB_UPPER = 0x04C1
STOCK_TB_LOWER = 0xA6C0

# pattern: lis r5, 0x04C1; ld r4, <toc>(r2); mr r3, r31; ori r5, r5, 0xA6C0
PATCH_SITE_HEAD = bytes([0x3C, 0xA0, 0x04, 0xC1])
PATCH_SITE_TAIL = bytes([0x7F, 0xE3, 0xFB, 0x78, 0x60, 0xA5, 0xA6, 0xC0])

# maps cell GHz string -> ref_clk MHz
GHZ_TO_REF = {}
for _mhz, _hz in SYSCON_FREQ_TABLE.items():
    _ghz_str = f"{(_mhz * CCM) / 1000:.1f}"
    GHZ_TO_REF[_ghz_str] = _mhz


def apply_crystal_correction(raw_hz):
    return raw_hz - (raw_hz // 400)


def compute_tb_clk(corrected_ref_clk):
    refdiv = corrected_ref_clk // STOCK_TB_CLK
    if refdiv == 0:
        refdiv = 1
    return corrected_ref_clk // refdiv, refdiv


def parse_frequency(arg):
    arg = arg.strip().lower()

    if arg.endswith("ghz"):
        ghz_val = arg[:-3].strip()
        if ghz_val in GHZ_TO_REF:
            return GHZ_TO_REF[ghz_val]
        try:
            g = float(ghz_val)
            ref_mhz = round(g * 1000 / CCM)
            if ref_mhz in SYSCON_FREQ_TABLE:
                return ref_mhz
        except ValueError:
            pass
        return None

    try:
        mhz = int(arg)
        if mhz in SYSCON_FREQ_TABLE:
            return mhz
        ref = mhz // CCM
        if ref in SYSCON_FREQ_TABLE:
            return ref
    except ValueError:
        pass

    return None


def print_freq_table():
    print("ref_clk   CELL      corrected_ref    RefDiv  tb_clk         tb_clk_hex")
    print("-" * 80)
    for mhz in sorted(SYSCON_FREQ_TABLE.keys()):
        raw_hz = SYSCON_FREQ_TABLE[mhz]
        corrected = apply_crystal_correction(raw_hz)
        tb_clk, refdiv = compute_tb_clk(corrected)
        cell_ghz = (mhz * CCM) / 1000
        marker = " <-- stock" if mhz == 400 else ""
        print(f"  {mhz:>3} MHz   {cell_ghz:.1f} GHz   {corrected:>13,}    /{refdiv:<3}    "
              f"{tb_clk:>13,}  0x{tb_clk:08X}{marker}")


def find_all(data, pattern, start=0, end=None):
    if end is None:
        end = len(data)
    results = []
    pos = start
    while pos < end:
        idx = data.find(pattern, pos, end)
        if idx == -1:
            break
        results.append(idx)
        pos = idx + 1
    return results


def find_patch_site(data):
    candidates = find_all(data, PATCH_SITE_HEAD)
    for foff in candidates:
        if foff + 16 > len(data):
            continue
        if data[foff + 8 : foff + 16] != PATCH_SITE_TAIL:
            continue
        ld_insn = struct.unpack_from('>I', data, foff + 4)[0]
        if (ld_insn & 0xFFFF0000) != 0xE8820000:
            continue
        if foff + 20 > len(data):
            continue
        bl_insn = struct.unpack_from('>I', data, foff + 16)[0]
        if (bl_insn >> 26) != 18 or (bl_insn & 1) != 1:
            continue
        return foff
    return None


def patch_file(src_path, dst_path, ref_mhz):
    raw_hz = SYSCON_FREQ_TABLE[ref_mhz]
    corrected = apply_crystal_correction(raw_hz)
    tb_clk, refdiv = compute_tb_clk(corrected)
    cell_ghz = (ref_mhz * CCM) / 1000

    upper = (tb_clk >> 16) & 0xFFFF
    lower = tb_clk & 0xFFFF

    print(f"target:  {ref_mhz} MHz ref_clk  ({cell_ghz:.1f} GHz CELL)")
    print(f"  corrected ref_clk: {corrected:,} Hz")
    print(f"  RefDiv:            {refdiv}")
    print(f"  tb_clk:            {tb_clk:,} Hz  (0x{tb_clk:08X})")
    print(f"  lis r5, 0x{upper:04X}     (was 0x{STOCK_TB_UPPER:04X})")
    print(f"  ori r5, r5, 0x{lower:04X}  (was 0x{STOCK_TB_LOWER:04X})")
    print()

    with open(src_path, 'rb') as f:
        data = bytearray(f.read())

    foff = find_patch_site(data)
    if foff is None:
        print("ERROR: could not find stock tb_clk pattern (lis r5, 0x04C1)")
        print("       file may already be patched or is an unsupported firmware version")
        return False

    ori_off = foff + 12

    print(f"  found at file offset 0x{foff:X}")
    print(f"  original bytes: {data[foff:foff+4].hex(' ')} ... {data[ori_off:ori_off+4].hex(' ')}")

    # patch lis immediate (2 bytes at foff+2, foff+3)
    data[foff + 2] = upper >> 8
    data[foff + 3] = upper & 0xFF

    # patch ori immediate (2 bytes at ori_off+2, ori_off+3)
    data[ori_off + 2] = lower >> 8
    data[ori_off + 3] = lower & 0xFF

    # verif
    new_val = ((data[foff + 2] << 8 | data[foff + 3]) << 16) | (data[ori_off + 2] << 8 | data[ori_off + 3])
    assert new_val == tb_clk

    print(f"  patched bytes:  {data[foff:foff+4].hex(' ')} ... {data[ori_off:ori_off+4].hex(' ')}")
    print(f"  {STOCK_TB_CLK:,} -> {tb_clk:,} Hz")

    with open(dst_path, 'wb') as f:
        f.write(data)

    print(f"\nwritten -> {dst_path}")
    return True


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lv0_base.elf> <freq> [output.elf]")
        print()
        print("freq can be:")
        print("  ref_clk in MHz:  475, 500, 450, ...")
        print("  cell clock:      3.8ghz, 4.0ghz, ...")
        print()
        print(f"  {sys.argv[0]} --list   show all frequencies and computed tb_clk values")
        return 1

    if sys.argv[1] == '--list':
        print_freq_table()
        return 0

    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <lv0_base.elf> <freq> [output.elf]")
        return 1

    src = sys.argv[1]
    freq_arg = sys.argv[2]

    if not os.path.isfile(src):
        print(f"ERROR: {src} not found")
        return 1

    ref_mhz = parse_frequency(freq_arg)
    if ref_mhz is None:
        print(f"ERROR: unknown frequency '{freq_arg}'")
        print(f"  run with --list to see valid frequencies")
        return 1

    if len(sys.argv) >= 4:
        dst = sys.argv[3]
    else:
        base, ext = os.path.splitext(src)
        dst = f"{base}_patched{ext}" if ext else f"{src}_patched"

    return 0 if patch_file(src, dst, ref_mhz) else 1


if __name__ == '__main__':
    sys.exit(main())
