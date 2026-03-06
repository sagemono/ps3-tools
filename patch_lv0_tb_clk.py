# patch_lv0_tb_clk.py
# Patches lv0 base ELF to compute tb_clk dynamically.

import struct
import sys
import os

# constants

# instruction pattern at the hardcoded tb_clk site (4 instructions, 16 bytes):
#   lis  r5, 0x4C1          3C A0 04 C1
#   ld   r4, <toc>(r2)      E8 82 xx xx  (TOC offset may vary per build)
#   mr   r3, r31            7F E3 FB 78
#   ori  r5, r5, 0xA6C0     60 A5 A6 C0
PATCH_SITE_HEAD = bytes([0x3C, 0xA0, 0x04, 0xC1])
PATCH_SITE_TAIL = bytes([0x7F, 0xE3, 0xFB, 0x78, 0x60, 0xA5, 0xA6, 0xC0])

# LFSR table signature: entries 0-7 (RefDiv 0 through 7)
LFSR_TABLE_SIGNATURE = bytes([0x00, 0xFF, 0x7F, 0x3F, 0x9F, 0x4F, 0x27, 0x13])

# the LFSR bytes we overwrite (entries 32-39, 32 bytes) for verification
LFSR_CAVE_ORIGINAL = bytes([
    0x0E, 0x07, 0x83, 0xC1, 0x60, 0x30, 0x18, 0x8C,
    0x46, 0xA3, 0x51, 0xA8, 0xD4, 0x6A, 0x35, 0x9A,
    0xCD, 0x66, 0x33, 0x99, 0x4C, 0xA6, 0xD3, 0xE9,
    0xF4, 0xFA, 0xFD, 0x7E, 0xBF, 0xDF, 0xEF, 0xF7,
])

# pattern to locate get_reference_clock: "mr r29, r3" immediately after a bl
MR_R29_R3 = bytes([0x7C, 0x7D, 0x1B, 0x78])

NOP = bytes([0x60, 0x00, 0x00, 0x00])
CODE_CAVE_SIZE = 32  # 8 instructions


# elf helpers

def parse_elf64_segments(data):
    if data[:4] != b'\x7fELF':
        return None
    if data[4] != 2 or data[5] != 2:  # ELF64, big-endian
        return None

    e_phoff = struct.unpack_from('>Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('>H', data, 0x36)[0]
    e_phnum = struct.unpack_from('>H', data, 0x38)[0]

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('>I', data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from('>Q', data, off + 0x08)[0]
        p_vaddr = struct.unpack_from('>Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('>Q', data, off + 0x20)[0]
        p_memsz = struct.unpack_from('>Q', data, off + 0x28)[0]
        segments.append({
            'vaddr': p_vaddr,
            'offset': p_offset,
            'filesz': p_filesz,
            'memsz': p_memsz,
        })
    return segments


def va_to_file_offset(segments, va):
    for seg in segments:
        if seg['vaddr'] <= va < seg['vaddr'] + seg['filesz']:
            return seg['offset'] + (va - seg['vaddr'])
    return None


def file_offset_to_va(segments, foff):
    for seg in segments:
        if seg['offset'] <= foff < seg['offset'] + seg['filesz']:
            return seg['vaddr'] + (foff - seg['offset'])
    return None


# ppc64 encoding

def encode_branch(source_va, target_va, link=False):
    displacement = target_va - source_va
    if displacement < -(1 << 25) or displacement >= (1 << 25):
        raise ValueError(
            f"branch displacement {displacement:#x} out of range "
            f"(source={source_va:#x}, target={target_va:#x})"
        )
    insn = 0x48000000 | (1 if link else 0) | (displacement & 0x03FFFFFC)
    return struct.pack('>I', insn)


def decode_branch_target(insn_bytes, insn_va):
    insn = struct.unpack('>I', insn_bytes)[0]
    if (insn >> 26) != 18:
        return None
    li = insn & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    if (insn >> 1) & 1:  # AA
        return li
    return insn_va + li


# pattern search

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


def find_patch_site(data, segments):
    main_seg = None
    for seg in segments:
        if seg['vaddr'] >= 0x8000000:
            main_seg = seg
            break
    if main_seg is None:
        return None, None

    seg_start = main_seg['offset']
    seg_end = seg_start + main_seg['filesz']

    candidates = find_all(data, PATCH_SITE_HEAD, seg_start, seg_end)

    for foff in candidates:
        # check tail pattern at +8
        if foff + 16 > len(data):
            continue
        if data[foff + 8 : foff + 16] != PATCH_SITE_TAIL:
            continue

        # verify ld r4, <offset>(r2) at +4
        ld_insn = struct.unpack_from('>I', data, foff + 4)[0]
        if (ld_insn & 0xFFFF0000) != 0xE8820000:
            continue

        # verify bl (branch-and-link) at +16
        if foff + 20 > len(data):
            continue
        bl_insn = struct.unpack_from('>I', data, foff + 16)[0]
        if (bl_insn >> 26) != 18 or (bl_insn & 1) != 1:
            continue

        va = file_offset_to_va(segments, foff)
        return foff, va

    return None, None


def find_get_reference_clock(data, segments, patch_foff, patch_va):
    for i in range(4, 512, 4):
        mr_off = patch_foff - i
        if mr_off < 4:
            break
        if data[mr_off : mr_off + 4] != MR_R29_R3:
            continue

        bl_off = mr_off - 4
        bl_bytes = data[bl_off : bl_off + 4]
        bl_insn = struct.unpack('>I', bl_bytes)[0]
        if (bl_insn >> 26) != 18 or (bl_insn & 1) != 1:
            continue

        bl_va = file_offset_to_va(segments, bl_off)
        if bl_va is None:
            continue

        target = decode_branch_target(bl_bytes, bl_va)
        if target is None:
            continue

        # next instruction after mr r29,r3 should be another bl (get_core_clock_multiplier)
        next_off = mr_off + 4
        if next_off + 4 <= len(data):
            next_insn = struct.unpack_from('>I', data, next_off)[0]
            if (next_insn >> 26) == 18 and (next_insn & 1) == 1:
                return target, va_to_file_offset(segments, target)

    return None, None


def find_lfsr_table(data, segments):
    main_seg = None
    for seg in segments:
        if seg['vaddr'] >= 0x8000000:
            main_seg = seg
            break
    if main_seg is None:
        return None, None

    seg_start = main_seg['offset']
    seg_end = seg_start + main_seg['filesz']

    matches = find_all(data, LFSR_TABLE_SIGNATURE, seg_start, seg_end)
    if not matches:
        return None, None
    if len(matches) > 1:
        print(f"  warning: {len(matches)} LFSR table candidates, using first")

    foff = matches[0]
    va = file_offset_to_va(segments, foff)
    return foff, va


# code cave assembly

def build_code_cave(cave_va, get_ref_clk_va, toc_offset_bytes, return_va):
    """
    assemble the 8-instruction code cave:
        bl   get_reference_clock     # r3 = actual ref_clk
        lis  r5, 0x4C1               # \.
        ori  r5, r5, 0xA6C0          # / r5 = 79800000
        divd r6, r3, r5              # r6 = RefDiv
        divd r5, r3, r6              # r5 = actual tb_clk
        ld   r4, <toc_off>(r2)       # r4 = "be.0.tb_clk"
        mr   r3, r31                 # r3 = config buffer
        b    <return_va>             # -> bl config_string_append_entry
    """
    code = bytearray()
    code += encode_branch(cave_va + 0, get_ref_clk_va, link=True)
    code += bytes([0x3C, 0xA0, 0x04, 0xC1])          # lis r5, 0x4C1
    code += bytes([0x60, 0xA5, 0xA6, 0xC0])          # ori r5, r5, 0xA6C0
    code += bytes([0x7C, 0xC3, 0x2B, 0xD2])          # divd r6, r3, r5
    code += bytes([0x7C, 0xA3, 0x33, 0xD2])          # divd r5, r3, r6
    code += bytes([0xE8, 0x82]) + toc_offset_bytes    # ld r4, <toc>(r2)
    code += bytes([0x7F, 0xE3, 0xFB, 0x78])          # mr r3, r31
    code += encode_branch(cave_va + 28, return_va, link=False)
    assert len(code) == CODE_CAVE_SIZE
    return bytes(code)


# -- main ---------------------------------------------------------------------

def patch_file(src_path, dst_path):
    with open(src_path, 'rb') as f:
        data = bytearray(f.read())

    print(f"loaded {src_path} ({len(data)} bytes)")

    segments = parse_elf64_segments(data)
    if segments is None:
        print("ERROR: not a valid ELF64 big-endian file")
        print("       extract base ELF first: SecureTool -b lv0.elf lv0")
        return False

    load_segs = [s for s in segments if s['vaddr'] >= 0x8000000]
    if not load_segs:
        print("ERROR: no LOAD segment at VA 0x8000000+")
        return False

    for s in load_segs:
        end_va = s['vaddr'] + s['filesz']
        print(f"  segment: VA {s['vaddr']:#010x}-{end_va:#010x}  "
              f"file {s['offset']:#08x}  size {s['filesz']:#x}")

    # find all targets

    patch_foff, patch_va = find_patch_site(data, segments)
    if patch_va is None:
        # check if already patched
        print("ERROR: hardcoded tb_clk pattern not found")
        print("       (may already be patched, or unsupported firmware version)")
        return False

    toc_offset_bytes = bytes(data[patch_foff + 6 : patch_foff + 8])
    return_va = patch_va + 0x10

    ref_clk_va, _ = find_get_reference_clock(data, segments, patch_foff, patch_va)
    if ref_clk_va is None:
        print("ERROR: could not locate get_reference_clock()")
        return False

    lfsr_foff, lfsr_va = find_lfsr_table(data, segments)
    if lfsr_va is None:
        print("ERROR: LFSR lookup table not found")
        return False

    cave_va = lfsr_va + 0x20
    cave_foff = lfsr_foff + 0x20
    cave_end_va = cave_va + CODE_CAVE_SIZE

    # verify cave is within loaded segment
    seg = load_segs[0]
    seg_end_va = seg['vaddr'] + seg['filesz']
    if cave_va < seg['vaddr'] or cave_end_va > seg_end_va:
        print(f"ERROR: code cave {cave_va:#010x}-{cave_end_va:#010x} "
              f"outside segment {seg['vaddr']:#010x}-{seg_end_va:#010x}")
        return False

    print(f"  patch site:           VA {patch_va:#010x}  (build_clock_config_string)")
    print(f"  return point:         VA {return_va:#010x}  (bl config_string_append_entry)")
    print(f"  get_reference_clock:  VA {ref_clk_va:#010x}")
    print(f"  LFSR table:           VA {lfsr_va:#010x}")
    print(f"  code cave:            VA {cave_va:#010x}  (LFSR entries 32-39)")

    # verify LFSR cave bytes
    actual_cave = bytes(data[cave_foff : cave_foff + CODE_CAVE_SIZE])
    if actual_cave != LFSR_CAVE_ORIGINAL:
        print(f"ERROR: unexpected bytes at code cave (LFSR entries 32-39)")
        print(f"  expected: {LFSR_CAVE_ORIGINAL.hex(' ')}")
        print(f"  found:    {actual_cave.hex(' ')}")
        return False

    # build patches

    cave_code = build_code_cave(cave_va, ref_clk_va, toc_offset_bytes, return_va)
    patch_site_new = encode_branch(patch_va, cave_va, link=False) + NOP * 3

    # now apply it

    print()
    orig_site = data[patch_foff : patch_foff + 16].hex(' ')
    data[patch_foff : patch_foff + 16] = patch_site_new
    print(f"  patch site:  {orig_site}")
    print(f"           ->  {patch_site_new.hex(' ')}")

    orig_cave = data[cave_foff : cave_foff + CODE_CAVE_SIZE].hex(' ')
    data[cave_foff : cave_foff + CODE_CAVE_SIZE] = cave_code
    print(f"  code cave:   {orig_cave}")
    print(f"           ->  {cave_code.hex(' ')}")

    # verify

    print()
    ok = True

    b_target = decode_branch_target(data[patch_foff:patch_foff+4], patch_va)
    match = b_target == cave_va
    ok &= match
    print(f"  verify branch to cave:   {b_target:#010x}  {'OK' if match else 'FAIL'}")

    bl_target = decode_branch_target(data[cave_foff:cave_foff+4], cave_va)
    match = bl_target == ref_clk_va
    ok &= match
    print(f"  verify bl ref_clock:     {bl_target:#010x}  {'OK' if match else 'FAIL'}")

    ret = decode_branch_target(data[cave_foff+28:cave_foff+32], cave_va+28)
    match = ret == return_va
    ok &= match
    print(f"  verify return branch:    {ret:#010x}  {'OK' if match else 'FAIL'}")

    if not ok:
        print("\nERROR: verification failed")
        return False

    with open(dst_path, 'wb') as f:
        f.write(data)

    print(f"\nwritten -> {dst_path}")
    print()
    print("rebuild SELF:")
    print(f"  SecureTool -ms {dst_path} -e 1 -o lv0_new lv0")
    return True


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lv0_base.elf> [output.elf]")
        print()
        print("input:  base ELF extracted with SecureTool -b")
        print("output: patched ELF (default: <input>_patched.elf)")
        return 1

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"ERROR: {src} not found")
        return 1

    if len(sys.argv) >= 3:
        dst = sys.argv[2]
    else:
        base, ext = os.path.splitext(src)
        dst = f"{base}_patched{ext}" if ext else f"{src}_patched"

    return 0 if patch_file(src, dst) else 1


if __name__ == '__main__':
    sys.exit(main())
