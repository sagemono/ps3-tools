# lv0_self_extract.py
# Extract embedded SELFs from a decrypted lv0.elf

import sys
import os
import struct


SCE_MAGIC = b"\x53\x43\x45\x00"

AUTH_ID_NAMES = {
    0x1FF0000001000001: "bootldr",
    0x1FF0000002000001: "lv0ldr",
    0x1FF0000003000001: "lv1ldr_old",
    0x1FF0000004000001: "lv2ldr_old",
    0x1FF0000005000001: "isoldr_old",
    0x1FF0000006000001: "appldr_old",
    0x1FF0000007000001: "unk07",
    0x1FF0000008000001: "unk08",
    0x1FF0000009000001: "lv1ldr",
    0x1FF000000A000001: "lv2ldr",
    0x1FF000000B000001: "appldr",
    0x1FF000000C000001: "isoldr",
}

PROG_TYPE_NAMES = {
    1: "lv0",
    2: "lv1",
    3: "lv2",
    4: "application",
    5: "iso_spu_module",
    6: "secure_loader",
    7: "npdrm_application",
    8: "iso_spu_module",
}


def parse_sce_header(data, offset):
    if offset + 0x20 > len(data):
        return None
    magic = data[offset:offset + 4]
    if magic != SCE_MAGIC:
        return None

    version = struct.unpack_from(">I", data, offset + 0x04)[0]
    key_revision = struct.unpack_from(">H", data, offset + 0x08)[0]
    header_type = struct.unpack_from(">H", data, offset + 0x0A)[0]
    metadata_offset = struct.unpack_from(">I", data, offset + 0x0C)[0]
    header_length = struct.unpack_from(">Q", data, offset + 0x10)[0]
    data_length = struct.unpack_from(">Q", data, offset + 0x18)[0]

    if version not in (2, 3) or header_type != 1:
        return None
    if header_length > 0x100000 or data_length > 0x10000000:
        return None

    return {
        "version": version,
        "key_revision": key_revision,
        "header_type": header_type,
        "metadata_offset": metadata_offset,
        "header_length": header_length,
        "data_length": data_length,
        "total_size": header_length + data_length,
    }


def parse_self_extended_header(data, offset):
    base = offset + 0x20
    if base + 0x50 > len(data):
        return None

    return {
        "ext_hdr_version": struct.unpack_from(">Q", data, base + 0x00)[0],
        "program_id_hdr_offset": struct.unpack_from(">Q", data, base + 0x08)[0],
        "ehdr_offset": struct.unpack_from(">Q", data, base + 0x10)[0],
        "phdr_offset": struct.unpack_from(">Q", data, base + 0x18)[0],
        "shdr_offset": struct.unpack_from(">Q", data, base + 0x20)[0],
        "segment_ext_hdr_offset": struct.unpack_from(">Q", data, base + 0x28)[0],
        "version_hdr_offset": struct.unpack_from(">Q", data, base + 0x30)[0],
        "supplemental_hdr_offset": struct.unpack_from(">Q", data, base + 0x38)[0],
        "supplemental_hdr_size": struct.unpack_from(">Q", data, base + 0x40)[0],
    }


def parse_program_id_header(data, offset, pid_offset):
    base = offset + pid_offset
    if base + 0x20 > len(data):
        return None

    auth_id = struct.unpack_from(">Q", data, base)[0]
    vendor_id = struct.unpack_from(">I", data, base + 0x08)[0]
    prog_type = struct.unpack_from(">I", data, base + 0x0C)[0]
    prog_version = struct.unpack_from(">Q", data, base + 0x10)[0]

    return {
        "auth_id": auth_id,
        "vendor_id": vendor_id,
        "prog_type": prog_type,
        "prog_version": prog_version,
    }


def parse_segment_ext_headers(data, offset, seg_ext_offset, count):
    segments = []
    base = offset + seg_ext_offset
    for i in range(count):
        entry_off = base + i * 0x20
        if entry_off + 0x20 > len(data):
            break
        seg_offset = struct.unpack_from(">Q", data, entry_off + 0x00)[0]
        seg_size = struct.unpack_from(">Q", data, entry_off + 0x08)[0]
        compression = struct.unpack_from(">I", data, entry_off + 0x10)[0]
        encryption = struct.unpack_from(">Q", data, entry_off + 0x18)[0]

        segments.append({
            "offset": seg_offset,
            "size": seg_size,
            "compression": compression,
            "encrypted": encryption == 2,
            "compress_name": {1: "plain", 2: "zlib"}.get(compression, f"unk_{compression}"),
        })
    return segments


def self_to_elf(data, self_offset, sce_hdr, ext_hdr):
    base = self_offset
    ehdr_off = ext_hdr["ehdr_offset"]
    phdr_off = ext_hdr["phdr_offset"]
    shdr_off = ext_hdr["shdr_offset"]
    seg_ext_off = ext_hdr["segment_ext_hdr_offset"]

    elf_start = base + ehdr_off
    if elf_start + 0x40 > len(data):
        return None
    ei_class = data[elf_start + 4]
    is_64 = ei_class == 2

    if is_64:
        ehdr_size = 0x40
        phdr_entry_size = 0x38
        shdr_entry_size = 0x40
        e_phnum = struct.unpack_from(">H", data, elf_start + 0x38)[0]
        e_shnum = struct.unpack_from(">H", data, elf_start + 0x3C)[0]
        e_shoff = struct.unpack_from(">Q", data, elf_start + 0x28)[0]
    else:
        ehdr_size = 0x34
        phdr_entry_size = 0x20
        shdr_entry_size = 0x28
        e_phnum = struct.unpack_from(">H", data, elf_start + 0x2C)[0]
        e_shnum = struct.unpack_from(">H", data, elf_start + 0x30)[0]
        e_shoff = struct.unpack_from(">I", data, elf_start + 0x20)[0]

    seg_exts = parse_segment_ext_headers(data, base, seg_ext_off, e_phnum)

    max_offset = ehdr_size + e_phnum * phdr_entry_size
    if e_shoff > 0 and e_shnum > 0:
        max_offset = max(max_offset, e_shoff + e_shnum * shdr_entry_size)

    phdrs = []
    for i in range(e_phnum):
        ph_base = base + phdr_off + i * phdr_entry_size
        if is_64:
            p_offset = struct.unpack_from(">Q", data, ph_base + 0x08)[0]
            p_filesz = struct.unpack_from(">Q", data, ph_base + 0x20)[0]
        else:
            p_offset = struct.unpack_from(">I", data, ph_base + 0x04)[0]
            p_filesz = struct.unpack_from(">I", data, ph_base + 0x10)[0]
        phdrs.append((p_offset, p_filesz))
        if p_filesz > 0:
            max_offset = max(max_offset, p_offset + p_filesz)

    out = bytearray(max_offset)

    out[0:ehdr_size] = data[base + ehdr_off:base + ehdr_off + ehdr_size]

    phdr_data_size = e_phnum * phdr_entry_size
    if is_64:
        elf_phoff = 0x40
    else:
        elf_phoff = 0x34
    out[elf_phoff:elf_phoff + phdr_data_size] = data[base + phdr_off:base + phdr_off + phdr_data_size]

    if is_64:
        struct.pack_into(">Q", out, 0x20, elf_phoff)
    else:
        struct.pack_into(">I", out, 0x1C, elf_phoff)

    for i, (p_offset, p_filesz) in enumerate(phdrs):
        if p_filesz == 0 or i >= len(seg_exts):
            continue
        seg_ext = seg_exts[i]
        src_offset = base + seg_ext["offset"]
        copy_size = min(seg_ext["size"], p_filesz)
        if src_offset + copy_size <= len(data) and p_offset + copy_size <= len(out):
            out[p_offset:p_offset + copy_size] = data[src_offset:src_offset + copy_size]

    if shdr_off > 0 and e_shnum > 0 and base + shdr_off + e_shnum * shdr_entry_size <= len(data):
        sh_size = e_shnum * shdr_entry_size
        if e_shoff + sh_size <= len(out):
            out[e_shoff:e_shoff + sh_size] = data[base + shdr_off:base + shdr_off + sh_size]

    return bytes(out)


def find_embedded_selfs(data):
    """Find all embedded SELF containers in the binary."""
    results = []
    pos = 4  # skip main ELF header
    while pos < len(data):
        idx = data.find(SCE_MAGIC, pos)
        if idx < 0:
            break

        sce = parse_sce_header(data, idx)
        if sce is None:
            pos = idx + 4
            continue

        ext = parse_self_extended_header(data, idx)
        if ext is None:
            pos = idx + 4
            continue

        pid = parse_program_id_header(data, idx, ext["program_id_hdr_offset"])

        results.append({
            "offset": idx,
            "sce": sce,
            "ext": ext,
            "pid": pid,
        })

        pos = idx + 4

    return results


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <lv0.elf> [output_dir]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "lv0_selfs"

    with open(input_file, "rb") as f:
        data = f.read()

    os.makedirs(output_dir, exist_ok=True)

    print(f"Loaded {input_file} ({len(data)} bytes)")
    print(f"Output directory: {output_dir}\n")

    selfs = find_embedded_selfs(data)
    if not selfs:
        print("No embedded SELFs found.")
        sys.exit(1)

    # detect dupes (let's call them backup copies...)
    seen_auth = {}
    for entry in selfs:
        if entry["pid"]:
            aid = entry["pid"]["auth_id"]
            if aid not in seen_auth:
                seen_auth[aid] = 0
            seen_auth[aid] += 1

    copy_counter = {}
    for i, entry in enumerate(selfs):
        sce = entry["sce"]
        ext = entry["ext"]
        pid = entry["pid"]
        offset = entry["offset"]

        auth_id = pid["auth_id"] if pid else 0
        prog_type = pid["prog_type"] if pid else 0
        auth_name = AUTH_ID_NAMES.get(auth_id, f"auth_{auth_id:016X}")
        type_name = PROG_TYPE_NAMES.get(prog_type, f"type_{prog_type}")

        # track 'em
        if auth_id not in copy_counter:
            copy_counter[auth_id] = 0
        copy_num = copy_counter[auth_id]
        copy_counter[auth_id] += 1

        is_backup = copy_num > 0
        suffix = f"_backup{copy_num}" if is_backup else ""
        base_name = f"{auth_name}{suffix}"

        total = sce["total_size"]
        end = offset + total

        print(f"[{i}] {auth_name} ({type_name}){' [BACKUP]' if is_backup else ''}")
        print(f"    Offset: 0x{offset:06X} - 0x{end:06X} (0x{total:X} bytes)")
        print(f"    Auth-ID: 0x{auth_id:016X}")
        print(f"    Key Rev: 0x{sce['key_revision']:04X}")
        print(f"    Header:  0x{sce['header_length']:X}  Data: 0x{sce['data_length']:X}")

        seg_exts = parse_segment_ext_headers(data, offset, ext["segment_ext_hdr_offset"], 8)
        any_encrypted = any(s["encrypted"] for s in seg_exts)
        print(f"    Segments: {len(seg_exts)}, encrypted={any_encrypted}")

        if end <= len(data):
            self_path = os.path.join(output_dir, f"{base_name}.self")
            with open(self_path, "wb") as f:
                f.write(data[offset:end])
            print(f"    -> {self_path}")
        else:
            print(f"    WARNING: SELF extends past EOF (need 0x{end:X}, have 0x{len(data):X})")
            self_path = os.path.join(output_dir, f"{base_name}.self")
            with open(self_path, "wb") as f:
                f.write(data[offset:len(data)])
            print(f"    -> {self_path} (truncated)")

        if not any_encrypted and end <= len(data):
            elf_data = self_to_elf(data, offset, sce, ext)
            if elf_data:
                elf_path = os.path.join(output_dir, f"{base_name}.elf")
                with open(elf_path, "wb") as f:
                    f.write(elf_data)
                print(f"    -> {elf_path} (converted)")
            else:
                print(f"    ELF conversion failed")
        elif any_encrypted:
            print(f"    (encrypted, use scetool/SecureTool to decrypt)")

        print()

    print(f"Extracted {len(selfs)} embedded SELFs to {output_dir}/")


if __name__ == "__main__":
    main()
