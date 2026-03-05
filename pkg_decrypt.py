# pkg_decrypt.py
# Decrypt data sections from PKG files
# Some bruteforcing code is still left over but it should work as is :P

import sys
import struct
import zlib
import argparse


def _get_aes():
    try:
        from Crypto.Cipher import AES
        return AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
            return AES
        except ImportError:
            print("ERROR: pycryptodome required. Install with:", file=sys.stderr)
            print("  pip install pycryptodome", file=sys.stderr)
            sys.exit(1)


def aes_cbc_decrypt(data, key, iv):
    AES = _get_aes()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def aes_ctr_decrypt(data, key, iv):
    AES = _get_aes()

    counter_val = int.from_bytes(iv, "big")
    ctr = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=counter_val)
    return ctr.decrypt(data)

def parse_hex(s):
    s = s.replace(" ", "").replace(":", "")
    return bytes.fromhex(s)


def parse_int_auto(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def parse_sce_header(data):
    if len(data) < 0x20:
        return None

    magic = struct.unpack_from(">I", data, 0x00)[0]
    if magic != 0x53434500:
        return None

    return {
        "magic": magic,
        "version": struct.unpack_from(">I", data, 0x04)[0],
        "key_revision": struct.unpack_from(">H", data, 0x08)[0],
        "header_type": struct.unpack_from(">H", data, 0x0A)[0],
        "metadata_offset": struct.unpack_from(">I", data, 0x0C)[0],
        "header_length": struct.unpack_from(">Q", data, 0x10)[0],
        "data_length": struct.unpack_from(">Q", data, 0x18)[0],
    }


def parse_metadata_header(data, offset):
    return {
        "sig_input_length": struct.unpack_from(">Q", data, offset)[0],
        "unknown_0": struct.unpack_from(">I", data, offset + 0x08)[0],
        "section_count": struct.unpack_from(">I", data, offset + 0x0C)[0],
        "key_count": struct.unpack_from(">I", data, offset + 0x10)[0],
        "opt_header_size": struct.unpack_from(">I", data, offset + 0x14)[0],
    }


def parse_metadata_section(data, offset):
    return {
        "data_offset": struct.unpack_from(">Q", data, offset + 0x00)[0],
        "data_size": struct.unpack_from(">Q", data, offset + 0x08)[0],
        "type": struct.unpack_from(">I", data, offset + 0x10)[0],
        "program_index": struct.unpack_from(">I", data, offset + 0x14)[0],
        "hashed": struct.unpack_from(">I", data, offset + 0x18)[0],
        "sha1_index": struct.unpack_from(">I", data, offset + 0x1C)[0],
        "encrypted": struct.unpack_from(">I", data, offset + 0x20)[0],
        "key_index": struct.unpack_from(">I", data, offset + 0x24)[0],
        "iv_index": struct.unpack_from(">I", data, offset + 0x28)[0],
        "compressed": struct.unpack_from(">I", data, offset + 0x2C)[0],
    }


def parse_sce_keys(data, offset, count):
    keys = []
    for i in range(count):
        key = data[offset + i * 16:offset + i * 16 + 16]
        keys.append(key)
    return keys


PKG_METADATA_KEYS = [
    {
        "key_revision": 0x0000,
        "erk": bytes.fromhex("2B7F1AC68A2F41E0E54AB1B10DC1ABB1"), # thx 2 fail0verflow 4 theez.
        "riv": bytes.fromhex("9B1E0B2E6F568E4BEE3EBFA150606F73"),
    },
]


def try_decrypt_metadata(data, sce_header):
    meta_offset = sce_header["metadata_offset"]
    header_length = sce_header["header_length"]

    for ks in PKG_METADATA_KEYS:
        if ks["key_revision"] != sce_header["key_revision"]:
            continue

        for info_offset in [0x80, 0xC0, 0x100, 0x20 + meta_offset]:
            if info_offset + 0x40 > len(data):
                continue

            encrypted_info = data[info_offset:info_offset + 0x40]
            decrypted_info = aes_cbc_decrypt(encrypted_info, ks["erk"], ks["riv"])

            meta_key = decrypted_info[0x00:0x10]
            meta_iv = decrypted_info[0x10:0x20]

            meta_header_offset = info_offset + 0x40
            meta_header_size = header_length - meta_header_offset

            if meta_header_size <= 0 or meta_header_offset + meta_header_size > len(data):
                continue

            encrypted_meta = data[meta_header_offset:meta_header_offset + meta_header_size]
            pad_len = (16 - len(encrypted_meta) % 16) % 16
            if pad_len:
                encrypted_meta += b"\x00" * pad_len

            decrypted_meta = aes_cbc_decrypt(encrypted_meta, meta_key, meta_iv)

            test_header = parse_metadata_header(decrypted_meta, 0)
            if 1 <= test_header["section_count"] <= 16 and 1 <= test_header["key_count"] <= 64:
                return decrypted_meta, meta_header_offset, test_header

    return None, None, None


def decrypt_manual(args):
    with open(args.input, "rb") as f:
        pkg_data = f.read()

    key = parse_hex(args.key)
    iv = parse_hex(args.iv)
    offset = parse_int_auto(args.offset)
    size = parse_int_auto(args.size) if args.size else len(pkg_data) - offset

    print(f"Input:  {args.input} ({len(pkg_data)} bytes)")
    print(f"Key:    {key.hex().upper()}")
    print(f"IV:     {iv.hex().upper()}")
    print(f"Offset: 0x{offset:X}")
    print(f"Size:   0x{size:X} ({size} bytes)")

    if len(key) != 16:
        print(f"ERROR: Key must be 16 bytes (got {len(key)})", file=sys.stderr)
        sys.exit(1)
    if len(iv) != 16:
        print(f"ERROR: IV must be 16 bytes (got {len(iv)})", file=sys.stderr)
        sys.exit(1)

    encrypted = pkg_data[offset:offset + size]

    pad_len = (16 - len(encrypted) % 16) % 16
    if pad_len:
        encrypted += b"\x00" * pad_len

    # try CTR mode first, then CBC as fallback
    for mode_name, decrypt_fn in [("CTR", aes_ctr_decrypt), ("CBC", aes_cbc_decrypt)]:
        print(f"\nTrying AES-128-{mode_name}...")
        decrypted = decrypt_fn(encrypted, key, iv)
        decrypted = decrypted[:size]

        output = decrypted
        decompressed = False

        # then zlib
        try:
            output = zlib.decompress(decrypted)
            print(f"Decompressed (zlib): {len(decrypted)} -> {len(output)} bytes")
            decompressed = True
        except zlib.error:
            pass

        if not decompressed:
            try:
                output = zlib.decompress(decrypted, -15)
                print(f"Decompressed (raw deflate): {len(decrypted)} -> {len(output)} bytes")
                decompressed = True
            except zlib.error:
                pass

        # check if first bytes look like a valid CORE_OS header, type should b a small int (0x00000001 etc), count should be less than 256
        if len(output) >= 16:
            test_type, test_count = struct.unpack_from(">II", output, 0)
            if test_type <= 0x10 and 0 < test_count <= 256:
                print(f"AES-{mode_name} produced valid looking header "
                      f"(type=0x{test_type:X}, count={test_count})")
                break

        if decompressed:
            # decompression success, probably correct even if a header check failed lol 
            break

        print(f"AES-{mode_name}: output doesn't look valid, trying next mode...")
        output = decrypted

    if not decompressed:
        print("Data not compressed (or decompression failed), writing raw decrypted anyways")

    print(f"\nfirst 64 bytes of output:") # debug: show first bytes of output
    for i in range(0, min(64, len(output)), 16):
        chunk = output[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        print(f"  {i:04X}: {hex_str}")

    with open(args.output, "wb") as f:
        f.write(output)

    print(f"\nWritten {len(output)} bytes to {args.output}")


def decrypt_auto(args):
    with open(args.input, "rb") as f:
        pkg_data = f.read()

    print(f"Input: {args.input} ({len(pkg_data)} bytes)")

    sce = parse_sce_header(pkg_data)
    if not sce:
        print("ERROR: Not a valid SCE file", file=sys.stderr)
        sys.exit(1)

    header_type_names = {1: "SELF", 2: "RVK", 3: "PKG", 4: "SPP"}
    ht_name = header_type_names.get(sce["header_type"], f"0x{sce['header_type']:04X}")

    print(f"SCE Header: version={sce['version']}, type={ht_name}, "
          f"key_rev=0x{sce['key_revision']:04X}")
    print(f"Header Length: 0x{sce['header_length']:X}")
    print(f"Data Length:   0x{sce['data_length']:X}")

    if sce["header_type"] != 3:
        print(f"WARNING: Not a PKG file (type={ht_name}), trying anyway...")

    print("\nAttempting automatic metadata decryption...")
    decrypted_meta, meta_offset, meta_header = try_decrypt_metadata(pkg_data, sce)

    if decrypted_meta is None:
        print("Automatic metadata decryption failed")
        print("Use manual mode with keys from scetool -i output:")
        print(f"  python3 {sys.argv[0]} {args.input} {args.output} \\")
        print(f"      --key <KEY_HEX> --iv <IV_HEX> --offset <DATA_OFFSET> --size <DATA_SIZE>")
        print()
        print("From scetool -i, find the Metadata Section Headers table")
        print("The encrypted data section shows Key and IV indices")
        print("Look up those indices in the SCE File Keys table")
        sys.exit(1)

    print(f"Metadata decrypted at offset 0x{meta_offset:X}")
    print(f"Sections: {meta_header['section_count']}, Keys: {meta_header['key_count']}")

    sections = []
    for i in range(meta_header["section_count"]):
        sect = parse_metadata_section(decrypted_meta, 0x20 + i * 0x30)
        sections.append(sect)
        enc_str = "ENC" if sect["encrypted"] == 3 else "---"
        comp_str = "ZIP" if sect["compressed"] == 3 else "---"
        print(f"  Section {i}: offset=0x{sect['data_offset']:X} size=0x{sect['data_size']:X} "
              f"{enc_str} key={sect['key_index']:02X} iv={sect['iv_index']:02X} {comp_str}")

    keys_offset = 0x20 + meta_header["section_count"] * 0x30
    file_keys = parse_sce_keys(decrypted_meta, keys_offset, meta_header["key_count"])

    data_sections = [s for s in sections if s["encrypted"] == 3]
    if not data_sections:
        data_sections = [s for s in sections if s["data_size"] > 0x100]

    if not data_sections:
        print("ERROR: No data sections found", file=sys.stderr)
        sys.exit(1)

    main_section = max(data_sections, key=lambda s: s["data_size"])
    print(f"\nDecrypting main data section at 0x{main_section['data_offset']:X} "
          f"({main_section['data_size']} bytes)")

    sect_data = pkg_data[main_section["data_offset"]:
                         main_section["data_offset"] + main_section["data_size"]]

    if main_section["encrypted"] == 3:
        key = file_keys[main_section["key_index"]]
        iv = file_keys[main_section["iv_index"]]
        print(f"Key [{main_section['key_index']:02X}]: {key.hex().upper()}")
        print(f"IV  [{main_section['iv_index']:02X}]: {iv.hex().upper()}")

        pad_len = (16 - len(sect_data) % 16) % 16
        if pad_len:
            sect_data += b"\x00" * pad_len

        sect_data = aes_cbc_decrypt(sect_data, key, iv)
        sect_data = sect_data[:main_section["data_size"]]

    output = sect_data
    if main_section["compressed"] == 3:
        try:
            output = zlib.decompress(sect_data)
            print(f"Decompressed: {len(sect_data)} -> {len(output)} bytes")
        except zlib.error:
            try:
                output = zlib.decompress(sect_data, -15)
                print(f"Decompressed (raw): {len(sect_data)} -> {len(output)} bytes")
            except zlib.error:
                print("WARNING: Decompression failed, writing raw decrypted data anyways")

    print(f"\nfirst 64 bytes of output:")
    for i in range(0, min(64, len(output)), 16):
        chunk = output[i:i + 16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        print(f"  {i:04X}: {hex_str}")

    with open(args.output, "wb") as f:
        f.write(output)

    print(f"\nWritten {len(output)} bytes to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt PKG data sections")
    parser.add_argument("input", help="Input .pkg file")
    parser.add_argument("output", help="Output file")
    parser.add_argument("--key", help="AES-128 key (hex, from scetool file keys)")
    parser.add_argument("--iv", help="AES-128 IV (hex, from scetool file keys)")
    parser.add_argument("--offset", help="Data offset in file (hex or decimal)", default="0x340")
    parser.add_argument("--size", help="Data size (hex or decimal, default=auto)")

    args = parser.parse_args()

    if args.key and args.iv:
        decrypt_manual(args)
    else:
        decrypt_auto(args)


if __name__ == "__main__":
    main()
