# pup.py 
# PS3 PUP update file extractor/creator
# Ported from pup.c by KaKaRoTo

# Original Copyright (C) Youness Alaoui (KaKaRoTo)
# Licensed under GPL v3

import sys
import os
import struct
import hmac
import hashlib

VERSION = "0.2"

PUP_MAGIC = 0x5343455546000000  # "SCEUF\0\0\0"

HMAC_PUP_KEY = bytes([
    0xf4, 0x91, 0xad, 0x94, 0xc6, 0x81, 0x10, 0x96,
    0x91, 0x5f, 0xd5, 0xd2, 0x44, 0x81, 0xae, 0xdc,
    0xed, 0xed, 0xbe, 0x6b, 0xe5, 0x13, 0x72, 0x4d,
    0xd8, 0xf7, 0xb6, 0x91, 0xe8, 0x8a, 0x38, 0xf4,
    0xb5, 0x16, 0x2b, 0xfb, 0xec, 0xbe, 0x3a, 0x62,
    0x18, 0x5d, 0xd7, 0xc9, 0x4d, 0xa2, 0x22, 0x5a,
    0xda, 0x3f, 0xbf, 0xce, 0x55, 0x5b, 0x9e, 0xa9,
    0x64, 0x98, 0x29, 0xeb, 0x30, 0xce, 0x83, 0x66,
])

# struct sizes (all big-endian / network order)
# PUPHeader:    6 x uint64 = 48 bytes
# PUPFileEntry: 3 x uint64 + 8 pad = 32 bytes
# PUPHashEntry: uint64 + 20 hash + 4 pad = 32 bytes
# PUPFooter:    20 hash + 12 pad = 32 bytes

HEADER_FMT = ">6Q"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

FILE_ENTRY_FMT = ">3Q8s"
FILE_ENTRY_SIZE = struct.calcsize(FILE_ENTRY_FMT)

HASH_ENTRY_FMT = ">Q20s4s"
HASH_ENTRY_SIZE = struct.calcsize(HASH_ENTRY_FMT)

FOOTER_FMT = ">20s12s"
FOOTER_SIZE = struct.calcsize(FOOTER_FMT)

ENTRIES = [
    (0x100, "version.txt"),
    (0x101, "license.xml"),
    (0x102, "promo_flags.txt"),
    (0x103, "update_flags.txt"),
    (0x104, "patch_build.txt"),
    (0x200, "ps3swu.self"),
    (0x201, "vsh.tar"),
    (0x202, "dots.txt"),
    (0x203, "patch_data.pkg"),
    (0x300, "update_files.tar"),
]

ID_TO_FILENAME = {eid: name for eid, name in ENTRIES}


def id_to_filename(entry_id):
    return ID_TO_FILENAME.get(entry_id)


def format_hash(h):
    return "".join(f"{b:02X}" for b in h)


def print_hash(message, h):
    print(f"{message} : {format_hash(h)}")


def hmac_sha1(key, data):
    return hmac.new(key, data, hashlib.sha1).digest()


def hmac_sha1_incremental(key, chunks):
    ctx = hmac.new(key, b"", hashlib.sha1)
    for chunk in chunks:
        ctx.update(chunk)
    return ctx.digest()


def print_header_info(header, footer_hash):
    print(
        f"PUP file information\n"
        f"Package version: {header['package_version']}\n"
        f"Image version: {header['image_version']}\n"
        f"File count: {header['file_count']}\n"
        f"Header length: {header['header_length']}\n"
        f"Data length: {header['data_length']}"
    )
    print_hash("PUP file hash", footer_hash)


def print_file_info(file_entry, hash_entry):
    filename = id_to_filename(file_entry["entry_id"])
    print(
        f"\tFile {hash_entry['entry_id']}\n"
        f"\tEntry id: 0x{file_entry['entry_id']:X}\n"
        f"\tFilename : {filename if filename else 'Unknown entry id'}\n"
        f"\tData offset: 0x{file_entry['data_offset']:X}\n"
        f"\tData length: {file_entry['data_length']}"
    )
    print_hash("File hash", hash_entry["hash"])


def read_header(fd):
    raw_header = fd.read(HEADER_SIZE)
    if len(raw_header) < HEADER_SIZE:
        raise RuntimeError("Couldn't read header")

    magic, pkg_ver, img_ver, file_count, hdr_len, data_len = struct.unpack(
        HEADER_FMT, raw_header
    )

    if magic != PUP_MAGIC:
        raise RuntimeError(
            f"Magic number is not the same 0x{magic:016X}"
        )

    header = {
        "magic": magic,
        "package_version": pkg_ver,
        "image_version": img_ver,
        "file_count": file_count,
        "header_length": hdr_len,
        "data_length": data_len,
    }

    raw_files = fd.read(file_count * FILE_ENTRY_SIZE)
    if len(raw_files) < file_count * FILE_ENTRY_SIZE:
        raise RuntimeError("Couldn't read file entries")

    raw_hashes = fd.read(file_count * HASH_ENTRY_SIZE)
    if len(raw_hashes) < file_count * HASH_ENTRY_SIZE:
        raise RuntimeError("Couldn't read hash entries")

    raw_footer = fd.read(FOOTER_SIZE)
    if len(raw_footer) < FOOTER_SIZE:
        raise RuntimeError("Couldn't read footer")

    computed_hash = hmac_sha1_incremental(
        HMAC_PUP_KEY, [raw_header, raw_files, raw_hashes]
    )

    footer_hash, _footer_pad = struct.unpack(FOOTER_FMT, raw_footer)

    if computed_hash != footer_hash:
        print("PUP file is corrupted, wrong header hash", file=sys.stderr)
        print_hash("Header hash", computed_hash)
        print_hash("Expected hash", footer_hash)
        raise RuntimeError("Header hash mismatch")

    files = []
    for i in range(file_count):
        offset = i * FILE_ENTRY_SIZE
        eid, doff, dlen, _pad = struct.unpack(
            FILE_ENTRY_FMT, raw_files[offset : offset + FILE_ENTRY_SIZE]
        )
        files.append({"entry_id": eid, "data_offset": doff, "data_length": dlen})

    hashes = []
    for i in range(file_count):
        offset = i * HASH_ENTRY_SIZE
        eid, h, _pad = struct.unpack(
            HASH_ENTRY_FMT, raw_hashes[offset : offset + HASH_ENTRY_SIZE]
        )
        hashes.append({"entry_id": eid, "hash": h})

    return header, files, hashes, footer_hash


def cmd_info(pup_file):
    with open(pup_file, "rb") as fd:
        header, files, hashes, footer_hash = read_header(fd)

    print_header_info(header, footer_hash)
    for i in range(header["file_count"]):
        print_file_info(files[i], hashes[i])


def cmd_extract(pup_file, dest):
    if os.path.exists(dest):
        print("Destination directory must not exist", file=sys.stderr)
        sys.exit(2)

    with open(pup_file, "rb") as fd:
        header, files, hashes, footer_hash = read_header(fd)

        print_header_info(header, footer_hash)
        os.makedirs(dest)

        for i in range(header["file_count"]):
            fe = files[i]
            he = hashes[i]
            print_file_info(fe, he)

            filename = id_to_filename(fe["entry_id"])
            if filename is None:
                print("*** Unknown entry id, file skipped ****\n")
                continue

            out_path = os.path.join(dest, filename)
            print(f"Writing file {out_path}")

            fd.seek(fe["data_offset"])
            remaining = fe["data_length"]
            ctx = hmac.new(HMAC_PUP_KEY, b"", hashlib.sha1)

            with open(out_path, "wb") as out:
                while remaining > 0:
                    chunk_size = min(remaining, 1024)
                    data = fd.read(chunk_size)
                    if len(data) < chunk_size:
                        raise RuntimeError("Couldn't read all the data")
                    ctx.update(data)
                    out.write(data)
                    remaining -= chunk_size

            computed = ctx.digest()
            if computed != he["hash"]:
                print("PUP file is corrupted, wrong file hash", file=sys.stderr)
                print_hash("File hash", computed)
                print_hash("Expected hash", he["hash"])
                sys.exit(2)


def cmd_create(directory, dest, build):
    if os.path.exists(dest):
        print("Destination file must not exist", file=sys.stderr)
        sys.exit(2)

    header = {
        "magic": PUP_MAGIC,
        "package_version": 1,
        "image_version": build,
        "file_count": 0,
        "header_length": HEADER_SIZE + FOOTER_SIZE,
        "data_length": 0,
    }

    files = []
    hashes = []

    for entry_id, entry_filename in ENTRIES:
        path = os.path.join(directory, entry_filename)
        if not os.path.isfile(path):
            continue

        print(f"Found file {path}")
        header["file_count"] += 1
        header["header_length"] += FILE_ENTRY_SIZE + HASH_ENTRY_SIZE

        ctx = hmac.new(HMAC_PUP_KEY, b"", hashlib.sha1)
        file_len = 0
        with open(path, "rb") as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                ctx.update(data)
                file_len += len(data)

        files.append({
            "entry_id": entry_id,
            "data_offset": 0,
            "data_length": file_len,
        })
        hashes.append({
            "entry_id": header["file_count"] - 1,
            "hash": ctx.digest(),
        })
        header["data_length"] += file_len

    for i in range(len(files)):
        if i == 0:
            files[i]["data_offset"] = header["header_length"]
        else:
            files[i]["data_offset"] = (
                files[i - 1]["data_offset"] + files[i - 1]["data_length"]
            )

    raw_header = struct.pack(
        HEADER_FMT,
        header["magic"],
        header["package_version"],
        header["image_version"],
        header["file_count"],
        header["header_length"],
        header["data_length"],
    )

    raw_files = b""
    for fe in files:
        raw_files += struct.pack(
            FILE_ENTRY_FMT,
            fe["entry_id"],
            fe["data_offset"],
            fe["data_length"],
            b"\x00" * 8,
        )

    raw_hashes = b""
    for he in hashes:
        raw_hashes += struct.pack(
            HASH_ENTRY_FMT,
            he["entry_id"],
            he["hash"],
            b"\x00" * 4,
        )

    footer_hash = hmac_sha1_incremental(
        HMAC_PUP_KEY, [raw_header, raw_files, raw_hashes]
    )
    raw_footer = struct.pack(FOOTER_FMT, footer_hash, b"\x00" * 12)

    print_header_info(header, footer_hash)

    with open(dest, "wb") as out:
        out.write(raw_header)
        out.write(raw_files)
        out.write(raw_hashes)
        out.write(raw_footer)

        for i, fe in enumerate(files):
            he = hashes[i]
            print_file_info(fe, he)

            filename = id_to_filename(fe["entry_id"])
            if filename is None:
                print("*** Unknown entry id, file skipped ****\n")
                continue

            path = os.path.join(directory, filename)
            out.seek(fe["data_offset"])

            with open(path, "rb") as f:
                remaining = fe["data_length"]
                while remaining > 0:
                    chunk_size = min(remaining, 1024)
                    data = f.read(chunk_size)
                    if len(data) < chunk_size:
                        raise RuntimeError("Couldn't read all the data")
                    out.write(data)
                    remaining -= chunk_size


def usage(program):
    print(
        f"Usage:\n\t{program} <command> <options>\n\n"
        f"Commands/Options:\n"
        f"\ti <filename.pup>:\t\t\t\t\tInformation about the PUP file\n"
        f"\tx <filename.pup> <output directory>:\t\t\tExtract PUP file\n"
        f"\tc <input directory> <filename.pup> <build number>:\tCreate PUP file",
        file=sys.stderr,
    )
    sys.exit(1)


def main():
    print(f"PUP Creator/Extractor {VERSION}\nBy KaKaRoTo\n", file=sys.stderr)

    if len(sys.argv) < 2:
        usage(sys.argv[0])

    cmd = sys.argv[1]
    if len(cmd) != 1:
        usage(sys.argv[0])

    if cmd == "i":
        if len(sys.argv) != 3:
            usage(sys.argv[0])
        cmd_info(sys.argv[2])
    elif cmd in ("e", "x"):
        if len(sys.argv) != 4:
            usage(sys.argv[0])
        cmd_extract(sys.argv[2], sys.argv[3])
    elif cmd == "c":
        if len(sys.argv) != 5:
            usage(sys.argv[0])
        cmd_create(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    else:
        usage(sys.argv[0])


if __name__ == "__main__":
    main()
