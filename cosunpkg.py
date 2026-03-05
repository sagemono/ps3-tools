# cosunpkg.py
# Extracts individual files from a decrypted CORE_OS_PACKAGE.pkg

import sys
import os
import struct

PKG_HEADER_FMT = ">II Q"
PKG_HEADER_SIZE = struct.calcsize(PKG_HEADER_FMT)

PKG_ENTRY_FMT = ">QQ 32s"
PKG_ENTRY_SIZE = struct.calcsize(PKG_ENTRY_FMT)


def extract_pkg(pkg_path, out_dir):
    if not os.path.isfile(pkg_path):
        print(f"Error: file not found: {pkg_path}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    with open(pkg_path, "rb") as f:
        raw_header = f.read(PKG_HEADER_SIZE)
        if len(raw_header) < PKG_HEADER_SIZE:
            print("Error: file too small for header", file=sys.stderr)
            sys.exit(1)

        pkg_type, num_files, total_size = struct.unpack(PKG_HEADER_FMT, raw_header)

        print(f"Package type: 0x{pkg_type:X}")
        print(f"File count:   {num_files} (0x{num_files:X})")
        print(f"Total size:   0x{total_size:X} ({total_size} bytes)")
        print()

        entries = []
        for i in range(num_files):
            raw_entry = f.read(PKG_ENTRY_SIZE)
            if len(raw_entry) < PKG_ENTRY_SIZE:
                print(f"Error: couldn't read entry {i}", file=sys.stderr)
                sys.exit(1)

            offset, size, raw_name = struct.unpack(PKG_ENTRY_FMT, raw_entry)
            name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            entries.append((offset, size, name))

        for i, (offset, size, name) in enumerate(entries):
            print(f"  [{i:02d}] offset=0x{offset:08X}  size=0x{size:08X}  '{name}'")

            out_path = os.path.join(out_dir, name)
            f.seek(offset)
            remaining = size

            with open(out_path, "wb") as out:
                while remaining > 0:
                    chunk = min(remaining, 65536)
                    data = f.read(chunk)
                    if not data:
                        print(f"  Warning: unexpected EOF for {name}", file=sys.stderr)
                        break
                    out.write(data)
                    remaining -= len(data)

            print(f"         -> {out_path}")

    print(f"\nDone. Extracted {num_files} files to {out_dir}")


def main():
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <test.pkg> <output_dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    extract_pkg(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
