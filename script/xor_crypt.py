#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
from typing import Optional

DEFAULT_KEY = 123
DEFAULT_CHUNK_SIZE = 1024 * 1024


def normalize_key(key: int) -> int:
    return key & 0xFF


def xor_chunk(data: bytes, key: int) -> bytes:
    if key == 0:
        return data
    buf = bytearray(data)
    for i in range(len(buf)):
        buf[i] ^= key
    return bytes(buf)


def xor_file(src_path: str, dst_path: str, key: int, chunk_size: int) -> None:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(xor_chunk(chunk, key))


def xor_file_in_place(path: str, key: int, chunk_size: int) -> None:
    directory = os.path.dirname(path) or "."
    tmp_file: Optional[tempfile.NamedTemporaryFile] = None
    try:
        tmp_file = tempfile.NamedTemporaryFile(delete=False, dir=directory)
        tmp_file.close()
        xor_file(path, tmp_file.name, key, chunk_size)
        os.replace(tmp_file.name, path)
    finally:
        if tmp_file is not None:
            try:
                if os.path.exists(tmp_file.name):
                    os.remove(tmp_file.name)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="XOR encrypt/decrypt file (same operation for both)")
    parser.add_argument("input", help="input file path")
    parser.add_argument("output", nargs="?", help="output file path (omit when --in-place)")
    parser.add_argument("--key", type=int, default=DEFAULT_KEY,
                        help=f"xor key 0-255 (default: {DEFAULT_KEY}, 0 disables)")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help=f"chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})")
    parser.add_argument("--in-place", action="store_true",
                        help="overwrite input file in place")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    key = normalize_key(args.key)
    if args.in_place:
        if args.output:
            parser.error("output should be omitted when --in-place is set")
        xor_file_in_place(args.input, key, args.chunk_size)
        return 0

    if not args.output:
        parser.error("output is required unless --in-place is set")

    xor_file(args.input, args.output, key, args.chunk_size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
