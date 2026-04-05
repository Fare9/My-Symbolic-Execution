#!/usr/bin/env python3
"""
VirtUAL 1 serial generator (bagolymadar 2020)
Usage: python3 keygen.py <username>
"""

import sys


def popcount(n: int) -> int:
    return bin(n).count('1')


def compute_hash(name: str) -> int:
    h = 0xb7e151628aed2a6a
    for c in name:
        b   = ord(c)
        pc  = popcount(b) & 63
        h   = ((h << pc) | (h >> (64 - pc))) & 0xffffffffffffffff
        if pc & 1:   # odd popcount → NOT the char
            b = (~b) & 0xff
        h ^= b
        h &= 0xffffffffffffffff
    return h


def make_serial(name: str) -> str:
    length   = len(name)
    pop_sum  = sum(popcount(ord(c)) for c in name) & 0xff
    hash_val = compute_hash(name)
    return f"{length:02X}{pop_sum:02X}-{hash_val:016X}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 keygen.py <username>")
        sys.exit(1)

    name   = sys.argv[1]
    serial = make_serial(name)

    print(f"Username : {name}")
    print(f"Serial   : {serial}")


if __name__ == "__main__":
    main()