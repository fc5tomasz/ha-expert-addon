from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path


def _material() -> bytes:
    parts = [
        "HA",
        "_Expert",
        "_Tomasz",
        "_Furdal",
        "_Bootstrap",
        "_2026",
    ]
    return "".join(parts).encode("utf-8")


def _keystream(length: int) -> bytes:
    seed = hashlib.sha256(_material()).digest()
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def decrypt_blob(blob_text: str) -> str:
    cipher = base64.urlsafe_b64decode(blob_text.encode("ascii"))
    key = _keystream(len(cipher))
    plain = bytes(c ^ k for c, k in zip(cipher, key))
    return plain.decode("utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: bootstrap_key.py <encrypted_blob_path> <output_path>", file=sys.stderr)
        return 2

    encrypted_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    blob = encrypted_path.read_text(encoding="utf-8").strip()
    output_path.write_text(decrypt_blob(blob), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
