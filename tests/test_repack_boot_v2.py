from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGE = 2048


def align(value: int) -> int:
    return (value + PAGE - 1) // PAGE * PAGE


def padded(payload: bytes) -> bytes:
    return payload + bytes(align(len(payload)) - len(payload))


def make_base_image(path: Path) -> tuple[bytes, bytes]:
    kernel = b"old-kernel" * 401
    ramdisk = b"magisk-ramdisk" * 173
    dtb = b"device-tree" * 91
    marker = b"SEANDROIDENFORCE"
    vbmeta = b"AVB0" + b"signed-metadata" * 19

    header = bytearray(PAGE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12, 0x40080000)
    struct.pack_into("<I", header, 16, len(ramdisk))
    struct.pack_into("<I", header, 20, 0x47C80000)
    struct.pack_into("<I", header, 24, 0)
    struct.pack_into("<I", header, 32, 0x4BC80000)
    struct.pack_into("<I", header, 36, PAGE)
    struct.pack_into("<I", header, 40, 2)
    struct.pack_into("<I", header, 1644, 1660)
    struct.pack_into("<I", header, 1648, len(dtb))
    struct.pack_into("<Q", header, 1652, 0x4BC80000)

    boot_id = hashlib.sha1()
    for component in (kernel, ramdisk, b"", b"", dtb):
        boot_id.update(component)
        boot_id.update(struct.pack("<I", len(component)))
    header[576:608] = boot_id.digest() + bytes(12)

    body = bytes(header) + padded(kernel) + padded(ramdisk) + padded(dtb)
    original_size = len(body) + len(marker)
    vbmeta_offset = align(original_size)
    total_size = 64 * 1024
    image = bytearray(total_size)
    image[: len(body)] = body
    image[len(body) : len(body) + len(marker)] = marker
    image[vbmeta_offset : vbmeta_offset + len(vbmeta)] = vbmeta
    footer = bytearray(64)
    footer[:4] = b"AVBf"
    struct.pack_into(">I", footer, 4, 1)
    struct.pack_into(">Q", footer, 12, original_size)
    struct.pack_into(">Q", footer, 20, vbmeta_offset)
    struct.pack_into(">Q", footer, 28, len(vbmeta))
    image[-64:] = footer
    path.write_bytes(image)
    return ramdisk, dtb


class BootRepackTests(unittest.TestCase):
    def test_repack_preserves_every_non_kernel_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            base = directory / "base.img"
            output = directory / "output.img"
            kernel = directory / "Image.gz"
            report = directory / "report.json"
            ramdisk, dtb = make_base_image(base)
            kernel.write_bytes(b"new-kernel" * 613)
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/repack_boot_v2.py"),
                    "--base",
                    str(base),
                    "--kernel",
                    str(kernel),
                    "--output",
                    str(output),
                    "--json-output",
                    str(report),
                ],
                check=True,
            )
            evidence = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(all(evidence["checks"].values()))
            self.assertEqual(
                evidence["preserved_components"]["ramdisk_sha256"],
                hashlib.sha256(ramdisk).hexdigest(),
            )
            self.assertEqual(
                evidence["preserved_components"]["dtb_sha256"],
                hashlib.sha256(dtb).hexdigest(),
            )
            self.assertFalse(evidence["vbmeta_resigned"])
            self.assertEqual(output.stat().st_size, base.stat().st_size)


if __name__ == "__main__":
    unittest.main()
