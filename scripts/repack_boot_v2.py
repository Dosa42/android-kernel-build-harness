#!/usr/bin/env python3
"""Replace only the kernel payload in an Android boot image v2.

The base image's ramdisk, second stage, recovery DTBO, DTB, Samsung marker,
AVB metadata, header fields, and fixed partition-image size are preserved.
The boot ID and AVB footer placement fields are recalculated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


BOOT_MAGIC = b"ANDROID!"
AVB_FOOTER_MAGIC = b"AVBf"
AVB_FOOTER_SIZE = 64


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    base = args.base.read_bytes()
    kernel = args.kernel.read_bytes()

    if base[:8] != BOOT_MAGIC:
        raise SystemExit("base is not an Android boot image")

    page_size = u32(base, 36)
    header_version = u32(base, 40)
    header_size = u32(base, 1644)
    if header_version != 2 or header_size != 1660:
        raise SystemExit(
            f"expected boot header v2/1660, got v{header_version}/{header_size}"
        )

    old_kernel_size = u32(base, 8)
    ramdisk_size = u32(base, 16)
    second_size = u32(base, 24)
    recovery_dtbo_size = u32(base, 1632)
    dtb_size = u32(base, 1648)

    old_kernel_offset = page_size
    ramdisk_offset = old_kernel_offset + align(old_kernel_size, page_size)
    second_offset = ramdisk_offset + align(ramdisk_size, page_size)
    recovery_dtbo_offset = second_offset + align(second_size, page_size)
    dtb_offset = recovery_dtbo_offset + align(recovery_dtbo_size, page_size)
    old_payload_end = dtb_offset + align(dtb_size, page_size)

    ramdisk = base[ramdisk_offset : ramdisk_offset + ramdisk_size]
    second = base[second_offset : second_offset + second_size]
    recovery_dtbo = base[
        recovery_dtbo_offset : recovery_dtbo_offset + recovery_dtbo_size
    ]
    dtb = base[dtb_offset : dtb_offset + dtb_size]

    footer = bytearray(base[-AVB_FOOTER_SIZE:])
    if footer[:4] != AVB_FOOTER_MAGIC:
        raise SystemExit("base has no AVB footer")
    old_original_image_size = struct.unpack_from(">Q", footer, 12)[0]
    old_vbmeta_offset = struct.unpack_from(">Q", footer, 20)[0]
    vbmeta_size = struct.unpack_from(">Q", footer, 28)[0]

    if old_original_image_size < old_payload_end:
        raise SystemExit("AVB original image size precedes boot payload")
    marker = base[old_payload_end:old_original_image_size]
    vbmeta = base[old_vbmeta_offset : old_vbmeta_offset + vbmeta_size]
    if len(vbmeta) != vbmeta_size:
        raise SystemExit("truncated AVB metadata")

    header = bytearray(base[:page_size])
    struct.pack_into("<I", header, 8, len(kernel))

    boot_id = hashlib.sha1()
    for component, size in (
        (kernel, len(kernel)),
        (ramdisk, ramdisk_size),
        (second, second_size),
        (recovery_dtbo, recovery_dtbo_size),
        (dtb, dtb_size),
    ):
        boot_id.update(component)
        boot_id.update(struct.pack("<I", size))
    header[576:608] = boot_id.digest() + bytes(12)

    output = bytearray(len(base))
    cursor = 0

    def append_page_aligned(component: bytes) -> None:
        nonlocal cursor
        output[cursor : cursor + len(component)] = component
        cursor += align(len(component), page_size)

    append_page_aligned(header)
    append_page_aligned(kernel)
    append_page_aligned(ramdisk)
    append_page_aligned(second)
    append_page_aligned(recovery_dtbo)
    append_page_aligned(dtb)

    output[cursor : cursor + len(marker)] = marker
    new_original_image_size = cursor + len(marker)
    new_vbmeta_offset = align(new_original_image_size, page_size)

    if new_vbmeta_offset + len(vbmeta) > len(output) - AVB_FOOTER_SIZE:
        raise SystemExit("repacked boot payload does not fit the base image")

    output[new_vbmeta_offset : new_vbmeta_offset + len(vbmeta)] = vbmeta

    struct.pack_into(">Q", footer, 12, new_original_image_size)
    struct.pack_into(">Q", footer, 20, new_vbmeta_offset)
    output[-AVB_FOOTER_SIZE:] = footer

    args.output.write_bytes(output)

    new_ramdisk_offset = page_size + align(len(kernel), page_size)
    new_second_offset = new_ramdisk_offset + align(ramdisk_size, page_size)
    new_recovery_dtbo_offset = new_second_offset + align(second_size, page_size)
    new_dtb_offset = new_recovery_dtbo_offset + align(recovery_dtbo_size, page_size)
    checks = {
        "fixed_image_size_preserved": len(output) == len(base),
        "kernel_payload_exact": (
            output[page_size : page_size + len(kernel)] == kernel
        ),
        "ramdisk_byte_identical": (
            output[new_ramdisk_offset : new_ramdisk_offset + ramdisk_size] == ramdisk
        ),
        "second_byte_identical": (
            output[new_second_offset : new_second_offset + second_size] == second
        ),
        "recovery_dtbo_byte_identical": (
            output[
                new_recovery_dtbo_offset : new_recovery_dtbo_offset
                + recovery_dtbo_size
            ]
            == recovery_dtbo
        ),
        "dtb_byte_identical": (
            output[new_dtb_offset : new_dtb_offset + dtb_size] == dtb
        ),
        "marker_byte_identical": (
            output[cursor : cursor + len(marker)] == marker
        ),
        "vbmeta_byte_identical": (
            output[new_vbmeta_offset : new_vbmeta_offset + vbmeta_size] == vbmeta
        ),
        "avb_footer_magic": output[-AVB_FOOTER_SIZE:-60] == AVB_FOOTER_MAGIC,
    }
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise SystemExit("boot repack self-verification failed: " + ", ".join(failed))

    report = {
        "format": "android-boot-header-v2",
        "base": {
            "path": str(args.base),
            "size": len(base),
            "sha256": sha256(base),
        },
        "kernel": {
            "path": str(args.kernel),
            "size": len(kernel),
            "sha256": sha256(kernel),
        },
        "output": {
            "path": str(args.output),
            "size": len(output),
            "sha256": sha256(output),
        },
        "preserved_components": {
            "ramdisk_sha256": sha256(ramdisk),
            "second_sha256": sha256(second),
            "recovery_dtbo_sha256": sha256(recovery_dtbo),
            "dtb_sha256": sha256(dtb),
            "marker_sha256": sha256(marker),
            "vbmeta_sha256": sha256(vbmeta),
        },
        "boot_id_sha1": boot_id.hexdigest(),
        "original_image_size": new_original_image_size,
        "vbmeta_offset": new_vbmeta_offset,
        "checks": checks,
        "vbmeta_resigned": False,
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {args.output} ({len(output)} bytes)")
    print(f"kernel_size={len(kernel)}")
    print(f"boot_id={boot_id.hexdigest()}")
    print(f"original_image_size={new_original_image_size}")
    print(f"vbmeta_offset={new_vbmeta_offset}")


if __name__ == "__main__":
    main()
