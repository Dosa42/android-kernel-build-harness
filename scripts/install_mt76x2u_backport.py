#!/usr/bin/env python3
"""Install a pinned Linux v4.19 MT7612U driver and firmware into a kernel tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path


LINUX_REPOSITORY = "https://github.com/torvalds/linux.git"
LINUX_COMMIT = "84df9525b0c27f3ebc2ebb1864fa62a97fdedb7d"
FIRMWARE_REPOSITORY = "https://gitlab.com/kernel-firmware/linux-firmware"
FIRMWARE_COMMIT = "8c7fac62c0d1c3b8915f596effc1ef6e95fd6b5f"
FIRMWARE = {
    "mediatek/mt7662u.bin": "527dc38380b698330a6f5300bfd70278c45c0b6c60596e6ef6ac9828a84628fb",
    "mediatek/mt7662u_rom_patch.bin": "3c358bb8feebfa124e809891a9d8efc27c69efa8a3169f3061f625f6b25d2870",
}


def run(*command: str, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def insert_before(path: Path, marker: str, addition: str) -> None:
    text = path.read_text(encoding="utf-8")
    if addition.strip() in text:
        return
    if marker not in text:
        raise RuntimeError(f"marker {marker!r} not found in {path}")
    path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")


def append_once(path: Path, addition: str) -> None:
    text = path.read_text(encoding="utf-8")
    if addition.strip() in text:
        return
    path.write_text(text.rstrip() + "\n" + addition, encoding="utf-8")


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"expected one compatibility patch target in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def apply_kernel_4_14_compatibility(driver_root: Path) -> None:
    # struct_size() was added after this Samsung 4.14 tree. Keep the exact
    # overflow-equivalent allocation used by Linux v4.19 without relying on
    # that newer helper macro.
    replace_once(
        driver_root / "agg-rx.c",
        "tid = kzalloc(struct_size(tid, reorder_buf, size), GFP_KERNEL);",
        "tid = kzalloc(sizeof(*tid) + size * sizeof(tid->reorder_buf[0]), "
        "GFP_KERNEL);",
    )

    # sg_init_marker() was introduced after this Samsung 4.14 tree. Its v4.19
    # implementation only marks the last scatterlist entry, and sg_mark_end()
    # is already available in 4.14, so use that exact equivalent directly.
    replace_once(
        driver_root / "usb.c",
        "sg_init_marker(urb->sg, urb->num_sgs);",
        "sg_mark_end(&urb->sg[urb->num_sgs - 1]);",
    )
    replace_once(
        driver_root / "usb.c",
        "sg_init_marker(urb->sg, nsgs);",
        "sg_mark_end(&urb->sg[nsgs - 1]);",
    )


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Nethunter-Kernel-Builder"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    mediatek_root = source_root / "drivers/net/wireless/mediatek"
    if not (mediatek_root / "Kconfig").is_file() or not (mediatek_root / "Makefile").is_file():
        raise RuntimeError(f"not a compatible kernel source tree: {source_root}")

    destination = mediatek_root / "mt76"
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite existing driver directory: {destination}")

    with tempfile.TemporaryDirectory(prefix="mt76x2u-backport-") as temporary:
        checkout = Path(temporary) / "linux"
        run("git", "init", "--quiet", str(checkout))
        run("git", "remote", "add", "origin", LINUX_REPOSITORY, cwd=checkout)
        run("git", "sparse-checkout", "init", "--cone", cwd=checkout)
        run("git", "sparse-checkout", "set", "drivers/net/wireless/mediatek/mt76", cwd=checkout)
        run(
            "git",
            "-c",
            "protocol.version=2",
            "fetch",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            LINUX_COMMIT,
            cwd=checkout,
        )
        run("git", "checkout", "--detach", "FETCH_HEAD", cwd=checkout)
        resolved = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
        ).strip()
        if resolved != LINUX_COMMIT:
            raise RuntimeError(f"unexpected Linux source commit: {resolved}")
        shutil.copytree(
            checkout / "drivers/net/wireless/mediatek/mt76",
            destination,
        )

    apply_kernel_4_14_compatibility(destination)

    insert_before(
        mediatek_root / "Kconfig",
        "endif # WLAN_VENDOR_MEDIATEK",
        'source "drivers/net/wireless/mediatek/mt76/Kconfig"\n',
    )
    append_once(
        mediatek_root / "Makefile",
        "obj-$(CONFIG_MT76_CORE)\t+= mt76/\n",
    )

    firmware_hashes: dict[str, str] = {}
    for relative_path, expected_hash in FIRMWARE.items():
        url = f"{FIRMWARE_REPOSITORY}/-/raw/{FIRMWARE_COMMIT}/{relative_path}"
        payload = download(url)
        actual_hash = sha256(payload)
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"firmware hash mismatch for {relative_path}: {actual_hash} != {expected_hash}"
            )
        destination_path = source_root / "firmware" / relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(payload)
        firmware_hashes[relative_path] = actual_hash

    expected_driver_files = [
        destination / "Kconfig",
        destination / "Makefile",
        destination / "mt76x2u_core.c",
        destination / "mt76x2u_main.c",
        destination / "mt76x2_usb.c",
    ]
    missing = [str(path) for path in expected_driver_files if not path.is_file()]
    if missing:
        raise RuntimeError("incomplete MT7612U driver copy: " + ", ".join(missing))

    manifest = {
        "driver": "mt76x2u",
        "chipset": "MT7612U",
        "adapter": "ALFA AWUS036ACM",
        "linux_source_repository": LINUX_REPOSITORY,
        "linux_source_commit": LINUX_COMMIT,
        "firmware_repository": FIRMWARE_REPOSITORY,
        "firmware_commit": FIRMWARE_COMMIT,
        "firmware_sha256": firmware_hashes,
        "required_kconfig": [
            "CONFIG_MT76_CORE=y",
            "CONFIG_MT76_USB=y",
            "CONFIG_MT76x2_COMMON=y",
            "CONFIG_MT76x2U=y",
        ],
        "kernel_4_14_compatibility": [
            "replace post-4.14 struct_size() use in agg-rx.c",
            "replace post-4.14 sg_init_marker() uses in usb.c",
        ],
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

