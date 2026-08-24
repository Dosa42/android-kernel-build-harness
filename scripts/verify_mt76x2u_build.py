#!/usr/bin/env python3
"""Verify that MT7612U support is built into the final kernel Image."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


REQUIRED_CONFIG = {
    "CONFIG_USB_SUPPORT": "y",
    "CONFIG_USB_COMMON": "y",
    "CONFIG_USB_XHCI_HCD": "y",
    "CONFIG_USB_XHCI_MTK": "y",
    "CONFIG_USB_MTU3": "y",
    "CONFIG_USB_MTU3_DUAL_ROLE": "y",
    "CONFIG_USB_MTU3_PLAT_PHONE": "y",
    "CONFIG_USB_HOST_NOTIFY": "y",
    "CONFIG_USB_HOST_SAMSUNG_FEATURE": "y",
    "CONFIG_USB_PHY": "y",
    "CONFIG_PHY_MTK_USB": "y",
    "CONFIG_TYPEC": "y",
    "CONFIG_EXTCON": "y",
    "CONFIG_EXTCON_MTK_USB": "y",
    "CONFIG_MTK_USB_TYPEC": "y",
    "CONFIG_MTK_USB_TYPEC_U3_MUX": "y",
    "CONFIG_REGULATOR": "y",
    "CONFIG_MTK_SIB_USB_SWITCH": "y",
    "CONFIG_CFG80211": "y",
    "CONFIG_MAC80211": "y",
    "CONFIG_WLAN": "y",
    "CONFIG_MT76_CORE": "y",
    "CONFIG_MT76_USB": "y",
    "CONFIG_MT76x2_COMMON": "y",
    "CONFIG_MT76x2U": "y",
    "CONFIG_FW_LOADER": "y",
    "CONFIG_FIRMWARE_IN_KERNEL": "y",
    "CONFIG_EXTRA_FIRMWARE_DIR": '"firmware"',
}
FIRMWARE = {
    "mediatek/mt7662u.bin": "527dc38380b698330a6f5300bfd70278c45c0b6c60596e6ef6ac9828a84628fb",
    "mediatek/mt7662u_rom_patch.bin": "3c358bb8feebfa124e809891a9d8efc27c69efa8a3169f3061f625f6b25d2870",
}


def read_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
    return values


def file_evidence(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path),
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    config = read_config(args.config)
    mismatches = [
        {"symbol": symbol, "expected": expected, "actual": config.get(symbol)}
        for symbol, expected in REQUIRED_CONFIG.items()
        if config.get(symbol) != expected
    ]
    extra_firmware = config.get("CONFIG_EXTRA_FIRMWARE", "")
    for firmware_path in FIRMWARE:
        if firmware_path not in extra_firmware:
            mismatches.append(
                {
                    "symbol": "CONFIG_EXTRA_FIRMWARE",
                    "expected_contains": firmware_path,
                    "actual": extra_firmware,
                }
            )

    driver_objects = [
        args.out_dir / "drivers/net/wireless/mediatek/mt76/mt76.o",
        args.out_dir / "drivers/net/wireless/mediatek/mt76/mt76-usb.o",
        args.out_dir / "drivers/net/wireless/mediatek/mt76/mt76x2-common.o",
        args.out_dir / "drivers/net/wireless/mediatek/mt76/mt76x2u.o",
    ]
    firmware_objects = [
        args.out_dir / "firmware/mediatek/mt7662u.bin.gen.o",
        args.out_dir / "firmware/mediatek/mt7662u_rom_patch.bin.gen.o",
    ]
    missing_or_empty = [
        str(path) for path in driver_objects + firmware_objects
        if not path.is_file() or path.stat().st_size == 0
    ]

    image = args.image.read_bytes()
    image_markers = {
        "driver_name": b"mt76x2u" in image,
        "firmware_name": b"mediatek/mt7662u.bin" in image,
        "rom_patch_name": b"mediatek/mt7662u_rom_patch.bin" in image,
    }
    embedded_firmware: dict[str, bool] = {}
    firmware_evidence: list[dict[str, object]] = []
    for relative_path, expected_hash in FIRMWARE.items():
        firmware_path = args.source_root / "firmware" / relative_path
        payload = firmware_path.read_bytes()
        actual_hash = hashlib.sha256(payload).hexdigest()
        firmware_evidence.append(file_evidence(firmware_path))
        embedded_firmware[relative_path] = payload in image and actual_hash == expected_hash

    report = {
        "chipset": "MT7612U",
        "adapter": "ALFA AWUS036ACM",
        "config_mismatches": mismatches,
        "missing_or_empty_objects": missing_or_empty,
        "image_markers": image_markers,
        "embedded_firmware": embedded_firmware,
        "driver_objects": [file_evidence(path) for path in driver_objects if path.is_file()],
        "firmware_objects": [file_evidence(path) for path in firmware_objects if path.is_file()],
        "firmware_files": firmware_evidence,
        "image": file_evidence(args.image),
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    failed = (
        bool(mismatches)
        or bool(missing_or_empty)
        or not all(image_markers.values())
        or not all(embedded_firmware.values())
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

