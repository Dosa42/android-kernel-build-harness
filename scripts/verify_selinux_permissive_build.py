#!/usr/bin/env python3
"""Verify forced persistent SELinux permissive behavior in source and Image."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RUNTIME_MARKER = "SELinux: forced persistent permissive mode"
REQUIRED_CONFIG = {
    "CONFIG_SECURITY": "y",
    "CONFIG_SECURITY_SELINUX": "y",
    "CONFIG_SECURITY_SELINUX_BOOTPARAM": "y",
    "CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE": "1",
    "CONFIG_SECURITY_SELINUX_DEVELOP": "y",
    "CONFIG_DEFAULT_SECURITY_SELINUX": "y",
    "CONFIG_DEFAULT_SECURITY": '"selinux"',
}
SOURCE_MARKERS = {
    "security/selinux/Makefile": ["ccflags-y += -UCONFIG_ALWAYS_ENFORCE"],
    "security/selinux/hooks.c": [
        "selinux_enforcing = 0;",
        "selinux_enforcing_boot = 0;",
        RUNTIME_MARKER,
    ],
    "security/selinux/include/security.h": [
        "return false;",
        "(u64)false",
        "selinux_enforcing = 0;",
    ],
    "security/selinux/selinuxfs.c": [
        "new_value = 0; /* forced persistent permissive */"
    ],
    "security/selinux/avc.c": [
        "AVC_STRICT never converts a denial to failure",
        "record/audit the denial but always grant it",
    ],
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


def evidence(path: Path) -> dict[str, object]:
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
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--patch-manifest", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    config = read_config(args.config)
    config_mismatches = [
        {"symbol": symbol, "expected": expected, "actual": config.get(symbol)}
        for symbol, expected in REQUIRED_CONFIG.items()
        if config.get(symbol) != expected
    ]

    missing_source_markers: list[dict[str, str]] = []
    source_evidence: list[dict[str, object]] = []
    for relative_path, markers in SOURCE_MARKERS.items():
        path = args.source_root / relative_path
        text = path.read_text(encoding="utf-8")
        source_evidence.append(evidence(path))
        for marker in markers:
            if marker not in text:
                missing_source_markers.append({"path": relative_path, "marker": marker})

    manifest = json.loads(args.patch_manifest.read_text(encoding="utf-8"))
    manifest_mismatches: list[dict[str, str]] = []
    if manifest.get("mode") != "forced-persistent-permissive":
        manifest_mismatches.append({
            "field": "mode",
            "expected": "forced-persistent-permissive",
            "actual": str(manifest.get("mode")),
        })
    if manifest.get("selinux_enabled") is not True:
        manifest_mismatches.append({
            "field": "selinux_enabled", "expected": "true",
            "actual": str(manifest.get("selinux_enabled")),
        })

    image = args.image.read_bytes()
    image_marker_present = RUNTIME_MARKER.encode() in image
    report = {
        "mode": "forced-persistent-permissive",
        "config_mismatches": config_mismatches,
        "missing_source_markers": missing_source_markers,
        "manifest_mismatches": manifest_mismatches,
        "runtime_marker_in_image": image_marker_present,
        "source_files": source_evidence,
        "patch_manifest": evidence(args.patch_manifest),
        "image": evidence(args.image),
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    failed = (
        bool(config_mismatches)
        or bool(missing_source_markers)
        or bool(manifest_mismatches)
        or not image_marker_present
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

