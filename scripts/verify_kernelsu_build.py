#!/usr/bin/env python3
"""Verify that KernelSU is configured and its objects were compiled."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


REQUIRED_CONFIG = {
    "CONFIG_KSU": "y",
    "CONFIG_KSU_DEBUG": "y",
    "CONFIG_KPROBES": "y",
    "CONFIG_HAVE_KPROBES": "y",
    "CONFIG_KPROBE_EVENTS": "y",
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
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    config = read_config(args.config)
    mismatches = [
        {"symbol": symbol, "expected": expected, "actual": config.get(symbol)}
        for symbol, expected in REQUIRED_CONFIG.items()
        if config.get(symbol) != expected
    ]

    source_candidates = [
        args.source_root / "KernelSU",
        args.source_root / "drivers/kernelsu",
    ]
    source_roots = [path for path in source_candidates if path.is_dir()]

    objects = [
        path
        for path in args.out_dir.rglob("*.o")
        if "kernelsu" in str(path).lower()
    ]
    objects = sorted(path for path in objects if path.stat().st_size > 0)

    image = args.image.read_bytes()
    image_markers = {
        marker.decode(): marker in image
        for marker in (b"KernelSU", b"kernelsu", b"ksud")
    }
    report = {
        "expected_ref": args.expected_ref,
        "config_mismatches": mismatches,
        "source_roots": [str(path) for path in source_roots],
        "compiled_objects": [evidence(path) for path in objects],
        "image_markers": image_markers,
        "image": evidence(args.image),
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

    failed = bool(mismatches) or not source_roots or not objects
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
