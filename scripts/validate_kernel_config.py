#!/usr/bin/env python3
"""Validate a resolved Linux kernel .config against required fragments."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ASSIGNMENT = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
NOT_SET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
KCONFIG_SYMBOL = re.compile(r"^\s*(?:config|menuconfig)\s+([A-Za-z0-9_]+)\b")


def read_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    duplicates: list[str] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = ASSIGNMENT.match(raw) or NOT_SET.match(raw)
        if not match:
            continue
        symbol = match.group(1)
        value = match.group(2) if raw.startswith("CONFIG_") else "n"
        if symbol in values:
            duplicates.append(f"{symbol} at line {line_number}")
        values[symbol] = value
    if duplicates:
        raise ValueError(f"duplicate symbols in {path}: " + ", ".join(duplicates))
    return values


def discover_kconfig_symbols(source_root: Path) -> set[str]:
    symbols: set[str] = set()
    for path in source_root.rglob("Kconfig*"):
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            match = KCONFIG_SYMBOL.match(raw)
            if match:
                symbols.add(f"CONFIG_{match.group(1)}")
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--required", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--expected-assertions", type=int)
    parser.add_argument(
        "--allow-required-baseline-overrides",
        action="store_true",
        help="Do not report a baseline regression when the required fragment explicitly changes that symbol.",
    )
    args = parser.parse_args()

    final = read_config(args.config)
    required = read_config(args.required)
    baseline = read_config(args.baseline) if args.baseline else {}

    mismatches: list[dict[str, str | None]] = []
    for symbol, expected in sorted(required.items()):
        actual = final.get(symbol)
        if actual != expected:
            mismatches.append({"symbol": symbol, "expected": expected, "actual": actual})

    supported: set[str] = set()
    if args.source_root:
        supported = discover_kconfig_symbols(args.source_root)

    baseline_regressions: list[dict[str, str | None]] = []
    baseline_unsupported: list[str] = []
    baseline_preserved = 0
    for symbol, expected in sorted(baseline.items()):
        if expected not in {"y", "m"}:
            continue
        if args.allow_required_baseline_overrides and symbol in required:
            continue
        actual = final.get(symbol)
        if actual in {"y", "m"}:
            baseline_preserved += 1
        elif supported and symbol not in supported:
            baseline_unsupported.append(symbol)
        else:
            baseline_regressions.append(
                {"symbol": symbol, "expected_enabled": expected, "actual": actual}
            )

    report = {
        "config": str(args.config),
        "required_fragment": str(args.required),
        "required_count": len(required),
        "required_mismatches": mismatches,
        "baseline_fragment": str(args.baseline) if args.baseline else None,
        "baseline_enabled_count": sum(v in {"y", "m"} for v in baseline.values()),
        "baseline_preserved_count": baseline_preserved,
        "baseline_supported_regressions": baseline_regressions,
        "baseline_unsupported_symbols": baseline_unsupported,
        "expected_assertion_count": args.expected_assertions,
        "assertion_count_matches": (
            args.expected_assertions is None or len(required) == args.expected_assertions
        ),
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.json_output:
        args.json_output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    count_mismatch = (
        args.expected_assertions is not None
        and len(required) != args.expected_assertions
    )
    return 1 if mismatches or baseline_regressions or count_mismatch else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"config validation error: {error}", file=sys.stderr)
        raise SystemExit(2)
