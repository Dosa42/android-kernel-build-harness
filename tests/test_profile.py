from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import kernel_harness  # noqa: E402


class ProfileTests(unittest.TestCase):
    def test_a32x_reference_profile_is_valid_and_complete(self) -> None:
        profile_path = ROOT / "profiles/a32x-full.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        report = kernel_harness.validate_profile(profile_path, profile)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["config_assertions"], 234)
        self.assertEqual(profile["features"]["selinux"]["mode"], "forced-persistent-permissive")
        self.assertTrue(profile["features"]["mt7612u_backport"]["enabled"])
        self.assertTrue(profile["features"]["kernelsu"]["enabled"])


if __name__ == "__main__":
    unittest.main()
