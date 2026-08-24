from __future__ import annotations

import json
import os
import sys
import tempfile
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

    def test_toolchain_bins_do_not_shadow_host_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "clang"
            selected = root / "clang-r383902b/bin"
            newer = root / "clang-r999999/bin"
            selected.mkdir(parents=True)
            newer.mkdir(parents=True)
            (selected / "clang").write_text("", encoding="utf-8")
            (newer / "clang").write_text("", encoding="utf-8")
            env, prefixes = kernel_harness.build_environment(
                {"clang": root},
                [{"name": "clang"}],
            )
            original_path = os.environ.get("PATH", "")
            self.assertTrue(env["PATH"].startswith(original_path + os.pathsep))
            self.assertIn(str(selected), prefixes)
            self.assertIn(str(newer), prefixes)
            composed = kernel_harness.add_harness_variables(
                env,
                source=Path("/tmp/source"),
                out_dir=Path("/tmp/out"),
                profile_id="test",
            )
            self.assertEqual(composed["PATH"], env["PATH"])

    def test_make_compiler_can_select_an_exact_toolchain_path(self) -> None:
        toolchain = Path("/tmp/toolchains/clang")
        value = kernel_harness.resolve_placeholders(
            "{toolchain:clang}/clang-r383902/bin/clang",
            {"clang": toolchain},
        )
        self.assertEqual(
            value,
            "/tmp/toolchains/clang/clang-r383902/bin/clang",
        )


if __name__ == "__main__":
    unittest.main()
