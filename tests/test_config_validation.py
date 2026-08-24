from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ConfigValidationTests(unittest.TestCase):
    def test_exact_assertion_count_and_required_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            required = root / "required.config"
            resolved = root / ".config"
            report = root / "report.json"
            required.write_text(
                "CONFIG_ALPHA=y\n# CONFIG_BETA is not set\n", encoding="utf-8"
            )
            resolved.write_text(
                "CONFIG_ALPHA=y\n# CONFIG_BETA is not set\n", encoding="utf-8"
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate_kernel_config.py"),
                    "--config",
                    str(resolved),
                    "--required",
                    str(required),
                    "--expected-assertions",
                    "2",
                    "--json-output",
                    str(report),
                ],
                check=True,
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertTrue(payload["assertion_count_matches"])
            self.assertEqual(payload["required_mismatches"], [])


if __name__ == "__main__":
    unittest.main()
