#!/usr/bin/env python3
"""Force the target Samsung SELinux implementation permanently permissive."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RUNTIME_MARKER = "SELinux: forced persistent permissive mode"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"expected one patch target in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def append_once(path: Path, addition: str) -> None:
    text = path.read_text(encoding="utf-8")
    if addition.strip() in text:
        return
    path.write_text(text.rstrip() + "\n\n" + addition.strip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    selinux_root = source_root / "security/selinux"
    hooks = selinux_root / "hooks.c"
    selinuxfs = selinux_root / "selinuxfs.c"
    security_h = selinux_root / "include/security.h"
    avc = selinux_root / "avc.c"
    makefile = selinux_root / "Makefile"
    required_files = [hooks, selinuxfs, security_h, avc, makefile]
    missing = [str(path) for path in required_files if not path.is_file()]
    if missing:
        raise RuntimeError("incompatible SELinux source tree: " + ", ".join(missing))

    # Neutralize Samsung's build-variant macro even if a later build supplies
    # SEC_BUILD_OPTION_SELINUX_ENFORCE=true.
    append_once(
        makefile,
        """# NetHunter experiment: SELinux stays enabled but can never enforce.
ccflags-y += -UCONFIG_ALWAYS_ENFORCE""",
    )

    # Ignore an enforcing=1 boot argument and keep both boot/runtime state zero.
    replace_once(
        hooks,
        """#else
		selinux_enforcing = enforcing ? 1 : 0;
		selinux_enforcing_boot = enforcing ? 1 : 0;
#endif""",
        """#else
		selinux_enforcing = 0;
		selinux_enforcing_boot = 0;
#endif""",
    )

    # Make the boot log and final state explicit in the linked kernel.
    replace_once(
        hooks,
        """	if (selinux_enforcing_boot)
		printk(KERN_DEBUG "SELinux:  Starting in enforcing mode\\n");
	else
		printk(KERN_DEBUG "SELinux:  Starting in permissive mode\\n");""",
        """	enforcing_set(&selinux_state, false);
	printk(KERN_INFO "SELinux: forced persistent permissive mode\\n");
	printk(KERN_DEBUG "SELinux:  Starting in permissive mode\\n");""",
    )

    # Every enforcement read reports false and every enforcement write stores
    # zero, including the Samsung KDP read-only variable path.
    replace_once(
        security_h,
        """static inline bool enforcing_enabled(struct selinux_state *state)
{
	return selinux_enforcing; // SEC_SELINUX_PORTING_COMMON Change to use RKP 
}

static inline void enforcing_set(struct selinux_state *state, bool value)
{
#if (defined CONFIG_KDP_CRED && defined CONFIG_SAMSUNG_PRODUCT_SHIP)
    uh_call(UH_APP_RKP, RKP_KDP_X60, (u64)&selinux_enforcing, (u64)value, 0, 0);
#else
    selinux_enforcing = value; // SEC_SELINUX_PORTING_COMMON Change to use RKP 
#endif
}""",
        """static inline bool enforcing_enabled(struct selinux_state *state)
{
	return false;
}

static inline void enforcing_set(struct selinux_state *state, bool value)
{
#if (defined CONFIG_KDP_CRED && defined CONFIG_SAMSUNG_PRODUCT_SHIP)
    uh_call(UH_APP_RKP, RKP_KDP_X60, (u64)&selinux_enforcing, (u64)false, 0, 0);
#else
    selinux_enforcing = 0;
#endif
}""",
    )

    # setenforce 1 becomes a successful no-op that leaves the state at zero.
    replace_once(
        selinuxfs,
        "\tnew_value = !!new_value;",
        "\tnew_value = 0; /* forced persistent permissive */",
    )

    # Remove both SELinux denial exits, including the AVC_STRICT exception
    # that normally remains enforcing even while global SELinux is permissive.
    replace_once(
        avc,
        """	if (flags & AVC_STRICT)
		return -EACCES;
""",
        """	/* Forced permissive: AVC_STRICT never converts a denial to failure. */
""",
    )
    replace_once(
        avc,
        """#ifdef CONFIG_ALWAYS_ENFORCE
	if (!(avd->flags & AVD_FLAGS_PERMISSIVE))
#else
	if (selinux_enforcing &&
	    !(avd->flags & AVD_FLAGS_PERMISSIVE))
#endif
		return -EACCES;""",
        """	/* Forced permissive: record/audit the denial but always grant it. */""",
    )

    manifest = {
        "mode": "forced-persistent-permissive",
        "selinux_enabled": True,
        "runtime_marker": RUNTIME_MARKER,
        "invariants": [
            "enforcing= boot argument is coerced to zero",
            "setenforce writes are coerced to zero",
            "enforcing_enabled always returns false",
            "enforcing_set can only store zero",
            "CONFIG_ALWAYS_ENFORCE is undefined for SELinux objects",
            "AVC_STRICT denials do not fail",
            "ordinary AVC denials do not fail",
        ],
        "patched_files_sha256": {
            str(path.relative_to(source_root)): sha256(path) for path in required_files
        },
    }
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

