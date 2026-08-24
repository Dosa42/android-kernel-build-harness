#!/usr/bin/env python3
"""Deterministic local/GitHub Actions Linux kernel build harness."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import traceback
from pathlib import Path
from typing import Any


HARNESS_ROOT = Path(__file__).resolve().parents[1]
FEATURE_OVERRIDES = {
    "kernelsu": "kernelsu",
    "mt7612u": "mt7612u_backport",
    "forced_permissive": "selinux",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def config_assertion_count(path: Path) -> int:
    return sum(
        line.startswith("CONFIG_") or line.startswith("# CONFIG_")
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def repository_path(value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (HARNESS_ROOT / path).resolve()


def validate_profile(profile_path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    required_sections = {
        "schema_version",
        "id",
        "source",
        "kernel",
        "toolchains",
        "make",
        "features",
        "config",
        "boot_image",
        "commands",
    }
    missing = sorted(required_sections - profile.keys())
    if missing:
        errors.append("missing profile keys: " + ", ".join(missing))
    if profile.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    source = profile.get("source", {})
    for key in ("repository", "ref"):
        if not isinstance(source.get(key), str) or not source.get(key):
            errors.append(f"source.{key} must be a non-empty string")

    kernel = profile.get("kernel", {})
    for key in ("arch", "defconfig", "out_dir"):
        if not isinstance(kernel.get(key), str) or not kernel.get(key):
            errors.append(f"kernel.{key} must be a non-empty string")
    if not isinstance(kernel.get("make_targets", []), list):
        errors.append("kernel.make_targets must be a list")

    toolchains = profile.get("toolchains", [])
    if not isinstance(toolchains, list):
        errors.append("toolchains must be a list")
        toolchains = []
    names: list[str] = []
    for index, toolchain in enumerate(toolchains):
        if not isinstance(toolchain, dict):
            errors.append(f"toolchains[{index}] must be an object")
            continue
        for key in ("name", "repository", "ref"):
            if not isinstance(toolchain.get(key), str) or not toolchain.get(key):
                errors.append(f"toolchains[{index}].{key} must be a non-empty string")
        if isinstance(toolchain.get("name"), str):
            names.append(toolchain["name"])
        path_globs = toolchain.get("path_prepend_globs", [])
        if not isinstance(path_globs, list) or not all(
            isinstance(value, str) and value for value in path_globs
        ):
            errors.append(
                f"toolchains[{index}].path_prepend_globs must be a list of non-empty strings"
            )
    if len(names) != len(set(names)):
        errors.append("toolchain names must be unique")

    config = profile.get("config", {})
    fragment_value = config.get("fragment")
    fragment: Path | None = None
    if not isinstance(fragment_value, str) or not fragment_value:
        errors.append("config.fragment must be a non-empty string")
    else:
        fragment = repository_path(fragment_value)
        if not fragment.is_file():
            errors.append(f"config fragment does not exist: {fragment}")
    expected = config.get("expected_assertions")
    if not isinstance(expected, int) or expected < 1:
        errors.append("config.expected_assertions must be a positive integer")
    elif fragment and fragment.is_file():
        actual = config_assertion_count(fragment)
        if actual != expected:
            errors.append(
                f"config assertion count mismatch: expected {expected}, found {actual}"
            )

    features = profile.get("features", {})
    selinux = features.get("selinux", {})
    if selinux.get("enabled") and selinux.get("mode") not in {
        "forced-persistent-permissive",
        "source-default",
    }:
        errors.append("features.selinux.mode is unsupported")

    commands = profile.get("commands", {})
    for phase in ("post_clone", "pre_config", "pre_build", "post_build"):
        if not isinstance(commands.get(phase, []), list) or not all(
            isinstance(command, str) for command in commands.get(phase, [])
        ):
            errors.append(f"commands.{phase} must be a list of strings")

    report = {
        "profile": str(profile_path),
        "profile_id": profile.get("id"),
        "schema_version": profile.get("schema_version"),
        "config_fragment": str(fragment) if fragment else None,
        "config_assertions": config_assertion_count(fragment) if fragment and fragment.is_file() else None,
        "toolchains": names,
        "errors": errors,
        "valid": not errors,
    }
    return report


class CommandRunner:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.commands: list[dict[str, Any]] = []

    def write(self, text: str) -> None:
        print(text, flush=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(text + "\n")

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
        label: str | None = None,
    ) -> None:
        started = utc_now()
        rendered = shlex.join(str(item) for item in command)
        self.write(f"\n[{label or 'command'}] cwd={cwd}\n$ {rendered}")
        record: dict[str, Any] = {
            "label": label,
            "cwd": str(cwd),
            "command": command,
            "started_at": started,
        }
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        assert process.stdout is not None
        with self.log_path.open("a", encoding="utf-8") as log:
            for line in process.stdout:
                print(line, end="", flush=True)
                log.write(line)
        return_code = process.wait()
        record["finished_at"] = utc_now()
        record["return_code"] = return_code
        self.commands.append(record)
        if return_code != 0:
            raise RuntimeError(f"command failed ({return_code}): {rendered}")

    def shell(
        self,
        command: str,
        *,
        cwd: Path,
        env: dict[str, str],
        label: str,
    ) -> None:
        self.run(
            ["bash", "-euxo", "pipefail", "-c", command],
            cwd=cwd,
            env=env,
            label=label,
        )


def bool_override(value: str, inherited: bool) -> bool:
    if value == "inherit":
        return inherited
    return value == "true"


def apply_overrides(profile: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    resolved = copy.deepcopy(profile)
    if args.source_repository:
        resolved["source"]["repository"] = args.source_repository
    if args.source_ref:
        resolved["source"]["ref"] = args.source_ref
    if args.defconfig:
        resolved["kernel"]["defconfig"] = args.defconfig
    if args.config_fragment:
        resolved["config"]["fragment"] = args.config_fragment
        resolved["config"]["expected_assertions"] = config_assertion_count(
            repository_path(args.config_fragment)
        )

    for argument_name, feature_name in FEATURE_OVERRIDES.items():
        value = getattr(args, argument_name)
        feature = resolved["features"].setdefault(feature_name, {})
        feature["enabled"] = bool_override(value, bool(feature.get("enabled")))
    if args.kernelsu_ref:
        resolved["features"]["kernelsu"]["ref"] = args.kernelsu_ref
    return resolved


def safe_clean(path: Path) -> None:
    resolved = path.resolve()
    forbidden = {Path("/").resolve(), Path.home().resolve(), HARNESS_ROOT.resolve()}
    if resolved in forbidden or len(resolved.parts) < 3:
        raise ValueError(f"refusing to clean broad path: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)


def git_clone(
    runner: CommandRunner,
    definition: dict[str, Any],
    destination: Path,
    cwd: Path,
    label: str,
) -> None:
    command = ["git", "clone"]
    if definition.get("recursive", True):
        command.append("--recursive")
    depth = definition.get("depth")
    if depth:
        command.extend(["--depth", str(depth)])
    command.extend(
        [
            "--branch",
            definition["ref"],
            definition["repository"],
            str(destination),
        ]
    )
    runner.run(command, cwd=cwd, label=label)


def git_commit(runner: CommandRunner, repository: Path, label: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    )
    commit = result.stdout.strip()
    runner.write(f"[{label}] {commit}")
    return commit


def resolve_placeholders(value: str, toolchains: dict[str, Path]) -> str:
    resolved = value
    for name, path in toolchains.items():
        resolved = resolved.replace(f"{{toolchain:{name}}}", str(path))
    return resolved


def build_environment(
    toolchains: dict[str, Path], definitions: list[dict[str, Any]]
) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    preferred: list[Path] = []
    bin_dirs: list[Path] = []
    definition_by_name = {item["name"]: item for item in definitions}
    for name, root in toolchains.items():
        definition = definition_by_name[name]
        for pattern in definition.get("path_prepend_globs", []):
            matches = sorted(path for path in root.glob(pattern) if path.is_dir())
            if not matches:
                raise RuntimeError(
                    f"toolchain {name!r} path_prepend_glob matched nothing: {pattern}"
                )
            preferred.extend(matches)
        bin_dirs.extend(path for path in root.rglob("bin") if path.is_dir())
    clang_bins = sorted(
        path.parent
        for root in toolchains.values()
        for path in root.rglob("bin/clang")
        if path.is_file()
    )
    ordered: list[Path] = list(preferred)
    if clang_bins and not preferred:
        ordered.append(clang_bins[-1])
    ordered.extend(sorted(set(bin_dirs)))
    unique = list(dict.fromkeys(str(path) for path in ordered))
    env["PATH"] = os.pathsep.join(unique + [env.get("PATH", "")])
    return env, unique


def add_harness_variables(
    env: dict[str, str], *, source: Path, out_dir: Path, profile_id: str
) -> dict[str, str]:
    result = env.copy()
    result.update(
        {
            "HARNESS_ROOT": str(HARNESS_ROOT),
            "KERNEL_SOURCE": str(source),
            "OUT_DIR": str(out_dir),
            "PROFILE_ID": profile_id,
        }
    )
    return result


def run_hooks(
    runner: CommandRunner,
    commands: dict[str, list[str]],
    phase: str,
    source: Path,
    env: dict[str, str],
) -> None:
    for index, command in enumerate(commands.get(phase, []), 1):
        runner.shell(command, cwd=source, env=env, label=f"hook:{phase}:{index}")


def feature_enabled(profile: dict[str, Any], name: str) -> bool:
    return bool(profile.get("features", {}).get(name, {}).get("enabled"))


def tar_paths(paths: list[Path], root: Path, output: Path) -> None:
    if not paths:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for path in sorted(paths):
            archive.add(path, arcname=path.relative_to(root))


def collect_artifacts(
    *,
    profile: dict[str, Any],
    source: Path,
    out_dir: Path,
    artifacts: Path,
    state: dict[str, Any],
    runner: CommandRunner,
) -> None:
    artifacts.mkdir(parents=True, exist_ok=True)
    kernel_artifacts = artifacts / "kernel"
    kernel_artifacts.mkdir(parents=True, exist_ok=True)
    evidence = artifacts / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)

    arch = profile["kernel"]["arch"]
    boot_dir = out_dir / "arch" / arch / "boot"
    for name in ("Image", "Image.gz", "Image.lz4", "dtbo.img"):
        candidate = boot_dir / name
        if candidate.is_file():
            shutil.copy2(candidate, kernel_artifacts / name)

    if out_dir.is_dir():
        tar_paths(list((boot_dir / "dts").rglob("*.dtb")), out_dir, kernel_artifacts / "dtbs.tar.gz")
        tar_paths(list(out_dir.rglob("*.ko")), out_dir, kernel_artifacts / "modules.tar.gz")

    config = out_dir / ".config"
    if config.is_file():
        shutil.copy2(config, evidence / "resolved.config")
    baseline = out_dir.parent / "baseline.config"
    if baseline.is_file():
        shutil.copy2(baseline, evidence / "baseline.config")

    profile_output = evidence / "resolved-profile.json"
    profile_output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    state["commands"] = runner.commands
    state["finished_at"] = utc_now()
    state_path = evidence / "run-summary.json"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    summary_lines = [
        f"# Kernel harness run: {profile['id']}",
        "",
        f"- Status: **{state['status']}**",
        f"- Source: `{profile['source']['repository']}` @ `{profile['source']['ref']}`",
        f"- Defconfig: `{profile['kernel']['defconfig']}`",
        f"- Required assertions: `{profile['config']['expected_assertions']}`",
        f"- KernelSU: `{feature_enabled(profile, 'kernelsu')}`",
        f"- MT7612U: `{feature_enabled(profile, 'mt7612u_backport')}`",
        f"- SELinux mode: `{profile['features']['selinux'].get('mode') if feature_enabled(profile, 'selinux') else 'source-default'}`",
        f"- Flashable boot image: `{state.get('boot_image_status', 'not-requested')}`",
    ]
    if state.get("error"):
        summary_lines.extend(["", "## Failure", "", f"`{state['error']}`"])
    (artifacts / "SUMMARY.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    entries: list[dict[str, Any]] = []
    for path in sorted(artifacts.rglob("*")):
        if path.is_file() and path.name not in {"SHA256SUMS", "artifact-manifest.json"}:
            entries.append(
                {
                    "path": str(path.relative_to(artifacts)),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    manifest = {
        "profile_id": profile["id"],
        "status": state["status"],
        "source_commit": state.get("source_commit"),
        "toolchain_commits": state.get("toolchain_commits", {}),
        "artifacts": entries,
    }
    (artifacts / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    checksum_paths = [path for path in artifacts.rglob("*") if path.is_file() and path.name != "SHA256SUMS"]
    checksum_text = "".join(
        f"{sha256_file(path)}  {path.relative_to(artifacts)}\n"
        for path in sorted(checksum_paths)
    )
    (artifacts / "SHA256SUMS").write_text(checksum_text, encoding="utf-8")


def execute_build(args: argparse.Namespace) -> int:
    profile_path = Path(args.profile).resolve()
    original_profile = read_json(profile_path)
    profile = apply_overrides(original_profile, args)
    validation = validate_profile(profile_path, profile)
    if not validation["valid"]:
        print(json.dumps(validation, indent=2))
        return 2

    work_dir = Path(args.work_dir).resolve()
    artifacts = Path(args.artifacts_dir).resolve()
    if args.clean:
        safe_clean(work_dir)
        safe_clean(artifacts)
    elif work_dir.exists() and any(work_dir.iterdir()):
        raise ValueError(f"work directory is not empty; use --clean: {work_dir}")
    work_dir.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)

    source = work_dir / "source"
    toolchain_root = work_dir / "toolchains"
    toolchain_root.mkdir(parents=True, exist_ok=True)
    out_dir = work_dir / profile["kernel"]["out_dir"]
    evidence = artifacts / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    runner = CommandRunner(evidence / "build.log")

    state: dict[str, Any] = {
        "status": "running",
        "started_at": utc_now(),
        "profile": str(profile_path),
        "profile_id": profile["id"],
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        },
        "boot_image_status": "not-requested",
    }

    try:
        git_clone(runner, profile["source"], source, work_dir, "clone:kernel")
        state["source_commit"] = git_commit(runner, source, "source-commit")

        base_env = add_harness_variables(
            os.environ.copy(),
            source=source,
            out_dir=out_dir,
            profile_id=profile["id"],
        )
        run_hooks(runner, profile["commands"], "post_clone", source, base_env)

        if feature_enabled(profile, "mt7612u_backport"):
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/install_mt76x2u_backport.py"),
                    "--source-root",
                    str(source),
                    "--json-output",
                    str(evidence / "mt7612u-backport.json"),
                ],
                cwd=source,
                label="feature:mt7612u-backport",
            )

        selinux = profile["features"]["selinux"]
        if feature_enabled(profile, "selinux") and selinux.get("mode") == "forced-persistent-permissive":
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/force_selinux_permissive.py"),
                    "--source-root",
                    str(source),
                    "--json-output",
                    str(evidence / "selinux-permissive-patch.json"),
                ],
                cwd=source,
                label="feature:forced-persistent-permissive",
            )

        kernelsu = profile["features"]["kernelsu"]
        if feature_enabled(profile, "kernelsu"):
            for relative in ("KernelSU", "drivers/kernelsu"):
                candidate = source / relative
                if candidate.exists():
                    shutil.rmtree(candidate)
            setup_script = work_dir / "kernelsu-setup.sh"
            runner.run(
                ["curl", "-fL", kernelsu["setup_url"], "-o", str(setup_script)],
                cwd=work_dir,
                label="feature:kernelsu-download",
            )
            state["kernelsu_setup_sha256"] = sha256_file(setup_script)
            runner.run(
                ["bash", str(setup_script), kernelsu["ref"]],
                cwd=source,
                label="feature:kernelsu-install",
            )

        toolchains: dict[str, Path] = {}
        commits: dict[str, str] = {}
        for definition in profile["toolchains"]:
            destination = toolchain_root / definition["name"]
            git_clone(
                runner,
                definition,
                destination,
                toolchain_root,
                f"clone:toolchain:{definition['name']}",
            )
            toolchains[definition["name"]] = destination
            commits[definition["name"]] = git_commit(
                runner, destination, f"toolchain-commit:{definition['name']}"
            )
        state["toolchain_commits"] = commits

        env, path_prefixes = build_environment(toolchains, profile["toolchains"])
        env = add_harness_variables(
            env,
            source=source,
            out_dir=out_dir,
            profile_id=profile["id"],
        )
        state["toolchain_path_prefixes"] = path_prefixes
        if profile["make"].get("params", {}).get("CC") == "clang":
            runner.run(
                ["clang", "--version"],
                cwd=source,
                env=env,
                label="toolchain:clang-version",
            )
        make_values: dict[str, str] = {"ARCH": profile["kernel"]["arch"]}
        for section in ("params", "extra_params"):
            for key, value in profile["make"].get(section, {}).items():
                if value != "":
                    make_values[key] = resolve_placeholders(str(value), toolchains)
        jobs = args.jobs or (os.cpu_count() or 2)
        make_args = [
            "make",
            f"-j{jobs}",
            f"O={out_dir}",
            *[f"{key}={value}" for key, value in make_values.items()],
        ]
        state["make_arguments"] = make_args[1:]

        run_hooks(runner, profile["commands"], "pre_config", source, env)
        runner.run(
            make_args + [profile["kernel"]["defconfig"]],
            cwd=source,
            env=env,
            label="make:defconfig",
        )
        shutil.copy2(out_dir / ".config", work_dir / "baseline.config")

        fragment = repository_path(profile["config"]["fragment"])
        runner.run(
            [
                "bash",
                str(source / "scripts/kconfig/merge_config.sh"),
                "-m",
                "-O",
                str(out_dir),
                str(out_dir / ".config"),
                str(fragment),
            ],
            cwd=source,
            env=env,
            label="config:merge",
        )
        runner.run(
            make_args + ["olddefconfig"],
            cwd=source,
            env=env,
            label="make:olddefconfig",
        )

        validator = [
            sys.executable,
            str(HARNESS_ROOT / "scripts/validate_kernel_config.py"),
            "--config",
            str(out_dir / ".config"),
            "--required",
            str(fragment),
            "--source-root",
            str(source),
            "--json-output",
            str(evidence / "config-validation.json"),
            "--expected-assertions",
            str(profile["config"]["expected_assertions"]),
        ]
        if profile["config"].get("preserve_baseline"):
            validator.extend(
                [
                    "--baseline",
                    str(work_dir / "baseline.config"),
                    "--allow-required-baseline-overrides",
                ]
            )
        runner.run(validator, cwd=source, env=env, label="config:validate")

        run_hooks(runner, profile["commands"], "pre_build", source, env)
        runner.run(
            make_args + list(profile["kernel"].get("make_targets", [])),
            cwd=source,
            env=env,
            label="make:kernel",
        )
        run_hooks(runner, profile["commands"], "post_build", source, env)

        image = out_dir / "arch" / profile["kernel"]["arch"] / "boot" / "Image"
        if not image.is_file() or image.stat().st_size == 0:
            raise RuntimeError(f"kernel Image was not produced: {image}")

        if feature_enabled(profile, "kernelsu"):
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/verify_kernelsu_build.py"),
                    "--source-root",
                    str(source),
                    "--config",
                    str(out_dir / ".config"),
                    "--out-dir",
                    str(out_dir),
                    "--image",
                    str(image),
                    "--expected-ref",
                    kernelsu["ref"],
                    "--json-output",
                    str(evidence / "kernelsu-build-evidence.json"),
                ],
                cwd=source,
                env=env,
                label="verify:kernelsu",
            )

        if feature_enabled(profile, "mt7612u_backport"):
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/verify_mt76x2u_build.py"),
                    "--source-root",
                    str(source),
                    "--config",
                    str(out_dir / ".config"),
                    "--out-dir",
                    str(out_dir),
                    "--image",
                    str(image),
                    "--json-output",
                    str(evidence / "mt7612u-build-evidence.json"),
                ],
                cwd=source,
                env=env,
                label="verify:mt7612u",
            )

        if feature_enabled(profile, "selinux") and selinux.get("mode") == "forced-persistent-permissive":
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/verify_selinux_permissive_build.py"),
                    "--source-root",
                    str(source),
                    "--config",
                    str(out_dir / ".config"),
                    "--image",
                    str(image),
                    "--patch-manifest",
                    str(evidence / "selinux-permissive-patch.json"),
                    "--json-output",
                    str(evidence / "selinux-permissive-build-evidence.json"),
                ],
                cwd=source,
                env=env,
                label="verify:forced-persistent-permissive",
            )

        if args.base_boot:
            base_boot = Path(args.base_boot).resolve()
            if not base_boot.is_file():
                raise RuntimeError(f"base boot image does not exist: {base_boot}")
            boot = profile["boot_image"]
            if boot.get("packer") != "android-v2":
                raise RuntimeError(f"unsupported boot packer: {boot.get('packer')}")
            kernel_payload = out_dir / boot["kernel_payload"].format(
                arch=profile["kernel"]["arch"]
            )
            flashable = artifacts / "flashable" / boot["output_name"]
            flashable.parent.mkdir(parents=True, exist_ok=True)
            runner.run(
                [
                    sys.executable,
                    str(HARNESS_ROOT / "scripts/repack_boot_v2.py"),
                    "--base",
                    str(base_boot),
                    "--kernel",
                    str(kernel_payload),
                    "--output",
                    str(flashable),
                    "--json-output",
                    str(evidence / "boot-repack-evidence.json"),
                ],
                cwd=source,
                env=env,
                label="package:boot-image",
            )
            state["boot_image_status"] = "built-and-structurally-verified"

        state["status"] = "succeeded"
        return_code = 0
    except Exception as error:  # evidence is finalized below for every failure
        state["status"] = "failed"
        state["error"] = f"{type(error).__name__}: {error}"
        state["traceback"] = traceback.format_exc()
        runner.write(state["traceback"])
        return_code = 1
    finally:
        collect_artifacts(
            profile=profile,
            source=source,
            out_dir=out_dir,
            artifacts=artifacts,
            state=state,
            runner=runner,
        )
    return return_code


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-profile")
    validate.add_argument("--profile", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--profile", required=True)
    build.add_argument("--work-dir", default="work")
    build.add_argument("--artifacts-dir", default="artifacts")
    build.add_argument("--clean", action="store_true")
    build.add_argument("--jobs", type=int)
    build.add_argument("--base-boot")
    build.add_argument("--source-repository")
    build.add_argument("--source-ref")
    build.add_argument("--defconfig")
    build.add_argument("--config-fragment")
    build.add_argument("--kernelsu-ref")
    build.add_argument("--kernelsu", choices=("inherit", "true", "false"), default="inherit")
    build.add_argument("--mt7612u", choices=("inherit", "true", "false"), default="inherit")
    build.add_argument("--forced-permissive", choices=("inherit", "true", "false"), default="inherit")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    if args.command == "validate-profile":
        path = Path(args.profile).resolve()
        report = validate_profile(path, read_json(path))
        print(json.dumps(report, indent=2))
        return 0 if report["valid"] else 1
    if args.command == "build":
        return execute_build(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
