# Profile format

Every build is a JSON document in `profiles/`. A profile is versioned with the harness so an experiment can be reproduced from its source commit, profile, config fragment and generated evidence.

## Required sections

### `source`

- `repository`: clone URL for the kernel source
- `ref`: exact branch or tag
- `recursive`: whether submodules are cloned
- `depth`: shallow-clone depth; omit or set `null` for full history

### `kernel`

- `arch`: kernel architecture, normally `arm64`
- `defconfig`: exact make defconfig target
- `out_dir`: isolated Kbuild output directory inside the work directory
- `make_targets`: optional explicit targets; an empty list invokes the source default build

### `toolchains`

Each toolchain has a unique `name`, `repository`, `ref`, and optional `recursive` and `depth`. All discovered `bin` directories are added to `PATH`.

Make values can reference an absolute checkout path with `{toolchain:name}`. Example:

```json
"CROSS_COMPILE": "{toolchain:gcc64}/bin/aarch64-linux-android-"
```

### `make`

`params` and `extra_params` become exact `KEY=value` arguments on defconfig, olddefconfig and the final build. Empty values are omitted; no value is silently substituted.

### `features`

Known feature integrations are independently selectable:

- `kernelsu`: installs the requested KernelSU ref and verifies final config plus compiled objects
- `mt7612u_backport`: installs the pinned Linux 4.19 MT76 source and pinned firmware, applies 4.14 compatibility edits, and verifies driver objects and embedded firmware in the linked Image
- `selinux`: `forced-persistent-permissive` retains SELinux as Android's selected LSM while compiled source forces every enforcement read/write and AVC denial path permissive

Workflow overrides use `inherit`, `true`, or `false`. `inherit` means exactly the profile value.

### `config`

- `fragment`: repository-relative required Kconfig fragment
- `expected_assertions`: exact number of `CONFIG_...` or `# CONFIG_... is not set` assertions
- `preserve_baseline`: preserve enabled defconfig symbols unless the required fragment explicitly overrides them

The validator runs after `olddefconfig`; unsupported or dependency-rejected requested values are failures.

### `boot_image`

- `packer`: currently `android-v2`
- `kernel_payload`: output path relative to Kbuild's output directory
- `output_name`: generated flashable filename

Packaging runs only when a base boot image is explicitly supplied. A missing base image is recorded as `not-requested`; it does not pretend that a raw `Image` is flashable.

### `commands`

Profiles may execute their own shell commands at four phases:

- `post_clone`
- `pre_config`
- `pre_build`
- `post_build`

Commands run with `bash -euxo pipefail` in the kernel source. Available variables include:

- `HARNESS_ROOT`
- `KERNEL_SOURCE`
- `OUT_DIR`
- `PROFILE_ID`

Hook commands are intentionally unrestricted profile-owned experiment code. Their command text, output and exit status are written to the build log, and any nonzero exit fails the run.

## Workflow overrides

The GitHub form can override the profile's source repository, source ref, defconfig, config fragment, KernelSU ref, and three known feature states. Overrides appear in `resolved-profile.json` so the produced artifact records what was actually built.
