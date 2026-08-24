# Android Kernel Build Harness

A reusable, profile-driven Linux/Android kernel build system for GitHub Actions and local Linux. It keeps source selection, toolchains, kernel configuration, feature patches, verification, evidence, and boot-image packaging in one deterministic pipeline.

The initial `a32x-full` profile is the exact continuation of the successful Samsung A32x work:

- `ASKSAP/android_kernel_samsung_a32x` at `A326BXXU1AUA5`
- `a32x_defconfig`, ARM64 and the Android R clang/GCC toolchains
- KernelSU `v0.9.5`
- 234 required NetHunter configuration assertions
- built-in ALFA AWUS036ACM / MT7612U driver and embedded firmware
- MediaTek USB host, XHCI, MTU3 dual-role, PHY, Type-C and extcon chain enabled
- SELinux enabled but permanently forced fully permissive in the compiled kernel
- source, config, object, firmware and linked-Image verification
- optional real 32 MiB Android boot-image v2 repacking

There are no silent fallbacks: a requested configuration value, feature patch, compiled object, embedded firmware payload, SELinux runtime marker, build output, hash check, or boot-image preservation check that does not match fails the run and remains recorded in the evidence artifact.

## GitHub Actions

Open **Actions → Build kernel experiment → Run workflow**.

The default inputs build the full A32x reference profile. For another experiment, either override the source/ref/defconfig and feature states in the workflow form, or copy `profiles/a32x-full.json` into a new versioned profile.

The workflow produces one complete artifact containing:

- raw `Image`, `Image.gz`, available DTBs/DTBO and modules
- final and baseline kernel configurations
- every patch and post-build verification report
- source and toolchain commit identities
- complete build command log
- artifact manifest and `SHA256SUMS`
- a flashable `boot.img` when an exact base boot image is supplied

## Flashable boot images

For a local build, pass the exact device boot image:

```bash
python3 scripts/kernel_harness.py build \
  --profile profiles/a32x-full.json \
  --work-dir work/a32x-full \
  --artifacts-dir artifacts/a32x-full \
  --base-boot /path/to/boot-current.img \
  --clean
```

For GitHub Actions, supply `base_boot_url` and optionally `base_boot_sha256`. The repository can also use `BASE_BOOT_URL` and `BASE_BOOT_SHA256` repository secrets as defaults.

The Android v2 packer replaces only the kernel payload. It recalculates the Android boot ID and AVB footer placement fields while proving that the ramdisk, second stage, recovery DTBO, DTB, Samsung marker, vbmeta bytes and fixed partition-image size remain unchanged. Existing vbmeta is copied; it is not Samsung-resigned.

## Local build

Required programs are ordinary Linux kernel build dependencies plus Git, curl and Python 3. The GitHub workflow installs the complete package set automatically.

```bash
python3 scripts/kernel_harness.py validate-profile \
  --profile profiles/a32x-full.json

python3 scripts/kernel_harness.py build \
  --profile profiles/a32x-full.json \
  --work-dir work/a32x-full \
  --artifacts-dir artifacts/a32x-full \
  --clean
```

## Create another experiment

1. Copy a profile in `profiles/` and give it a new ID.
2. Point it at the kernel source, ref, defconfig and toolchains.
3. Select the known features or add profile-owned hook commands.
4. Add a required config fragment and record its exact assertion count.
5. Validate it, then select its filename in the Actions workflow.

The workflow and local build both execute `scripts/kernel_harness.py`; there is no separate reduced CI implementation.

See [Profile format](docs/PROFILE_FORMAT.md) and [Artifacts and evidence](docs/ARTIFACTS.md).
