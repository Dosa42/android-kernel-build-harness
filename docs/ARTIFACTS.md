# Artifacts and evidence

Every build attempts to finalize the same evidence tree, including failed builds.

## `kernel/`

- `Image`
- `Image.gz` or `Image.lz4` when produced
- `dtbo.img` when produced
- `dtbs.tar.gz` containing every built DTB
- `modules.tar.gz` containing every built kernel module

## `flashable/`

Present only when a base boot image was supplied and structural repacking passed. For the A32x profile the generated file is:

`a32x-nethunter-full-mt7612u-kernelsu-permissive-boot.img`

## `evidence/`

- `build.log`: exact commands and combined output
- `resolved-profile.json`: profile after workflow/CLI overrides
- `baseline.config` and `resolved.config`
- `config-validation.json`
- `kernelsu-build-evidence.json`
- `mt7612u-backport.json` and `mt7612u-build-evidence.json`
- `selinux-permissive-patch.json` and `selinux-permissive-build-evidence.json`
- `boot-repack-evidence.json` when packaging was requested
- `run-summary.json`: source/toolchain identities, status, error and command records

## Root files

- `SUMMARY.md`: concise human-readable result
- `artifact-manifest.json`: paths, sizes and SHA-256 hashes
- `SHA256SUMS`: checksum file for the entire finalized artifact

Repository/build verification and real-device acceptance are distinct. The evidence reports only operations that were actually executed. A successful build does not claim that the kernel booted on a phone or that attached hardware passed a physical test.
