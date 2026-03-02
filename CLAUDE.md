# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tools for collecting, verifying, and compile-testing the source files that were actually compiled into a Yocto image's installed binaries. A single Python 3.10+ script (`yocto/source_audit.py`) with a unified CLI that operates on a Yocto build directory.

## Running the Tools

All commands require a Yocto build directory (`$BUILDDIR`) and an image manifest. Source the Yocto build environment first or pass paths explicitly.

```bash
# Collect sources into ./output/sources/
python3 yocto/source_audit.py collect -b $BUILDDIR -m core-image-minimal --clean

# Verify collected sources against DWARF debug info
python3 yocto/source_audit.py verify -b $BUILDDIR -m core-image-minimal

# Check coverage (which compiled sources are collected)
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-minimal

# Re-compile using collected sources and verify success
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-minimal --compile

# Test specific packages only
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-minimal --compile -p busybox,dropbear

# Generate interactive HTML report
python3 yocto/source_audit.py report -b $BUILDDIR -m core-image-minimal

# Run collect + report in sequence
python3 yocto/source_audit.py all -b $BUILDDIR -m core-image-minimal --clean
```

Output goes to `./output/` by convention:
```
./output/
    sources/          # collected source files per package
    sources/MANIFEST.txt  # source counts summary
    licenses/         # license text files per recipe (deduplicated)
    patches/          # applied patches per recipe (deduplicated)
    report.html       # interactive HTML report (with license, patch, metadata, and dependency tabs)
```

There is no test suite, linter, or build system.

## Architecture

Single-file script: `yocto/source_audit.py` (~2900 lines)

The script is organized into logical sections:

1. **Constants & Data classes** — `KernelInfo`, `PackageInfo`, `CompileCmd` dataclasses; `SOURCE_EXTS`, `KERNEL_IMAGE_GLOBS`, regex constants; `_COPYLEFT_KEYWORDS`, `is_copyleft()`
2. **Discovery** — `discover_packages()`, pkgdata helpers, manifest parsing, DWARF extraction, ELF helpers, argparse setup
3. **License/patch/metadata helpers** — `get_license_files()`, `get_patch_files()`, `get_pkg_metadata()`, `build_shlibs_map()`, `get_needed_libs()`, `resolve_linking_deps()`
4. **Compile-log parsing** — `parse_compile_log()`, `check_coverage()`, `compile_test()`, `_make_shadow_cmd()`
5. **YoctoSession** — Shared state dataclass with `from_args()`, `discover()`, `sources_dir` property
6. **Collector** — Collects DWARF-confirmed source files, license texts, and patches per package/recipe
7. **Verifier** — Cross-checks collected sources against DWARF CU paths
8. **Reporter** — Generates self-contained HTML report with Chart.js
9. **HTML template** — Inline HTML/CSS/JS template string with 6 detail tabs per package
10. **CLI** — Unified entry point with subcommands: `collect`, `verify`, `test`, `report`, `all`

### Key classes

- **`YoctoSession`** — shared state (build_dir, manifest, machine, output_dir, cached package discovery)
- **`Collector`** — collects DWARF-confirmed source files, license texts (`output/licenses/`), and patches (`output/patches/`) per recipe (deduplicated)
- **`Verifier`** — different verification strategies per package type (userspace DWARF, kernel `.o` cross-check, module `.mod` files)
- **`Reporter`** — generates interactive HTML report with 6 per-package detail tabs: Source Files, Installed Files, License, Patches, Metadata, Dependencies
- **Linking analysis** — `build_shlibs_map()` parses `shlibs2/*.list` to map sonames to provider packages; `resolve_linking_deps()` runs `readelf -d` on installed ELFs and resolves NEEDED libs to provider recipes/licenses, flagging copyleft dependencies

## Key Patterns

- Package types: `userspace`, `kernel_image`, `kernel_module`, `no_source` — all classes branch on `pkg.pkg_type`
- Source-root stripping: Yocto unpacks into versioned dirs (e.g. `busybox-1.35.0/`); `strip_src_root()` removes this prefix for stored paths
- Recipe prefix: `/usr/src/debug/{recipe}/{ver}/` — used to filter DWARF paths to same-recipe sources
- External tools required: `readelf` (DWARF), `objcopy` (.o comparison)
- `.o` mismatch in compile tests is expected (due to `-fdebug-prefix-map`) and reported separately from failures
- **Synthetic kernel-image**: The rootfs manifest lists `kernel-<version>` → `kernel-base` (a meta-package), not the actual `kernel-image-image`. `discover_packages()` injects a synthetic `kernel-image-image` entry from pkgdata when no `kernel_image` type is found.
- **Split-recipe packages**: Recipes like `glibc-locale` package pre-built binaries from `glibc` but have no `log.do_compile`. These are classified as `no_source` since compilation happened in the parent recipe.
- **Kernel module headers**: `Collector.collect_kernel_module()` collects `.h` headers by parsing Kbuild `.*.o.cmd` dependency files, same as `collect_kernel_image()` Step 2.

## Compile Test Internals (`python3 yocto/source_audit.py test --compile`)

The compile test replays original gcc commands with the collected source copy via `_make_shadow_cmd`. Key subtleties:

- **Ninja/meson progress prefix**: Meson/ninja builds prefix compile lines with `[N/M]` (e.g. `[1/88] gcc ...`). `parse_compile_log` strips this prefix before parsing so it doesn't leak into the replayed command.

- **Cross-libtool prefix**: Libtool emits the actual gcc command as `<cross-prefix>libtool: compile:  gcc ...`. The cross-prefixed variant (e.g. `aarch64-poky-linux-libtool: compile:`) is matched by `\S*libtool:\s+compile:\s+` and stripped using `re.split` + take the last element. This handles both single and double libtool prefixes (from line truncation/re-emit in long lines like libgnutls30). The wrapper invocation (`--mode=compile`) is skipped entirely.

- **Shell operators**: Trailing `|| ( ... )` error-handling (bash), `&& true`/`&& :` chaining (nettle), and `>/dev/null 2>&1` redirections (sudo) are all stripped before tokenization.

- **Bare-quoted -D values**: The compile log may show `-DNAME="value"` where the double quotes are C string delimiters that need preserving. `_make_shadow_cmd` wraps such values in single quotes: `-DNAME='"value"'`. However, values containing shell metacharacters (`<>|&$` etc.) are left untouched — the double quotes are shell protection, not C quoting (e.g. `-DCURSESINC="<ncurses.h>"` uses quotes to protect angle brackets from shell redirection). Already-single-quoted values (e.g. `-DPROGRAM='"bash"'`) are left untouched.

- **Quoted source arguments**: Meson/ninja builds may quote source file arguments (e.g. `-c 'xkbcommon@sha/parser.c'`). The source file regex in `_make_shadow_cmd` uses backreference matching to handle both quoted and unquoted source tokens.

- **Generated-then-deleted sources**: Some build systems generate temporary `.c` files, compile them, then delete them (e.g. bash `mkbuiltins` generates `trap.c` from `trap.def`). If the original source no longer exists on disk, the compile test skips it to avoid compiling the wrong file (a different file may share the same stripped name).

- **Backtick VPATH expansion**: Some build systems (e.g. util-linux) use `` `test -f 'src.c' || echo '../pkg-ver/'`src.c `` in commands. `_make_shadow_cmd` strips backtick spans via regex and appends the collected source explicitly.

- **Include symlinks**: Collected source/header files may `#include "file.h"`, `#include "file.def"`, or `#include "file.tbl"` — files that aren't collected. Before running compile tests, the code symlinks missing `.h`/`.def`/`.tbl` files from the original tree into collected directories (and cleans them up after). Both the source tree and build tree are scanned for original files, since out-of-tree builds may reference headers from either location.

- **Ancestor `-iquote` paths**: `_make_shadow_cmd` adds `-iquote` for the original source file's parent directory and its ancestors up to `work_ver`, so `#include "..."` from the collected copy resolves headers in the original tree.

- **PATH fallback for Python do_compile**: Some recipes (e.g. psplash) use a Python `do_compile` function instead of a shell script. `_get_build_env` falls back to `run.oe_runmake.*` files to find the cross-compiler PATH when `run.do_compile` doesn't contain shell exports.
