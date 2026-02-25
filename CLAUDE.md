# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tools for collecting, verifying, and compile-testing the source files that were actually compiled into a Yocto image's installed binaries. All scripts are standalone Python 3.10+ CLI tools that operate on a Yocto build directory.

## Running the Tools

All scripts require a Yocto build directory (`$BUILDDIR`) and an image manifest. Source the Yocto build environment first or pass paths explicitly.

```bash
# Collect sources into ./sources
python3 collect_sources.py -b $BUILDDIR -m core-image-minimal -o ./sources

# Verify collected sources against DWARF debug info
python3 verify_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources

# Check coverage (which compiled sources are collected)
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources

# Re-compile using collected sources and verify success
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources --compile

# Test specific packages only
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources --compile -p busybox,dropbear

# Generate interactive HTML report
python3 report.py -b $BUILDDIR -m core-image-minimal -s ./sources -o report.html
```

There is no test suite, linter, or build system — these are standalone scripts.

## Architecture

**`yocto_source_utils.py`** — Shared library imported by all other scripts as `yu`. Contains:
- `PackageInfo` / `KernelInfo` dataclasses — core data model for discovered packages
- `discover_packages()` — reads rootfs manifest + pkgdata to build the package list
- DWARF extraction (`extract_dwarf_cu_sources`) via `readelf` subprocess
- Common argparse setup (`add_common_args` / `resolve_common_args`)
- Helpers: `strip_src_root()`, `is_build_dir()`, `find_debug_counterpart()`

**`collect_sources.py`** — Collects source files into three categories per package:
- `<pkg>/` — compiled+used (DWARF-confirmed)
- `<pkg>/_compiled_not_used/` — compiled but not in installed binary
- `<pkg>/_never_used/` — in source tree but never compiled

Uses DWARF per-binary collection for userspace; `.o`-based collection for kernel image; `.mod` file enumeration for kernel modules.

**`verify_sources.py`** — Cross-checks collected sources against DWARF CU paths from `.debug` binaries. Different verification strategies per package type (userspace DWARF, kernel `.o` cross-check, module `.mod` files).

**`test_sources.py`** — Parses `log.do_compile` to extract gcc `-c` invocations, tracks CWD via `make[N]: Entering/Leaving` lines. Coverage mode checks file presence; `--compile` mode re-runs each command with the collected source copy. Exports `parse_compile_log`, `check_coverage` (used by `collect_sources.py` and `report.py`).

**`report.py`** — Generates a self-contained HTML report with Chart.js. Imports `check_coverage` from `test_sources.py`.

### Cross-script data flow

`collect_sources.py` and `report.py` both import from `test_sources.py` (`parse_compile_log`, `check_coverage`). Changes to the compile-log parsing or coverage API affect all three scripts.

## Key Patterns

- Package types: `userspace`, `kernel_image`, `kernel_module`, `no_source` — all scripts branch on `pkg.pkg_type`
- Source-root stripping: Yocto unpacks into versioned dirs (e.g. `busybox-1.35.0/`); `strip_src_root()` removes this prefix for stored paths
- Recipe prefix: `/usr/src/debug/{recipe}/{ver}/` — used to filter DWARF paths to same-recipe sources
- External tools required: `readelf` (DWARF), `objcopy` (.o comparison)
- `.o` mismatch in compile tests is expected (due to `-fdebug-prefix-map`) and reported separately from failures

## Compile Test Internals (`test_sources.py --compile`)

The compile test replays original gcc commands with the collected source copy via `_make_shadow_cmd`. Key subtleties:

- **Backtick VPATH expansion**: Some build systems (e.g. util-linux) use `` `test -f 'src.c' || echo '../pkg-ver/'`src.c `` in commands. `shlex.split` breaks these into orphan tokens. `_make_shadow_cmd` strips the entire backtick span and appends the collected source explicitly.

- **Data-include symlinks**: Collected headers may `#include "file.def"` or `#include "file.tbl"` — non-header files that aren't collected. Before running compile tests, the code symlinks missing `.def`/`.tbl` files from the original tree into the collected directories (and cleans them up after). This avoids `-iquote` manipulation which risks shadowing configured headers.

- **Ancestor `-iquote` paths**: `_make_shadow_cmd` adds `-iquote` for the original source file's parent directory and its ancestors up to `work_ver`, so `#include "..."` from the collected copy resolves headers in the original tree.
