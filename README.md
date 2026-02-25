# yocto-source-collector

Tools for collecting, verifying, and compile-testing the source files that were
actually compiled into a Yocto image's installed binaries.

## Scripts

| Script | Purpose |
|--------|---------|
| `yocto_source_utils.py` | Shared library: package discovery, DWARF extraction, kernel helpers |
| `collect_sources.py` | Collect sources per installed package in three categories |
| `verify_sources.py` | Verify collected sources against installed ELF DWARF info |
| `test_sources.py` | Parse compiler logs and optionally re-compile using collected sources |
| `report.py` | Generate an interactive HTML report of collected sources |

## How it works

### Collection (`collect_sources.py`)

Sources are collected into three categories per package, with source-root
prefixes stripped (e.g. `busybox-1.35.0/archival/...` → `archival/...`):

| Category | Output directory | How identified |
|----------|-----------------|----------------|
| **compiled+used** | `<pkg>/` | DWARF CU paths from installed binaries + headers from `debugsources.list` |
| **compiled+not-used** | `<pkg>/_compiled_not_used/` | In `log.do_compile` but not in DWARF — optional features, static libs, test utils |
| **never-compiled** | `<pkg>/_never_used/` | In the recipe source tree but never compiled (all non-binary file types) |

For **userspace packages**: uses per-binary DWARF extraction for category 1,
parses `log.do_compile` for category 2, and walks the source tree for category 3.
Only files belonging to the package's own recipe are collected (shared-library
sources from other recipes are filtered out).

For the **kernel image**: finds all `.o` files in the kernel build directory that
are not owned by any kernel module, then copies the corresponding `.c`/`.S` from
`kernel-source/`. Also collects headers via Kbuild `.cmd` dependency files.

For **kernel modules**: uses `.mod` files to enumerate the object files, then
collects the corresponding sources from `kernel-source/`.

Packages with no compiled source (scripts, configs, data) get a
`NO_COMPILED_SOURCE.txt` marker.

### Verification (`verify_sources.py`)

Re-reads DWARF CU source paths from the installed `.debug` binaries and checks
that every referenced source file exists in the collected directory.

### Compile test (`test_sources.py`)

Parses `temp/log.do_compile` to extract every `gcc -c` invocation, then:

1. **Coverage check**: reports which compiled sources are (and aren't) in the
   collected directory.
2. **Compile test** (`--compile`): re-runs each compile command with the
   collected source replacing the original and verifies it succeeds.

### Report (`report.py`)

Generates a self-contained interactive HTML report (using Chart.js) showing
per-package source counts across all three categories, with file-type breakdowns,
per-category tabs, and filtering/sorting.

## Usage

```bash
# Source the Yocto build environment first (or pass paths explicitly)

# Collect sources
python3 collect_sources.py -b $BUILDDIR -m core-image-minimal -o ./sources

# Verify collected sources against DWARF
python3 verify_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources

# Check coverage (which compiled sources are collected)
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources

# Re-compile using collected sources and verify success
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources --compile

# Test specific packages only
python3 test_sources.py -b $BUILDDIR -m core-image-minimal -s ./sources \
    --compile -p busybox,dropbear

# Generate interactive HTML report
python3 report.py -b $BUILDDIR -m core-image-minimal -s ./sources -o report.html
```

## Common arguments

| Flag | Description |
|------|-------------|
| `-b / --build` | Yocto build directory (`$BUILDDIR`) |
| `-m / --manifest` | Image name (e.g. `core-image-minimal`) or path to `.manifest` file |
| `-s / --sources` | Collected sources directory (default: `<build-dir>/sources`) |
| `-v / --verbose` | Verbose output |

## Requirements

- Python 3.10+
- `readelf` (from binutils) — for DWARF extraction in `verify_sources.py`
- `objcopy` (from binutils) — for `.o` comparison in `test_sources.py`
- Cross-compiler toolchain must be present (Yocto sysroot in build dir)

## Notes

- `.o` files always differ in the compile test because `-fdebug-prefix-map` and
  `-fmacro-prefix-map` embed the source path in DWARF/macro sections.  This is
  expected and reported separately as "mismatch", not as a failure.
- "INCOMPLETE" status means some compile commands target uninstalled binaries or
  disabled optional features — the uncollected files are correct omissions.
