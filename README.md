# oss-clearance

Collect, verify, and audit the source files compiled into a Yocto image — for OSS clearance and license compliance.

## Prerequisites

- Python 3.10+
- `readelf` and `objcopy` (from binutils)
- Cross-compiler toolchain (present in the Yocto build directory)

**Important:**

- You **must** source the Yocto build environment before running the script:
  ```bash
  source oe-init-build-env <build-dir>
  ```
- **Do not** use `sstate` (shared state cache) when building the image. The script needs the full build artifacts (work directories, compile logs, debug info) which are not preserved by sstate. Build with:
  ```bash
  SSTATE_DIR="" bitbake <image>
  ```
  Or set `SSTATE_MIRRORS = ""` in `local.conf` to ensure a clean build from source.

## Usage

All commands use the unified CLI: `python3 yocto/source_audit.py <command>`.

```bash
# Collect sources + generate HTML report (recommended)
python3 yocto/source_audit.py all -b $BUILDDIR -m core-image-sato --clean

# Collect sources only
python3 yocto/source_audit.py collect -b $BUILDDIR -m core-image-sato --clean

# Verify collected sources against DWARF debug info
python3 yocto/source_audit.py verify -b $BUILDDIR -m core-image-sato

# Check compile-log coverage / re-compile with collected sources
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-sato
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-sato --compile
python3 yocto/source_audit.py test -b $BUILDDIR -m core-image-sato --compile -p busybox,dropbear

# Generate HTML report only (requires prior collect)
python3 yocto/source_audit.py report -b $BUILDDIR -m core-image-sato
```

### Arguments

| Flag | Description |
|------|-------------|
| `-b / --build` | Yocto build directory (`$BUILDDIR`) |
| `-m / --manifest` | Image name (e.g. `core-image-sato`) or path to `.manifest` file |
| `--machine` | Machine name (auto-detected from build dir) |
| `--clean` | Remove existing output before collecting |
| `-v / --verbose` | Verbose output |

### Output

All output goes to `./output/` relative to the current directory:

```
./output/
    sources/           # one directory per installed package
        busybox/       # DWARF-confirmed source files
        glibc/
        ...
    licenses/          # license text files per recipe (deduplicated)
        busybox/       # LICENSE.0, generic_GPLv2, ...
        glibc/         # COPYING, COPYING.LIB, ...
    patches/           # applied patches per recipe (deduplicated)
        busybox/       # *.patch files from work dir
        glibc/
        ...
    report.html        # interactive HTML report
```

Packages with no compiled source (scripts, configs, data) have an empty directory.
License and patch files are collected once per recipe (shared across all sub-packages from the same recipe).

## How it works

### Source collection

For each installed package, collects the source files that were actually compiled into the installed binaries:

- **Userspace packages**: extracts DWARF compilation-unit paths from installed ELF binaries to identify which source files were compiled and used. Headers are collected from `debugsources.list`.
- **Kernel image**: finds all `.o` files in the kernel build directory not owned by any module, then collects the corresponding `.c`/`.S` sources and headers from Kbuild `.cmd` dependency files.
- **Kernel modules**: uses `.mod` files to enumerate object files, then collects the corresponding sources.

### Verification

Re-reads DWARF CU source paths from installed `.debug` binaries and checks that every referenced source file exists in the collected directory.

### Compile test

Parses `temp/log.do_compile` to extract every `gcc -c` invocation, then:
1. **Coverage check**: reports which compiled sources are present in the collected directory.
2. **Compile test** (`--compile`): re-runs each compile command with the collected source copy and verifies it succeeds.

### License and patch collection

During `collect` (and `all`), the tool also gathers:

- **License texts** from `tmp/deploy/licenses/{recipe}/` (excluding the `recipeinfo` metadata file)
- **Patches** (`.patch` and `.diff` files) from the top level of each recipe's work directory

These are deduplicated per recipe — if multiple packages come from the same recipe (e.g. `libglib-2.0-0` and `glib-2.0-utils` both from `glib-2.0`), license and patch files are collected only once.

### Linking analysis

The report includes shared library dependency analysis for each package:

- Runs `readelf -d` on installed ELF binaries to extract `NEEDED` shared libraries
- Resolves each library to its provider package/recipe via Yocto's `shlibs2` database
- Looks up the provider's license and flags copyleft dependencies
- Highlights copyleft linking chains (e.g. a permissively-licensed package linking against a GPL library)

### HTML report

Generates a self-contained interactive HTML report (Chart.js) with:

- **Summary cards**: package count, source files, installed files, copyleft package count, patch count
- **Per-package table**: sortable columns including license (with copyleft badge)
- **6 detail tabs per package**: Source Files, Installed Files, License, Patches, Metadata, Dependencies
- **Dependency tab**: shows NEEDED libraries, provider recipes, licenses, and copyleft warnings

Supports filtering by package name and type.

## Notes

- `.o` files always differ in the compile test because `-fdebug-prefix-map` embeds source paths in DWARF sections. This is expected and reported as "mismatch", not failure.
- "INCOMPLETE" status means some compile commands target uninstalled binaries or disabled features — the uncollected files are correct omissions.
