#!/usr/bin/env python3
"""
Collect compiled source files (.c, .h, .S) per installed package.

Uses Yocto's debugsources.list (DWARF-derived) for userspace packages,
and kernel .mod files for kernel packages — ensuring only sources actually
compiled into installed binaries are collected.

Usage:
  python3 collect_sources.py -b /path/to/build -m core-image-minimal -o ./sources
  python3 collect_sources.py -b $BUILDDIR -m path/to/image.manifest -o ./out/sources
"""

import argparse
import shutil
import sys
from pathlib import Path

import yocto_source_utils as yu


# ── Collection helpers ────────────────────────────────────────────────────────

def copy_source(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def collect_userspace(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """
    Copy sources for a userspace package.

    Uses per-binary DWARF CU extraction (readelf on installed .debug files)
    to identify exactly which source files were compiled into *this* package's
    installed binaries, giving accurate per-package counts even when multiple
    packages share the same recipe (e.g. libc6 vs ldconfig from glibc).

    Falls back to debugsources.list if no ELF binaries with debug info are
    found for this package.
    """
    split_root = pkg_info.work_ver / "packages-split"
    pkg_split  = split_root / pkg_info.yocto_pkg
    prefix     = pkg_info.recipe_prefix   # /usr/src/debug/<recipe>/<ver>/

    counts  = {"c": 0, "h": 0, "S": 0, "missing": 0}
    pkg_out = out_dir / pkg_info.installed_name

    # ── Try DWARF-based per-binary collection ──────────────────────────────
    installed_elfs = yu.find_installed_elfs(pkg_split)
    if installed_elfs:
        dwarf_rels: set[str] = set()
        for elf in installed_elfs:
            dbg = yu.find_debug_counterpart(elf, pkg_split)
            target = dbg if (dbg and dbg.exists()) else elf
            for path in yu.extract_dwarf_cu_sources(target):
                if path.startswith(prefix):
                    rel = path[len(prefix):]
                    if rel and not rel.startswith("<"):
                        dwarf_rels.add(rel)

        if dwarf_rels:
            # Collect .c / .S from DWARF CU list
            for rel in dwarf_rels:
                src = pkg_info.work_ver / rel
                ext = Path(rel).suffix.lstrip(".")
                if copy_source(src, pkg_out / rel):
                    if ext in counts:
                        counts[ext] += 1
                else:
                    counts["missing"] += 1

            # Also collect .h files from debugsources.list (DWARF CU level
            # only tracks compilation units, not included headers).
            debugsources = pkg_info.work_ver / "debugsources.list"
            if debugsources.exists():
                for debug_path in yu.read_debugsources(debugsources):
                    if not debug_path.startswith(prefix):
                        continue
                    rel = debug_path[len(prefix):]
                    if not rel or rel.startswith("<"):
                        continue
                    if not rel.endswith(".h"):
                        continue
                    src = pkg_info.work_ver / rel
                    if copy_source(src, pkg_out / rel):
                        counts["h"] += 1
            return counts

    # ── Fallback: recipe-level debugsources.list ───────────────────────────
    debugsources = pkg_info.work_ver / "debugsources.list"
    paths = yu.read_debugsources(debugsources)
    for debug_path in paths:
        if not debug_path.startswith(prefix):
            continue
        rel = debug_path[len(prefix):]
        if not rel or rel.startswith("<"):
            continue
        src = pkg_info.work_ver / rel
        ext = Path(rel).suffix.lstrip(".")
        if copy_source(src, pkg_out / rel):
            if ext in counts:
                counts[ext] += 1
        else:
            counts["missing"] += 1
    return counts


def collect_kernel_image(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """
    Collect sources for the kernel image (built-in code).

    Step 1 — .c / .S: for every non-module .o in the build dir, copy the
    matching source file from kernel-source/.

    Step 2 — .h: Kbuild writes a .*.o.cmd file alongside each .o that lists
    every header the compiler read (Makefile deps format).  Parse those to
    collect the exact set of headers used, from kernel-source/ only.
    """
    k = pkg_info.kernel
    if k is None:
        return {"c": 0, "S": 0, "h": 0, "missing": 0, "error": "no kernel info"}

    module_objs = k.module_objs()
    pkg_out = out_dir / pkg_info.installed_name
    counts = {"c": 0, "S": 0, "h": 0, "missing": 0}

    # ── Step 1: source files (.c / .S) ────────────────────────────────────
    for o_file in k.build_dir.rglob("*.o"):
        if o_file in module_objs:
            continue
        if o_file.name.startswith(".") or o_file.name.endswith(".mod.o"):
            continue
        rel = o_file.relative_to(k.build_dir)
        for ext in (".c", ".S"):
            src = k.src_dir / rel.parent / (rel.stem + ext)
            if copy_source(src, pkg_out / rel.parent / src.name):
                counts["c" if ext == ".c" else "S"] += 1
                break

    # ── Step 2: headers from Kbuild .cmd dependency files ─────────────────
    # Kbuild writes  build/path/.foo.o.cmd  for each  build/path/foo.o
    # The file contains the compile command on line 1, then the header deps:
    #   deps_path/foo.o := \
    #     /abs/path/header1.h \
    #     /abs/path/header2.h \
    # We collect only headers that live under kernel-source/.
    src_prefix = str(k.src_dir)
    collected_h: set[str] = set()

    for o_file in k.build_dir.rglob("*.o"):
        if o_file in module_objs:
            continue
        if o_file.name.startswith(".") or o_file.name.endswith(".mod.o"):
            continue
        # .cmd file sits beside the .o with a leading dot
        cmd_file = o_file.parent / f".{o_file.name}.cmd"
        if not cmd_file.exists():
            continue
        try:
            text = cmd_file.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            h = line.strip().rstrip("\\").strip()
            if not h.endswith(".h") or not h.startswith(src_prefix):
                continue
            if h in collected_h:
                continue
            h_path = Path(h)
            try:
                rel_h = h_path.relative_to(k.src_dir)
            except ValueError:
                continue
            if copy_source(h_path, pkg_out / rel_h):
                collected_h.add(h)
                counts["h"] += 1

    return counts


def collect_kernel_module(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """Collect sources for a kernel module using its .mod file entries."""
    k = pkg_info.kernel
    if k is None:
        return {"c": 0, "S": 0, "missing": 0, "error": "no kernel info"}

    pkg_out = out_dir / pkg_info.installed_name
    counts = {"c": 0, "S": 0, "missing": 0}

    for obj_rel in pkg_info.kernel_mod_obj_rels:
        rel = Path(obj_rel)
        found = False
        for ext in (".c", ".S"):
            src = k.src_dir / rel.parent / (rel.stem + ext)
            if copy_source(src, pkg_out / rel.parent / src.name):
                counts["c" if ext == ".c" else "S"] += 1
                found = True
                break
        if not found:
            counts["missing"] += 1

    return counts


def write_no_source(pkg_info: yu.PackageInfo, out_dir: Path) -> None:
    pkg_out = out_dir / pkg_info.installed_name
    pkg_out.mkdir(parents=True, exist_ok=True)
    (pkg_out / "NO_COMPILED_SOURCE.txt").write_text(
        f"Package {pkg_info.installed_name} contains scripts/configs only.\n"
        f"Recipe: {pkg_info.recipe} {pkg_info.ver}\n"
    )


# ── Manifest writer ───────────────────────────────────────────────────────────

def write_manifest(packages: list[yu.PackageInfo], out_dir: Path) -> None:
    rows = []
    for p in sorted(packages, key=lambda x: x.installed_name):
        d = out_dir / p.installed_name
        c = sum(1 for f in d.rglob("*.c")) if d.exists() else 0
        h = sum(1 for f in d.rglob("*.h")) if d.exists() else 0
        s = sum(1 for f in d.rglob("*.S")) if d.exists() else 0
        rows.append((p.installed_name, p.recipe, p.ver, c, h, s, str(d)))

    manifest = out_dir / "MANIFEST.txt"
    header = (f"{'package':<55} {'recipe':<20} {'version':<45}"
              f" {'c':>8} {'h':>8} {'S':>8}  source_dir\n")
    sep = "-" * 160 + "\n"
    lines = [header, sep]
    for name, rec, ver, c, h, s, sdir in rows:
        lines.append(f"{name:<55} {rec:<20} {ver:<45} {c:>8} {h:>8} {s:>8}  {sdir}\n")
    manifest.write_text("".join(lines))
    print(f"\nManifest: {manifest}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect compiled sources per installed Yocto package.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].strip() if "Usage:" in __doc__ else "",
    )
    yu.add_common_args(parser)
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        default="",
        help="Output directory for collected sources (default: <build-dir>/sources)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove output directory before collecting",
    )
    args = parser.parse_args()

    build_dir, manifest_path, machine = yu.resolve_common_args(args)

    out_dir = Path(args.output).resolve() if args.output else build_dir / "sources"

    print(f"Build dir : {build_dir}")
    print(f"Machine   : {machine}")
    print(f"Manifest  : {manifest_path}")
    print(f"Output    : {out_dir}")

    if args.clean and out_dir.exists():
        shutil.rmtree(out_dir)
        print("(cleaned output dir)")

    out_dir.mkdir(parents=True, exist_ok=True)

    packages = yu.discover_packages(manifest_path, build_dir, machine, args.verbose)
    print(f"\nDiscovered {len(packages)} packages\n")

    # Track which kernel-image collection has been done (image pkgs share sources)
    kernel_image_done: dict[tuple[str, str], bool] = {}  # (recipe, ver) -> done

    for pkg in packages:
        print(f"[{pkg.installed_name}]  type={pkg.pkg_type}  recipe={pkg.recipe}  ver={pkg.ver}")

        if pkg.pkg_type == "no_source":
            write_no_source(pkg, out_dir)
            print("  → NO_COMPILED_SOURCE.txt")
            continue

        if pkg.pkg_type == "kernel_image":
            key = (pkg.recipe, pkg.ver)
            if not kernel_image_done.get(key):
                counts = collect_kernel_image(pkg, out_dir)
                kernel_image_done[key] = True
                print(f"  → c={counts['c']}  h={counts['h']}  S={counts['S']}  missing={counts['missing']}")
            else:
                # Sibling image package — note it shares sources
                note_dir = out_dir / pkg.installed_name
                note_dir.mkdir(parents=True, exist_ok=True)
                # Find the primary package name for this kernel/ver
                primary = next(
                    (p.installed_name for p in packages
                     if p.pkg_type == "kernel_image"
                     and p.recipe == pkg.recipe and p.ver == pkg.ver
                     and kernel_image_done.get((p.recipe, p.ver))),
                    "kernel-image package"
                )
                (note_dir / f"SAME_AS_{primary}.txt").write_text(
                    f"Sources for {pkg.installed_name} are identical to {primary}.\n"
                    f"See that directory for the full source list.\n"
                )
                print(f"  → shares sources with {primary}")
            continue

        if pkg.pkg_type == "kernel_module":
            counts = collect_kernel_module(pkg, out_dir)
            print(f"  → c={counts['c']}  S={counts['S']}  missing={counts['missing']}")
            continue

        # userspace
        counts = collect_userspace(pkg, out_dir)
        print(f"  → c={counts['c']}  h={counts['h']}  S={counts['S']}  missing={counts['missing']}")

    write_manifest(packages, out_dir)
    pkg_dirs = len([d for d in out_dir.iterdir() if d.is_dir()])
    print(f"Done. {pkg_dirs} package directories in {out_dir}")


if __name__ == "__main__":
    main()
