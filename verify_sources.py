#!/usr/bin/env python3
"""
Verify collected sources against installed rootfs binaries.

For each package, finds the installed ELF binaries in packages-split/,
locates their unstripped .debug counterparts, extracts DWARF compilation-unit
source paths, and cross-checks them against the collected sources directory.

Kernel image: verified via .o file existence (no DWARF in vmlinux).
Kernel modules: verified against .mod file contents.
No-source packages: checks NO_COMPILED_SOURCE.txt is present.

Usage:
  python3 verify_sources.py -b /path/to/build -m core-image-minimal -s ./sources
  python3 verify_sources.py -b $BUILDDIR -m path/to/image.manifest
"""

import argparse
import sys
from pathlib import Path

import yocto_source_utils as yu


# ── Per-type verification functions ──────────────────────────────────────────

def verify_no_source(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    exists = (out_dir / pkg_info.installed_name / "NO_COMPILED_SOURCE.txt").exists()
    return {"status": "OK" if exists else "FAIL",
            "detail": "" if exists else "NO_COMPILED_SOURCE.txt missing"}


def verify_userspace(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """
    Extract DWARF CU source paths from .debug binaries, filter for this
    recipe, and compare against collected files.
    """
    split_root = pkg_info.work_ver / "packages-split"
    pkg_split  = split_root / pkg_info.yocto_pkg
    prefix     = pkg_info.recipe_prefix   # /usr/src/debug/<recipe>/<ver>/

    installed_elfs = yu.find_installed_elfs(pkg_split)
    if not installed_elfs:
        return {"status": "NO_BINARIES", "pkg_split": str(pkg_split)}

    dwarf_sources: set[str] = set()   # relative paths (after prefix)
    debug_found = 0

    for elf in installed_elfs:
        dbg = yu.find_debug_counterpart(elf, pkg_split)
        target = dbg if (dbg and dbg.exists()) else elf
        if dbg and dbg.exists():
            debug_found += 1
        for path in yu.extract_dwarf_cu_sources(target):
            if path.startswith(prefix):
                rel = path[len(prefix):]
                if rel and not rel.startswith("<"):
                    dwarf_sources.add(yu.strip_src_root(rel))

    if not dwarf_sources:
        return {
            "status": "NO_DWARF_SOURCES",
            "elfs": len(installed_elfs),
            "debug_found": debug_found,
        }

    collected = yu.list_collected_files(out_dir, pkg_info.installed_name)
    missing   = dwarf_sources - collected
    extra_c   = {f for f in (collected - dwarf_sources) if f.endswith(".c")}

    return {
        "status":      "OK" if not missing else "MISSING",
        "dwarf":       len(dwarf_sources),
        "collected":   len(collected),
        "missing":     sorted(missing),
        "extra_c":     sorted(extra_c),   # .h extras are expected (DWARF CU-level)
        "binaries":    [e.name for e in installed_elfs],
        "debug_found": debug_found,
    }


def verify_kernel_module(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """Verify kernel module sources against .mod file contents."""
    k = pkg_info.kernel
    if k is None:
        return {"status": "NO_KERNEL_INFO"}

    expected: set[str] = set()
    for obj_rel in pkg_info.kernel_mod_obj_rels:
        rel = Path(obj_rel)
        for ext in (".c", ".S"):
            src = k.src_dir / rel.parent / (rel.stem + ext)
            if src.exists():
                expected.add(str(src.relative_to(k.src_dir)))
                break

    collected = yu.list_collected_files(out_dir, pkg_info.installed_name)
    missing = expected  - collected
    extra   = collected - expected

    return {
        "status":    "OK" if not missing and not extra else "MISMATCH",
        "expected":  sorted(expected),
        "collected": sorted(collected),
        "missing":   sorted(missing),
        "extra":     sorted(extra),
    }


def verify_kernel_image(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """
    Verify kernel-image sources:
      1. Every collected .c/.S must have a non-module .o in the build dir.
      2. Every non-module .o whose source exists in kernel-source must be collected.
    """
    k = pkg_info.kernel
    if k is None:
        return {"status": "NO_KERNEL_INFO"}

    # Use the canonical name (first kernel-image package in sort order) for the dir
    src_dir = out_dir / pkg_info.installed_name
    if not src_dir.exists():
        return {"status": "NO_SOURCES_DIR", "detail": str(src_dir)}

    module_objs = k.module_objs()

    missing_o:     list[str] = []   # collected but no matching .o
    is_module_src: list[str] = []   # collected but .o is module-owned
    uncollected:   list[str] = []   # .o exists, source exists, but not collected
    verified = 0

    # Check 1: every collected file has a non-module .o
    for src_file in src_dir.rglob("*"):
        if not src_file.is_file() or src_file.suffix not in (".c", ".S", ".s"):
            continue
        rel  = src_file.relative_to(src_dir)
        o    = k.build_dir / rel.parent / (rel.stem + ".o")
        if o in module_objs:
            is_module_src.append(str(rel))
        elif o.exists():
            verified += 1
        else:
            missing_o.append(str(rel))

    # Check 2: every non-module .o with an existing source is collected
    for o_file in k.build_dir.rglob("*.o"):
        if o_file in module_objs:
            continue
        if o_file.name.startswith(".") or o_file.name.endswith(".mod.o"):
            continue
        rel = o_file.relative_to(k.build_dir)
        collected_any = any(
            (src_dir / rel.parent / (rel.stem + ext)).exists()
            for ext in (".c", ".S", ".s")
        )
        if not collected_any:
            for ext in (".c", ".S", ".s"):
                ks = k.src_dir / rel.parent / (rel.stem + ext)
                if ks.exists():
                    uncollected.append(str(rel.parent / (rel.stem + ext)))
                    break

    total = verified + len(missing_o) + len(is_module_src)
    ok = not missing_o and not is_module_src and not uncollected
    return {
        "status":          "OK" if ok else "ISSUES",
        "total_collected": total,
        "verified":        verified,
        "missing_o":       missing_o[:20],
        "is_module_src":   is_module_src[:20],
        "uncollected":     uncollected[:20],
    }


# ── Reporting helpers ─────────────────────────────────────────────────────────

def _print_list(label: str, items: list[str], limit: int = 8) -> None:
    print(f"  {label} ({len(items)}):")
    for item in items[:limit]:
        print(f"    {item}")
    if len(items) > limit:
        print(f"    … and {len(items) - limit} more")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify collected Yocto sources against installed rootfs binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].strip() if "Usage:" in __doc__ else "",
    )
    yu.add_common_args(parser)
    parser.add_argument(
        "-s", "--sources",
        metavar="DIR",
        default="",
        help="Directory of collected sources to verify (default: <build-dir>/sources)",
    )
    args = parser.parse_args()

    build_dir, manifest_path, machine = yu.resolve_common_args(args)
    out_dir = Path(args.sources).resolve() if args.sources else build_dir / "sources"

    print(f"Build dir : {build_dir}")
    print(f"Machine   : {machine}")
    print(f"Manifest  : {manifest_path}")
    print(f"Sources   : {out_dir}")

    if not out_dir.exists():
        raise SystemExit(f"Sources directory not found: {out_dir}\n"
                         "Run collect_sources.py first.")

    packages = yu.discover_packages(manifest_path, build_dir, machine, args.verbose)
    print(f"\nDiscovered {len(packages)} packages\n")
    print("=" * 72)

    results: dict[str, str] = {}
    # Track which kernel-image we've already verified (shared sources dir)
    kernel_image_verified: dict[tuple[str, str], str] = {}   # (recipe, ver) -> pkg_name

    for pkg in sorted(packages, key=lambda p: p.installed_name):
        print(f"\n[{pkg.installed_name}]")

        # ── No source ──────────────────────────────────────────────────────
        if pkg.pkg_type == "no_source":
            r = verify_no_source(pkg, out_dir)
            print(f"  {'OK' if r['status']=='OK' else 'FAIL'}: NO_COMPILED_SOURCE.txt "
                  f"{'present' if r['status']=='OK' else 'MISSING'}")
            results[pkg.installed_name] = r["status"]
            continue

        # ── Kernel image ───────────────────────────────────────────────────
        if pkg.pkg_type == "kernel_image":
            key = (pkg.recipe, pkg.ver)
            if key not in kernel_image_verified:
                r = verify_kernel_image(pkg, out_dir)
                kernel_image_verified[key] = pkg.installed_name
                print("  Method: .o file cross-check (vmlinux has no DWARF)")
                print(f"  Collected: {r.get('total_collected', 0)}")
                print(f"  Verified (non-module .o present): {r.get('verified', 0)}")
                if r.get("missing_o"):
                    _print_list("Collected but .o missing", r["missing_o"])
                if r.get("is_module_src"):
                    _print_list("Collected but .o is module-owned", r["is_module_src"])
                if r.get("uncollected"):
                    _print_list("Non-module .o exists but NOT collected", r["uncollected"])
                if r["status"] == "OK":
                    print("  PERFECT MATCH")
                results[pkg.installed_name] = r["status"]
            else:
                primary = kernel_image_verified[key]
                note = out_dir / pkg.installed_name / f"SAME_AS_{primary}.txt"
                ok = note.exists() or (out_dir / pkg.installed_name).exists()
                print(f"  Shares sources with {primary} — {'OK' if ok else 'FAIL'}")
                results[pkg.installed_name] = "OK" if ok else "FAIL"
            continue

        # ── Kernel module ──────────────────────────────────────────────────
        if pkg.pkg_type == "kernel_module":
            r = verify_kernel_module(pkg, out_dir)
            print(f"  Expected (from .mod): {r.get('expected', [])}")
            print(f"  Collected:            {r.get('collected', [])}")
            if r.get("missing"): _print_list("MISSING", r["missing"])
            if r.get("extra"):   _print_list("EXTRA",   r["extra"])
            if r["status"] == "OK": print("  PERFECT MATCH")
            results[pkg.installed_name] = r["status"]
            continue

        # ── Userspace ──────────────────────────────────────────────────────
        r = verify_userspace(pkg, out_dir)
        status = r.get("status", "ERROR")
        results[pkg.installed_name] = status

        if status == "NO_BINARIES":
            print(f"  WARN: no ELFs in packages-split/{pkg.yocto_pkg}/")
        elif status == "NO_DWARF_SOURCES":
            print(f"  WARN: no own-recipe DWARF CUs "
                  f"({r['elfs']} ELF(s), {r['debug_found']} with .debug)")
            print(f"  Collected: {len(yu.list_collected_files(out_dir, pkg.installed_name))} files")
        else:
            dbg = r.get("debug_found", 0)
            total = len(r.get("binaries", []))
            print(f"  Binaries: {', '.join(r['binaries'])}  ({dbg}/{total} with .debug)")
            print(f"  DWARF sources (own recipe): {r['dwarf']}")
            print(f"  Collected:                  {r['collected']}")
            if r.get("missing"):
                _print_list("MISSING from sources/", r["missing"])
            if r.get("extra_c"):
                _print_list("EXTRA .c files (not in DWARF)", r["extra_c"])
            if not r.get("missing") and not r.get("extra_c"):
                print("  PERFECT MATCH  (.h extras are expected — DWARF CU-level only)")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    ok_pkgs   = [p for p, s in results.items() if s == "OK"]
    warn_pkgs = [p for p, s in results.items()
                 if s in ("NO_DWARF_SOURCES", "NO_BINARIES", "MISSING",
                           "ISSUES", "MISMATCH")]
    fail_pkgs = [p for p, s in results.items() if s == "FAIL"]

    print(f"  OK:   {len(ok_pkgs)}")
    print(f"  WARN: {len(warn_pkgs)}")
    for p in warn_pkgs:
        print(f"         {p}  [{results[p]}]")
    print(f"  FAIL: {len(fail_pkgs)}  {fail_pkgs}")

    sys.exit(0 if not fail_pkgs else 1)


if __name__ == "__main__":
    main()
