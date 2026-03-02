#!/usr/bin/env python3
"""
Collect sources per installed package in three categories:

  compiled+used        Sources compiled into the installed binary (DWARF-confirmed).
                       Stored directly under <out>/<pkg>/

  compiled+not-used    Sources compiled (in log.do_compile) but not in the installed
                       binary — optional features, static libs, test utilities.
                       Stored under <out>/<pkg>/_compiled_not_used/

  never-compiled       Files that exist in the recipe source tree but were never
                       compiled.  All non-binary file types are collected (scripts,
                       configs, makefiles, docs, headers, …).
                       Stored under <out>/<pkg>/_never_used/

Source-root prefixes (busybox-1.35.0/, git/, etc.) are stripped from all paths.

Usage:
  python3 collect_sources.py -b /path/to/build -m core-image-minimal -o ./sources
  python3 collect_sources.py -b $BUILDDIR -m path/to/image.manifest -o ./out/sources
"""

import argparse
import shutil
from pathlib import Path

import yocto_source_utils as yu


# ── Collection helpers ────────────────────────────────────────────────────────

def copy_source(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.chmod(0o644)
    shutil.copy2(src, dst)
    return True


def _get_compiled_srcs(work_ver: Path) -> set[Path]:
    """Return absolute paths of all files compiled per log.do_compile."""
    log_file = work_ver / "temp" / "log.do_compile"
    if not log_file.exists():
        return set()
    try:
        from test_sources import parse_compile_log, _get_initial_cwd
        cwd = _get_initial_cwd(work_ver)
        cmds = parse_compile_log(log_file, cwd)
        return {cmd.src for cmd in cmds}
    except Exception:
        return set()


# Extensions that are almost certainly binary artifacts (skip during never-used walk)
_BINARY_EXTS = frozenset({
    ".o", ".a", ".so", ".ko", ".lo", ".la", ".lib", ".dll", ".exe",
    ".pyc", ".pyo", ".pyd", ".class", ".beam",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".tiff", ".tif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".gz", ".bz2", ".xz", ".lz4", ".zst", ".lzma", ".tar", ".rar",
    ".mo",    # gettext compiled message catalog
    ".gmo",   # same
})

_COLLECT_CAP = 20_000   # max files per category per package


def _is_collectible(f: Path) -> bool:
    """Return True if f is likely a source or config file (not a binary artifact)."""
    if f.suffix.lower() in _BINARY_EXTS:
        return False
    try:
        return f.stat().st_size < 2_000_000   # skip files >2 MB
    except OSError:
        return False


def _collect_category(
    srcs: list[tuple[Path, str]],   # [(src_path, dst_rel), ...]
    out_dir: Path,
) -> int:
    """Copy (src_path → out_dir/dst_rel) for each pair. Returns file count."""
    count = 0
    for src, dst_rel in srcs:
        if copy_source(src, out_dir / dst_rel):
            count += 1
            if count >= _COLLECT_CAP:
                print(f"    [WARN] cap {_COLLECT_CAP} reached in {out_dir.name}/")
                break
    return count


# ── Userspace collection ──────────────────────────────────────────────────────

def collect_userspace(pkg_info: yu.PackageInfo, out_dir: Path,
                      build_dir: Path | None = None) -> dict:
    """
    Collect sources for a userspace package in three categories:

      compiled+used        → <pkg>/          (DWARF-confirmed, per-binary)
      compiled+not-used    → <pkg>/_compiled_not_used/
      never-compiled       → <pkg>/_never_used/  (all non-binary file types)

    Source-root prefixes (busybox-1.35.0/, git/, …) are stripped.
    Falls back to recipe-level debugsources.list if no ELF binaries found.
    """
    split_root = pkg_info.work_ver / "packages-split"
    pkg_split  = split_root / pkg_info.yocto_pkg
    prefix     = pkg_info.recipe_prefix   # /usr/src/debug/<recipe>/<ver>/

    counts = {
        "compiled_used": 0,
        "compiled_not_used": 0,
        "never_used": 0,
        "missing": 0,
    }
    pkg_out = out_dir / pkg_info.installed_name

    # Gather compile-log paths early (used for both categories 2 and 3)
    compiled_srcs: set[Path] = _get_compiled_srcs(pkg_info.work_ver)

    # ── Try DWARF-based per-binary collection ──────────────────────────────
    installed_elfs = yu.find_installed_elfs(pkg_split)
    if installed_elfs:
        # dwarf_items: list of (abs_source_path, stripped_dst_rel)
        dwarf_items: list[tuple[Path, str]] = []
        dwarf_abs:   set[Path] = set()
        src_roots:   set[str] = set()

        for elf in installed_elfs:
            dbg = yu.find_debug_counterpart(elf, pkg_split)
            target = dbg if (dbg and dbg.exists()) else elf
            for path in yu.extract_dwarf_cu_sources(target):
                if path.startswith(prefix):
                    # Standard recipe-prefix path
                    rel = path[len(prefix):]
                    if rel and not rel.startswith("<"):
                        src = pkg_info.work_ver / rel
                        dst = yu.strip_src_root(rel)
                        if src not in dwarf_abs:
                            dwarf_items.append((src, dst))
                            dwarf_abs.add(src)
                            parts = Path(rel).parts
                            if len(parts) > 1:
                                src_roots.add(parts[0])
                elif build_dir and "/work-shared/" in path:
                    # work-shared path (e.g. gcc-runtime): resolve to
                    # build_dir/tmp/work-shared/... and strip after recipe-ver dir
                    ws_idx = path.find("/work-shared/")
                    ws_rel = path[ws_idx + 1:]  # "work-shared/gcc-9.5.0-r0/..."
                    src = build_dir / "tmp" / ws_rel
                    # Strip "work-shared/" then strip the recipe-ver root
                    after_ws = ws_rel.split("/", 1)[1] if "/" in ws_rel else ""
                    dst = yu.strip_src_root(after_ws) if after_ws else ""
                    if dst and not dst.startswith("<") and src not in dwarf_abs:
                        dwarf_items.append((src, dst))
                        dwarf_abs.add(src)
                        parts = Path(after_ws).parts
                        if len(parts) > 1:
                            src_roots.add(parts[0])

        if dwarf_items:
            # ── Category 1: compiled + used (DWARF) ───────────────────────
            for src, dst_rel in dwarf_items:
                if copy_source(src, pkg_out / dst_rel):
                    counts["compiled_used"] += 1
                else:
                    counts["missing"] += 1

            # Also collect .h files from debugsources.list (DWARF CU only
            # tracks compilation units, not included headers).
            debugsources = pkg_info.work_ver / "debugsources.list"
            if debugsources.exists():
                for debug_path in yu.read_debugsources(debugsources):
                    src_h = None
                    dst_rel_h = None
                    if debug_path.startswith(prefix):
                        rel = debug_path[len(prefix):]
                        if not rel or rel.startswith("<") or not rel.endswith(".h"):
                            continue
                        src_h = pkg_info.work_ver / rel
                        dst_rel_h = yu.strip_src_root(rel)
                    elif build_dir and "/work-shared/" in debug_path:
                        if not debug_path.endswith(".h"):
                            continue
                        ws_idx = debug_path.find("/work-shared/")
                        ws_rel = debug_path[ws_idx + 1:]
                        src_h = build_dir / "tmp" / ws_rel
                        after_ws = ws_rel.split("/", 1)[1] if "/" in ws_rel else ""
                        dst_rel_h = yu.strip_src_root(after_ws) if after_ws else ""
                    if src_h and dst_rel_h:
                        if copy_source(src_h, pkg_out / dst_rel_h):
                            counts["compiled_used"] += 1

            # ── Category 2: compiled + not-used (in log, not in DWARF) ────
            if compiled_srcs:
                cat2: list[tuple[Path, str]] = []
                for abs_src in compiled_srcs:
                    if abs_src in dwarf_abs:
                        continue   # already in category 1
                    try:
                        rel = str(abs_src.relative_to(pkg_info.work_ver))
                    except ValueError:
                        continue
                    cat2.append((abs_src, yu.strip_src_root(rel)))
                counts["compiled_not_used"] = _collect_category(
                    cat2, pkg_out / "_compiled_not_used"
                )

            # ── Category 3: never compiled (in source tree, not in log) ───
            if src_roots:
                cat3: list[tuple[Path, str]] = []
                for root_name in src_roots:
                    if yu.is_build_dir(root_name):
                        continue
                    root_dir = pkg_info.work_ver / root_name
                    if not root_dir.exists():
                        continue
                    for src_file in root_dir.rglob("*"):
                        if not src_file.is_file():
                            continue
                        if src_file in compiled_srcs or src_file in dwarf_abs:
                            continue
                        if not _is_collectible(src_file):
                            continue
                        rel_full = str(src_file.relative_to(pkg_info.work_ver))
                        cat3.append((src_file, yu.strip_src_root(rel_full)))
                counts["never_used"] = _collect_category(
                    cat3, pkg_out / "_never_used"
                )

            return counts

        # ── Fix 2: No DWARF data but compile log has entries ──────────────
        # Packages built without -g (e.g. libcurl4): promote compile-log
        # sources to compiled+used since they are the installed binary's code.
        if compiled_srcs:
            for abs_src in compiled_srcs:
                try:
                    rel = str(abs_src.relative_to(pkg_info.work_ver))
                except ValueError:
                    continue
                dst_rel = yu.strip_src_root(rel)
                if copy_source(abs_src, pkg_out / dst_rel):
                    counts["compiled_used"] += 1
                    parts = Path(rel).parts
                    if len(parts) > 1:
                        src_roots.add(parts[0])

            # Category 3: never compiled (walk source roots)
            if src_roots:
                cat3_nodwarf: list[tuple[Path, str]] = []
                for root_name in src_roots:
                    if yu.is_build_dir(root_name):
                        continue
                    root_dir = pkg_info.work_ver / root_name
                    if not root_dir.exists():
                        continue
                    for src_file in root_dir.rglob("*"):
                        if not src_file.is_file():
                            continue
                        if src_file in compiled_srcs:
                            continue
                        if not _is_collectible(src_file):
                            continue
                        rel_full = str(src_file.relative_to(pkg_info.work_ver))
                        cat3_nodwarf.append((src_file, yu.strip_src_root(rel_full)))
                counts["never_used"] = _collect_category(
                    cat3_nodwarf, pkg_out / "_never_used"
                )

            return counts

    # ── Fallback: recipe-level debugsources.list ───────────────────────────
    debugsources = pkg_info.work_ver / "debugsources.list"
    paths = yu.read_debugsources(debugsources)
    src_roots_fb: set[str] = set()
    fallback_rels: set[str] = set()

    for debug_path in paths:
        if not debug_path.startswith(prefix):
            continue
        rel = debug_path[len(prefix):]
        if not rel or rel.startswith("<"):
            continue
        src     = pkg_info.work_ver / rel
        dst_rel = yu.strip_src_root(rel)
        if copy_source(src, pkg_out / dst_rel):
            counts["compiled_used"] += 1
            fallback_rels.add(rel)
            parts = Path(rel).parts
            if len(parts) > 1:
                src_roots_fb.add(parts[0])
        else:
            counts["missing"] += 1

    # Category 2 for fallback
    if compiled_srcs:
        cat2_fb: list[tuple[Path, str]] = []
        for abs_src in compiled_srcs:
            try:
                rel = str(abs_src.relative_to(pkg_info.work_ver))
            except ValueError:
                continue
            if rel in fallback_rels:
                continue
            cat2_fb.append((abs_src, yu.strip_src_root(rel)))
        counts["compiled_not_used"] = _collect_category(
            cat2_fb, pkg_out / "_compiled_not_used"
        )

    # Category 3 for fallback
    if src_roots_fb:
        dwarf_abs_fb: set[Path] = {pkg_info.work_ver / r for r in fallback_rels}
        cat3_fb: list[tuple[Path, str]] = []
        for root_name in src_roots_fb:
            if yu.is_build_dir(root_name):
                continue
            root_dir = pkg_info.work_ver / root_name
            if not root_dir.exists():
                continue
            for src_file in root_dir.rglob("*"):
                if not src_file.is_file():
                    continue
                if src_file in compiled_srcs or src_file in dwarf_abs_fb:
                    continue
                if not _is_collectible(src_file):
                    continue
                rel_full = str(src_file.relative_to(pkg_info.work_ver))
                cat3_fb.append((src_file, yu.strip_src_root(rel_full)))
        counts["never_used"] = _collect_category(
            cat3_fb, pkg_out / "_never_used"
        )

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
    src_prefix = str(k.src_dir)
    collected_h: set[str] = set()
    # Track compiled stems (relative to src_dir) for Step 3
    compiled_stems: set[str] = set()

    for o_file in k.build_dir.rglob("*.o"):
        if o_file in module_objs:
            continue
        if o_file.name.startswith(".") or o_file.name.endswith(".mod.o"):
            continue
        rel = o_file.relative_to(k.build_dir)
        compiled_stems.add(str(rel.parent / rel.stem))

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

    # ── Step 3: never-compiled source files (.c / .S) ──────────────────
    counts["never_used"] = 0
    never_out = pkg_out / "_never_used"
    for ext in (".c", ".S"):
        for src_file in k.src_dir.rglob(f"*{ext}"):
            if not src_file.is_file():
                continue
            try:
                rel_src = src_file.relative_to(k.src_dir)
            except ValueError:
                continue
            stem = str(rel_src.parent / rel_src.stem)
            if stem in compiled_stems:
                continue   # has matching .o → compiled
            if copy_source(src_file, never_out / rel_src):
                counts["never_used"] += 1

    return counts


def collect_kernel_module(pkg_info: yu.PackageInfo, out_dir: Path) -> dict:
    """Collect sources for a kernel module using its .mod file entries.

    Step 1 — .c / .S: for each .o in the .mod file, copy the matching source.
    Step 2 — .h: parse Kbuild .*.o.cmd files to collect referenced headers.
    """
    k = pkg_info.kernel
    if k is None:
        return {"c": 0, "S": 0, "h": 0, "missing": 0, "error": "no kernel info"}

    pkg_out = out_dir / pkg_info.installed_name
    counts = {"c": 0, "S": 0, "h": 0, "missing": 0}

    # ── Step 1: source files (.c / .S) ────────────────────────────────────
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

    # ── Step 2: headers from Kbuild .cmd dependency files ─────────────────
    src_prefix = str(k.src_dir)
    collected_h: set[str] = set()

    for obj_rel in pkg_info.kernel_mod_obj_rels:
        o_file = k.build_dir / obj_rel
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


def write_no_source(pkg_info: yu.PackageInfo, out_dir: Path) -> None:
    pkg_out = out_dir / pkg_info.installed_name
    pkg_out.mkdir(parents=True, exist_ok=True)
    (pkg_out / "NO_COMPILED_SOURCE.txt").write_text(
        f"Package {pkg_info.installed_name} contains scripts/configs only.\n"
        f"Recipe: {pkg_info.recipe} {pkg_info.ver}\n"
    )


# ── Manifest writer ───────────────────────────────────────────────────────────

def _count_files(d: Path, skip_subdirs: set[str] = frozenset()) -> int:
    if not d.exists():
        return 0
    return sum(
        1 for f in d.rglob("*")
        if f.is_file() and (not skip_subdirs or
           f.relative_to(d).parts[0] not in skip_subdirs)
    )


def write_manifest(packages: list[yu.PackageInfo], out_dir: Path) -> None:
    _SKIP = {"_compiled_not_used", "_never_used"}
    rows = []
    for p in sorted(packages, key=lambda x: x.installed_name):
        d = out_dir / p.installed_name
        cu  = _count_files(d, _SKIP)
        cnu = _count_files(d / "_compiled_not_used")
        nu  = _count_files(d / "_never_used")
        rows.append((p.installed_name, p.recipe, p.ver, cu, cnu, nu, str(d)))

    manifest = out_dir / "MANIFEST.txt"
    header = (f"{'package':<55} {'recipe':<20} {'version':<45}"
              f" {'compiled+used':>13} {'comp+not-used':>13} {'never-used':>10}  source_dir\n")
    sep = "-" * 175 + "\n"
    lines = [header, sep]
    for name, rec, ver, cu, cnu, nu, sdir in rows:
        lines.append(
            f"{name:<55} {rec:<20} {ver:<45}"
            f" {cu:>13} {cnu:>13} {nu:>10}  {sdir}\n"
        )
    manifest.write_text("".join(lines))
    print(f"\nManifest: {manifest}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect sources per installed Yocto package (3 categories).",
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

    kernel_image_done: dict[tuple[str, str], bool] = {}

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
                print(f"  → c={counts['c']}  h={counts['h']}  S={counts['S']}  missing={counts['missing']}  never-used={counts.get('never_used', 0)}")
            else:
                note_dir = out_dir / pkg.installed_name
                note_dir.mkdir(parents=True, exist_ok=True)
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
            print(f"  → c={counts['c']}  h={counts.get('h', 0)}  S={counts['S']}  missing={counts['missing']}")
            continue

        # userspace
        counts = collect_userspace(pkg, out_dir, build_dir)
        print(f"  → compiled+used={counts['compiled_used']}  "
              f"compiled+not-used={counts['compiled_not_used']}  "
              f"never-used={counts['never_used']}  "
              f"missing={counts['missing']}")

    write_manifest(packages, out_dir)
    pkg_dirs = len([d for d in out_dir.iterdir() if d.is_dir()])
    print(f"Done. {pkg_dirs} package directories in {out_dir}")


if __name__ == "__main__":
    main()
