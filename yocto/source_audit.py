#!/usr/bin/env python3
"""
source_audit.py — Collect, verify, and test Yocto image source files.

Usage:
  python3 yocto/source_audit.py <command> -b BUILD -m IMAGE [options]

Commands:
  collect   Collect sources into ./output/sources/
  verify    Cross-check collected sources against DWARF debug info
  test      Check coverage and optionally re-compile
  report    Generate interactive HTML report
  all       Run collect + report in sequence
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

SOURCE_EXTS = {".c", ".h", ".S", ".s", ".cpp", ".cc", ".cxx", ".C"}

KERNEL_IMAGE_GLOBS = ("bzImage*", "zImage*", "Image", "vmlinuz*",
                      "uImage*", "fitImage*", "vmlinux")

_ATTR_RE = re.compile(r"DW_AT_(?:name|comp_dir)\s*:\s+(?:\(indirect [^\)]+\):\s*)?(.+)")

_COMPILER_RE = re.compile(
    r'\b(?:[a-z0-9_]+-(?:poky|oe)-(?:linux-)?(?:gcc|g\+\+)'
    r'|gcc(?:-\d+(?:\.\d+)*)?|g\+\+(?:-\d+(?:\.\d+)*)?|cc|c\+\+)\b'
)
_DEPTH_RE = re.compile(r"make\[(\d+)\]: (Entering|Leaving) directory '(.+)'")
_SOURCE_EXTS = (".c", ".S", ".s", ".cc", ".cpp", ".cxx")

TYPE_LABEL = {
    "userspace":     "Userspace",
    "kernel_image":  "Kernel image",
    "kernel_module": "Kernel module",
    "no_source":     "No compiled source",
}

TYPE_COLOR = {
    "userspace":     "#4f86c6",
    "kernel_image":  "#e07b39",
    "kernel_module": "#6dbf67",
    "no_source":     "#b0b0b0",
}



# ═══════════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class KernelInfo:
    build_dir: Path
    src_dir: Path

    @property
    def modules_order(self) -> Path:
        return self.build_dir / "modules.order"

    def module_objs(self) -> set[Path]:
        owned: set[Path] = set()
        if not self.modules_order.exists():
            return owned
        for line in self.modules_order.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            ko = Path(line)
            mod_file = self.build_dir / ko.parent / (ko.stem + ".mod")
            if mod_file.exists():
                for obj_rel in mod_file.read_text().splitlines():
                    obj_rel = obj_rel.strip()
                    if obj_rel:
                        owned.add(self.build_dir / obj_rel)
        return owned


@dataclass
class PackageInfo:
    installed_name: str
    yocto_pkg: str
    recipe: str
    ver: str
    work_ver: Path | None
    pkg_type: str
    recipe_prefix: str = ""
    kernel: KernelInfo | None = None
    kernel_mod_obj_rels: list[str] = field(default_factory=list)


@dataclass
class CompileCmd:
    cwd:  Path
    cmd:  str
    src:  Path
    obj:  Path | None


# ═══════════════════════════════════════════════════════════════════════════════
# Discovery — auto-detection, pkgdata, manifest, work-dir helpers
# ═══════════════════════════════════════════════════════════════════════════════

def auto_detect_machine(build_dir: Path) -> str:
    pkgdata = build_dir / "tmp" / "pkgdata"
    if not pkgdata.exists():
        raise SystemExit(f"pkgdata not found: {pkgdata}\n"
                         "Make sure --build-dir points to a Yocto build directory.")
    dirs = [d.name for d in pkgdata.iterdir()
            if d.is_dir() and d.name not in ("sdk", "world")]
    if len(dirs) == 1:
        return dirs[0]
    if len(dirs) == 0:
        raise SystemExit(f"No machine directories found in {pkgdata}")
    raise SystemExit(
        f"Multiple machines found in {pkgdata}: {dirs}\n"
        "Use --machine to specify which one."
    )


def find_manifest(build_dir: Path, image_or_path: str) -> Path:
    p = Path(image_or_path)
    if p.exists():
        return p.resolve()
    deploy = build_dir / "tmp" / "deploy" / "images"
    if not deploy.exists():
        raise SystemExit(f"Deploy images dir not found: {deploy}")
    candidates: list[Path] = []
    for machine_dir in deploy.iterdir():
        if not machine_dir.is_dir():
            continue
        for m in machine_dir.glob(f"{image_or_path}*.manifest"):
            candidates.append(m)
    if not candidates:
        raise SystemExit(f"No manifest found for '{image_or_path}' under {deploy}")
    no_ts = [c for c in candidates if not re.search(r"\d{14}", c.name)]
    if no_ts:
        return sorted(no_ts)[0]
    return sorted(candidates)[-1]


def build_pkgname_map(pkgdata_runtime: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not pkgdata_runtime.exists():
        return mapping
    for f in pkgdata_runtime.iterdir():
        if f.suffix == ".packaged" or not f.is_file():
            continue
        try:
            for line in f.read_text(errors="replace").splitlines():
                if line.startswith("PKG_"):
                    key, _, installed_name = line.partition(":")
                    if not installed_name:
                        continue
                    yocto_pkg = key[4:]
                    installed_name = installed_name.strip()
                    if installed_name and installed_name != yocto_pkg:
                        mapping[installed_name] = yocto_pkg
        except OSError:
            pass
    return mapping


def parse_pkgdata_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            k, _, v = line.partition(":")
            k = k.strip()
            if k and " " not in k:
                data[k] = v.strip()
    except OSError:
        pass
    return data


def parse_manifest(manifest_path: Path) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    for line in manifest_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        pkg  = parts[0]
        arch = parts[1] if len(parts) > 1 else ""
        ver  = parts[2] if len(parts) > 2 else ""
        result.append((pkg, arch, ver))
    return result


def find_work_ver_dir(work: Path, recipe: str, ver: str) -> Path | None:
    candidates = [
        d for d in work.glob(f"*/{recipe}/{ver}")
        if d.parent.parent.parent == work and d.is_dir()
    ]
    if not candidates:
        return None
    for c in candidates:
        if (c / "debugsources.list").exists():
            return c
    for c in candidates:
        if (c / "packages-split").exists():
            return c
    return candidates[0]


def find_kernel_build_dir(work_ver: Path) -> Path | None:
    for d in work_ver.iterdir():
        if d.is_dir() and d.name.startswith("linux-") and d.name.endswith("-build"):
            return d
    return None


def find_kernel_src_dir(build_dir: Path, machine: str) -> Path | None:
    p = build_dir / "tmp" / "work-shared" / machine / "kernel-source"
    return p if p.exists() else None


# ── ELF helpers ──────────────────────────────────────────────────────────────

def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def find_installed_elfs(pkg_split_dir: Path) -> list[Path]:
    if not pkg_split_dir.exists():
        return []
    return [
        p for p in pkg_split_dir.rglob("*")
        if p.is_file() and not p.is_symlink() and is_elf(p)
    ]


def find_debug_counterpart(elf: Path, pkg_split_dir: Path) -> Path | None:
    split_root = pkg_split_dir.parent
    rel = elf.relative_to(pkg_split_dir)
    name = elf.name
    canonical = (split_root / (pkg_split_dir.name + "-dbg")
                 / rel.parent / ".debug" / name)
    if canonical.exists():
        return canonical
    for dbg_dir in split_root.iterdir():
        if not (dbg_dir.name.endswith("-dbg") and dbg_dir.is_dir()):
            continue
        for candidate in dbg_dir.rglob(f".debug/{name}"):
            if candidate.is_file():
                return candidate
    return None


# ── DWARF source path extraction ────────────────────────────────────────────

def extract_dwarf_cu_sources(elf_path: Path, timeout: int = 180) -> set[str]:
    try:
        r = subprocess.run(
            ["readelf", "--debug-dump=info", str(elf_path)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()

    sources: set[str] = set()
    cu_name: str | None = None
    cu_comp_dir: str | None = None
    in_cu = False

    def _commit():
        nonlocal cu_name, cu_comp_dir
        if cu_name and cu_comp_dir:
            if cu_name.startswith("/"):
                sources.add(os.path.normpath(cu_name))
            else:
                sources.add(os.path.normpath(
                    cu_comp_dir.rstrip("/") + "/" + cu_name))
        cu_name = cu_comp_dir = None

    for line in r.stdout.splitlines():
        if "DW_TAG_compile_unit" in line:
            _commit()
            in_cu = True
        elif not in_cu:
            continue
        elif "DW_AT_name" in line and cu_name is None:
            m = _ATTR_RE.search(line)
            if m:
                val = m.group(1).strip().rstrip(")")
                if val.endswith((".c", ".h", ".S", ".s", ".cpp", ".cc", ".cxx", ".C")):
                    cu_name = val
        elif "DW_AT_comp_dir" in line and cu_comp_dir is None:
            m = _ATTR_RE.search(line)
            if m:
                cu_comp_dir = m.group(1).strip().rstrip(")")
        if cu_name and cu_comp_dir:
            _commit()
            in_cu = False

    _commit()
    return sources


# ── Package classification ──────────────────────────────────────────────────

def is_kernel_recipe(recipe: str) -> bool:
    return recipe.startswith("linux-") or recipe == "linux"


def _classify_kernel_pkg(yocto_pkg: str, work_ver: Path) -> tuple[str, list[str]]:
    pkg_split = work_ver / "packages-split" / yocto_pkg
    if not pkg_split.exists():
        return "no_source", []
    for glob in KERNEL_IMAGE_GLOBS:
        if list(pkg_split.rglob(glob)):
            return "kernel_image", []
    ko_files = list(pkg_split.rglob("*.ko"))
    if ko_files:
        return "kernel_module", [str(f.relative_to(pkg_split)) for f in ko_files]
    return "no_source", []


def _get_module_obj_rels(
    pkg_split: Path, kbuild: Path, ko_rels_in_split: list[str]
) -> list[str]:
    obj_rels: list[str] = []
    for ko_rel in ko_rels_in_split:
        ko_name = Path(ko_rel).name
        for ko_in_build in kbuild.rglob(ko_name):
            if ko_in_build.suffix != ".ko":
                continue
            mod_file = ko_in_build.parent / (ko_in_build.stem + ".mod")
            if mod_file.exists():
                for line in mod_file.read_text().splitlines():
                    line = line.strip()
                    if line:
                        obj_rels.append(line)
            break
    return obj_rels


# ── Main discovery entry point ──────────────────────────────────────────────

def discover_packages(
    manifest_path: Path,
    build_dir: Path,
    machine: str,
    verbose: bool = False,
) -> list[PackageInfo]:
    pkgdata_runtime = build_dir / "tmp" / "pkgdata" / machine / "runtime"
    work = build_dir / "tmp" / "work"

    pkgname_map = build_pkgname_map(pkgdata_runtime)
    manifest_pkgs = parse_manifest(manifest_path)

    _work_cache:   dict[tuple[str, str], Path | None] = {}
    _kernel_cache: dict[Path, KernelInfo | None] = {}

    packages: list[PackageInfo] = []

    for installed_pkg, _arch, _ver in manifest_pkgs:
        yocto_pkg = pkgname_map.get(installed_pkg, installed_pkg)

        pkgdata_file = pkgdata_runtime / yocto_pkg
        if not pkgdata_file.exists():
            pkgdata_file = pkgdata_runtime / installed_pkg
        if not pkgdata_file.exists():
            if verbose:
                print(f"  [WARN] no pkgdata for {installed_pkg} (yocto_pkg={yocto_pkg})")
            packages.append(PackageInfo(
                installed_name=installed_pkg, yocto_pkg=yocto_pkg,
                recipe=installed_pkg, ver="unknown",
                work_ver=None, pkg_type="no_source",
            ))
            continue

        data = parse_pkgdata_file(pkgdata_file)
        recipe = data.get("PN", yocto_pkg)
        pv     = data.get("PV", "")
        pr     = data.get("PR", "r0")
        pe     = data.get("PE", "")
        if pv:
            ver = f"{pe}_{pv}-{pr}" if pe else f"{pv}-{pr}"
        else:
            ver = "unknown"

        cache_key = (recipe, ver)
        if cache_key not in _work_cache:
            _work_cache[cache_key] = find_work_ver_dir(work, recipe, ver)
        work_ver = _work_cache[cache_key]

        if work_ver is None:
            if verbose:
                print(f"  [WARN] work dir not found: {recipe}/{ver}")
            packages.append(PackageInfo(
                installed_name=installed_pkg, yocto_pkg=yocto_pkg,
                recipe=recipe, ver=ver,
                work_ver=None, pkg_type="no_source",
            ))
            continue

        recipe_prefix = f"/usr/src/debug/{recipe}/{ver}/"

        if is_kernel_recipe(recipe):
            pkg_type, ko_rels = _classify_kernel_pkg(yocto_pkg, work_ver)

            kernel: KernelInfo | None = None
            mod_obj_rels: list[str] = []

            if pkg_type in ("kernel_image", "kernel_module"):
                if work_ver not in _kernel_cache:
                    kbuild = find_kernel_build_dir(work_ver)
                    ksrc   = find_kernel_src_dir(build_dir, machine)
                    _kernel_cache[work_ver] = (
                        KernelInfo(build_dir=kbuild, src_dir=ksrc)
                        if kbuild and ksrc else None
                    )
                kernel = _kernel_cache[work_ver]

                if pkg_type == "kernel_module" and kernel:
                    pkg_split = work_ver / "packages-split" / yocto_pkg
                    mod_obj_rels = _get_module_obj_rels(
                        pkg_split, kernel.build_dir, ko_rels)

            packages.append(PackageInfo(
                installed_name=installed_pkg, yocto_pkg=yocto_pkg,
                recipe=recipe, ver=ver, work_ver=work_ver,
                pkg_type=pkg_type, recipe_prefix=recipe_prefix,
                kernel=kernel, kernel_mod_obj_rels=mod_obj_rels,
            ))
            continue

        debugsources = work_ver / "debugsources.list"
        compile_log = work_ver / "temp" / "log.do_compile"
        if not debugsources.exists():
            pkg_type = "no_source"
        elif not compile_log.exists():
            pkg_type = "no_source"
        else:
            pkg_split = work_ver / "packages-split" / yocto_pkg
            pkg_type = "userspace" if find_installed_elfs(pkg_split) else "no_source"

        packages.append(PackageInfo(
            installed_name=installed_pkg, yocto_pkg=yocto_pkg,
            recipe=recipe, ver=ver, work_ver=work_ver,
            pkg_type=pkg_type, recipe_prefix=recipe_prefix,
        ))

    # Inject synthetic kernel-image-image if not already present
    has_kernel_image = any(p.pkg_type == "kernel_image" for p in packages)
    if not has_kernel_image:
        ki_pkgdata = pkgdata_runtime / "kernel-image-image"
        if ki_pkgdata.exists():
            data = parse_pkgdata_file(ki_pkgdata)
            ki_recipe = data.get("PN", "linux-raspberrypi")
            pv = data.get("PV", "")
            pr = data.get("PR", "r0")
            pe = data.get("PE", "")
            ki_ver = f"{pe}_{pv}-{pr}" if pe else f"{pv}-{pr}" if pv else "unknown"
            cache_key = (ki_recipe, ki_ver)
            if cache_key not in _work_cache:
                _work_cache[cache_key] = find_work_ver_dir(work, ki_recipe, ki_ver)
            ki_work_ver = _work_cache[cache_key]
            if ki_work_ver:
                if ki_work_ver not in _kernel_cache:
                    kbuild = find_kernel_build_dir(ki_work_ver)
                    ksrc = find_kernel_src_dir(build_dir, machine)
                    _kernel_cache[ki_work_ver] = (
                        KernelInfo(build_dir=kbuild, src_dir=ksrc)
                        if kbuild and ksrc else None
                    )
                ki_kernel = _kernel_cache[ki_work_ver]
                if ki_kernel:
                    ki_prefix = f"/usr/src/debug/{ki_recipe}/{ki_ver}/"
                    packages.append(PackageInfo(
                        installed_name="kernel-image-image",
                        yocto_pkg="kernel-image-image",
                        recipe=ki_recipe, ver=ki_ver,
                        work_ver=ki_work_ver,
                        pkg_type="kernel_image",
                        recipe_prefix=ki_prefix,
                        kernel=ki_kernel,
                    ))
                    if verbose:
                        print(f"  [INFO] Injected synthetic kernel-image-image "
                              f"(recipe={ki_recipe}, ver={ki_ver})")

    return packages


# ── Source file utilities ───────────────────────────────────────────────────

def read_debugsources(path: Path) -> list[str]:
    data = path.read_bytes()
    sep  = b"\x00" if b"\x00" in data else b"\n"
    return [
        p.decode("utf-8", errors="replace").strip()
        for p in data.split(sep) if p.strip()
    ]


def list_collected_files(output_dir: Path, pkg: str) -> set[str]:
    d = output_dir / pkg
    if not d.exists():
        return set()
    return {
        str(p.relative_to(d))
        for p in d.rglob("*")
        if p.is_file() and p.suffix in SOURCE_EXTS
    }


def strip_src_root(rel: str) -> str:
    parts = Path(rel).parts
    return str(Path(*parts[1:])) if len(parts) > 1 else rel


def is_build_dir(dirname: str) -> bool:
    n = dirname.lower()
    if n in ("build", "builds", "_build", ".build"):
        return True
    if n.startswith("build-") or n.endswith("-build"):
        return True
    if re.search(r"^[a-z0-9_]+-(?:poky|oe)-", n):
        return True
    return False


def get_installed_files(pkgdata_runtime: Path, yocto_pkg: str,
                        pkg_split: Path | None = None) -> list[dict]:
    pkgdata_file = pkgdata_runtime / yocto_pkg
    if not pkgdata_file.exists():
        return []
    data = parse_pkgdata_file(pkgdata_file)
    raw = data.get("FILES_INFO", "")
    if not raw:
        return []
    try:
        info = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    result: list[dict] = []
    for fpath, size in info.items():
        elf = False
        if pkg_split:
            on_disk = pkg_split / fpath.lstrip("/")
            if on_disk.exists() and not on_disk.is_symlink():
                elf = is_elf(on_disk)
        result.append({"path": fpath, "size": size, "is_elf": elf})
    return result


# ── Shared argparse helpers ─────────────────────────────────────────────────

def add_common_args(parser) -> None:
    parser.add_argument(
        "-b", "--build-dir",
        metavar="DIR",
        default=os.environ.get("BUILDDIR", ""),
        help="Yocto build directory (default: $BUILDDIR env var)",
    )
    parser.add_argument(
        "-m", "--manifest",
        metavar="IMAGE_OR_PATH",
        required=True,
        help="Rootfs manifest: image name (e.g. core-image-minimal) or path to .manifest file",
    )
    parser.add_argument(
        "--machine",
        metavar="MACHINE",
        default="",
        help="Yocto MACHINE name (default: auto-detect from pkgdata)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show discovery warnings and extra detail",
    )


def resolve_common_args(args) -> tuple[Path, Path, str]:
    if not args.build_dir:
        raise SystemExit(
            "Build directory not specified. Use -b/--build-dir or set $BUILDDIR."
        )
    build_dir = Path(args.build_dir).resolve()
    if not build_dir.is_dir():
        raise SystemExit(f"Build directory not found: {build_dir}")
    machine = args.machine or auto_detect_machine(build_dir)
    manifest = find_manifest(build_dir, args.manifest)
    return build_dir, manifest, machine


# ═══════════════════════════════════════════════════════════════════════════════
# Compile-log parsing, coverage checking, and compile testing
# ═══════════════════════════════════════════════════════════════════════════════

def print_list(label: str, items: list[str], limit: int = 8) -> None:
    print(f"  {label} ({len(items)}):")
    for item in items[:limit]:
        print(f"    {item}")
    if len(items) > limit:
        print(f"    … and {len(items) - limit} more")


def _get_initial_cwd(work_ver: Path) -> Path:
    run_script = work_ver / "temp" / "run.do_compile"
    if run_script.exists():
        for line in run_script.read_text(errors="replace").splitlines():
            m = re.match(r"^cd '(.+)'", line)
            if m:
                p = Path(m.group(1))
                if p.is_dir():
                    return p
    return work_ver


def parse_compile_log(log_file: Path, initial_cwd: Path) -> list[CompileCmd]:
    cmds: list[CompileCmd] = []
    try:
        lines = log_file.read_text(errors="replace").splitlines()
    except OSError:
        return cmds

    cwd_stack: dict[int, Path] = {0: initial_cwd}
    current_depth = 0

    for line in lines:
        m = _DEPTH_RE.search(line)
        if m:
            depth  = int(m.group(1))
            action = m.group(2)
            path   = m.group(3)
            if action == "Entering":
                cwd_stack[depth] = Path(path)
                current_depth = depth
            else:
                cwd_stack.pop(depth, None)
                remaining = [k for k in cwd_stack if k < depth]
                current_depth = max(remaining) if remaining else 0
            continue

        line = re.sub(r'^\[\d+/\d+\]\s+', '', line)

        if " -c " not in line or not _COMPILER_RE.search(line):
            continue
        if "--mode=compile" in line:
            continue
        parts = re.split(r'\S*libtool:\s+compile:\s+', line)
        if len(parts) > 1:
            line = parts[-1]
        line = re.sub(r'\s*\|\|\s*\(.*\)\s*$', '', line)
        line = re.sub(r'\s*&&\s*(true|:)\s*$', '', line)
        line = re.sub(r'(?:\s+[12]?>\s*/dev/null|\s+2>&1)+\s*$', '', line)

        cwd = cwd_stack.get(current_depth, initial_cwd)
        cmd = _parse_one_cmd(line, cwd)
        if cmd:
            cmds.append(cmd)

    return cmds


def _parse_one_cmd(line: str, cwd: Path) -> CompileCmd | None:
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None

    obj_tok: str | None = None
    src_tok: str | None = None

    i = 0
    while i < len(tokens):
        if tokens[i] == "-o" and i + 1 < len(tokens):
            obj_tok = tokens[i + 1]
            i += 2
        else:
            i += 1

    for t in reversed(tokens):
        if t.startswith("-"):
            continue
        if "`" in t:
            continue
        if any(t.endswith(e) for e in _SOURCE_EXTS):
            src_tok = t
            break

    if not src_tok:
        return None

    def _abs(tok: str) -> Path:
        p = Path(tok)
        return p if p.is_absolute() else (cwd / p)

    src = _abs(src_tok).resolve()
    obj = _abs(obj_tok).resolve() if obj_tok else None
    return CompileCmd(cwd=cwd, cmd=line.strip(), src=src, obj=obj)


def check_coverage(pkg, sources_dir: Path) -> dict:
    if not pkg.work_ver:
        return {"status": "NO_WORK_DIR"}
    log_file = pkg.work_ver / "temp" / "log.do_compile"
    if not log_file.exists():
        return {"status": "NO_LOG"}
    initial_cwd = _get_initial_cwd(pkg.work_ver)
    cmds = parse_compile_log(log_file, initial_cwd)
    if not cmds:
        return {"status": "NO_CMDS"}

    pkg_sources = sources_dir / pkg.installed_name
    covered:   list[str] = []
    not_coll:  list[str] = []
    outside:   list[str] = []

    for cmd in cmds:
        try:
            rel = cmd.src.relative_to(pkg.work_ver)
        except ValueError:
            if cmd.src.exists():
                outside.append(str(cmd.src))
            continue
        stripped = strip_src_root(str(rel))
        if (pkg_sources / stripped).exists():
            covered.append(stripped)
        else:
            not_coll.append(stripped)

    total = len(cmds)
    return {
        "status":   "OK" if not not_coll else "INCOMPLETE",
        "total":    total,
        "covered":  len(covered),
        "not_collected": not_coll,
        "outside":  outside,
    }


def _make_shadow_cmd(
    cmd: CompileCmd, collected_src: Path, out_obj: Path,
    work_ver: Path | None = None,
) -> str:
    line = cmd.cmd.strip()

    def _fix_d_value(m):
        val = m.group(2)
        if re.search(r'[<>|&$`*?]', val):
            return m.group(0)
        return f'''-D{m.group(1)}\'"{val}"\''''
    line = re.sub(
        r'-D(\w+=)"([^"]*)"(?=\s|$)',
        _fix_d_value,
        line,
    )

    has_backtick = "`" in line
    if has_backtick:
        line = re.sub(r'`[^`]*`\S*', '', line)

    line = re.sub(r"""-o\s+['"]?\S+['"]?""", f'-o {shlex.quote(str(out_obj))}', line, count=1)

    src_replaced = False
    _ext_alt = '|'.join(re.escape(e) for e in _SOURCE_EXTS)
    src_pat = r"""(^|\s)(?!-)(['"]?)(\S+?(?:""" + _ext_alt + r"""))\2(?=\s|$)"""
    matches = list(re.finditer(src_pat, line))
    if matches:
        m = matches[-1]
        line = line[:m.start(2)] + shlex.quote(str(collected_src)) + line[m.end():]
        src_replaced = True

    if not src_replaced:
        line += ' ' + shlex.quote(str(collected_src))

    if '-o ' not in cmd.cmd:
        line += f' -o {shlex.quote(str(out_obj))}'

    orig_src_dir = cmd.src.parent
    line += f' -iquote{orig_src_dir}'

    if work_ver:
        d = orig_src_dir.parent
        try:
            while d != work_ver and d.is_relative_to(work_ver):
                line += f' -iquote{d}'
                d = d.parent
        except (ValueError, OSError):
            pass

    return line


def _get_build_env(work_ver: Path) -> dict:
    env = os.environ.copy()
    candidates = [work_ver / "temp" / "run.do_compile"]
    temp_dir = work_ver / "temp"
    if temp_dir.is_dir():
        candidates += sorted(temp_dir.glob("run.oe_runmake.*"), reverse=True)
    for run_script in candidates:
        if not run_script.exists():
            continue
        for line in run_script.read_text(errors="replace").splitlines():
            m = re.match(r'^export (\w+)="(.*)"$', line)
            if m and m.group(1) == "PATH":
                env["PATH"] = m.group(2)
                return env
    return env


def compile_test(pkg, sources_dir: Path, work_dir: Path, verbose: bool = False) -> dict:
    if not pkg.work_ver:
        return {"status": "NO_WORK_DIR"}
    log_file = pkg.work_ver / "temp" / "log.do_compile"
    if not log_file.exists():
        return {"status": "NO_LOG"}
    initial_cwd = _get_initial_cwd(pkg.work_ver)
    cmds = parse_compile_log(log_file, initial_cwd)
    if not cmds:
        return {"status": "NO_CMDS"}

    pkg_sources = sources_dir / pkg.installed_name
    results = {
        "status": "OK", "total": 0, "pass": 0, "fail": 0,
        "mismatch": 0, "skip": 0, "failures": [], "mismatches": [],
    }

    build_env = _get_build_env(pkg.work_ver)

    _INCLUDE_EXTS = {".def", ".tbl", ".h"}
    _data_symlinks: list[Path] = []
    try:
        src_roots: list[Path] = []
        for c in cmds:
            try:
                rel = c.src.relative_to(pkg.work_ver)
                root = pkg.work_ver / rel.parts[0]
                if root not in src_roots and root.is_dir():
                    src_roots.append(root)
            except (ValueError, IndexError):
                continue
            if len(src_roots) >= 3:
                break
        for dirpath, _dirs, files in os.walk(pkg_sources):
            if not any(f.endswith((".c", ".h", ".S", ".cc", ".cpp"))
                       for f in files):
                continue
            reldir = Path(dirpath).relative_to(pkg_sources)
            collected_dir = Path(dirpath)
            for src_root in src_roots:
                orig_dir = src_root / reldir
                if not orig_dir.is_dir():
                    continue
                for f in orig_dir.iterdir():
                    if (f.is_file()
                            and f.suffix in _INCLUDE_EXTS
                            and not (collected_dir / f.name).exists()):
                        link = collected_dir / f.name
                        link.symlink_to(f)
                        _data_symlinks.append(link)
    except OSError:
        pass

    with tempfile.TemporaryDirectory(dir=work_dir, prefix=f"test_{pkg.installed_name}_") as tmp:
        tmp_path = Path(tmp)

        for idx, cmd in enumerate(cmds):
            try:
                rel = cmd.src.relative_to(pkg.work_ver)
            except ValueError:
                if cmd.src.exists():
                    results["skip"] += 1
                continue

            collected_src = pkg_sources / strip_src_root(str(rel))
            if not collected_src.exists():
                results["skip"] += 1
                continue

            if not cmd.src.exists():
                results["skip"] += 1
                continue

            results["total"] += 1
            out_obj = tmp_path / f"{idx}.o"
            new_cmd = _make_shadow_cmd(cmd, collected_src, out_obj,
                                      work_ver=pkg.work_ver)

            if verbose:
                short = new_cmd[:140] + ("…" if len(new_cmd) > 140 else "")
                print(f"      [{idx}] {short}")

            try:
                r = subprocess.run(
                    new_cmd, shell=True,
                    capture_output=True, text=True,
                    timeout=120, cwd=str(cmd.cwd),
                    env=build_env,
                )
            except subprocess.TimeoutExpired:
                results["fail"] += 1
                results["failures"].append({"rel": str(rel), "error": "timeout"})
                continue

            if r.returncode != 0:
                results["fail"] += 1
                err = r.stderr.strip().splitlines()
                results["failures"].append({
                    "rel":   str(rel),
                    "error": "\n".join(err[:6]),
                })
                continue

            results["pass"] += 1
            if cmd.obj and cmd.obj.exists() and out_obj.exists():
                def _strip_debug(p: Path) -> bytes:
                    r2 = subprocess.run(
                        ["objcopy", "--strip-debug", str(p), "/dev/stdout"],
                        capture_output=True, timeout=10,
                    )
                    return r2.stdout if r2.returncode == 0 else p.read_bytes()
                orig = _strip_debug(cmd.obj)
                new  = _strip_debug(out_obj)
                if orig != new:
                    results["mismatch"] += 1
                    results["mismatches"].append(str(rel))

    for link in _data_symlinks:
        try:
            link.unlink()
        except OSError:
            pass

    if results["fail"]:
        results["status"] = "FAIL"

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# YoctoSession — shared state for all subcommands
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class YoctoSession:
    build_dir: Path
    manifest_path: Path
    machine: str
    output_dir: Path
    verbose: bool = False
    _packages: list[PackageInfo] | None = field(default=None, repr=False)

    @classmethod
    def from_args(cls, args) -> "YoctoSession":
        if not args.build_dir:
            raise SystemExit(
                "Build directory not specified. Use -b/--build-dir or set $BUILDDIR."
            )
        build_dir = Path(args.build_dir).resolve()
        if not build_dir.is_dir():
            raise SystemExit(f"Build directory not found: {build_dir}")
        machine = args.machine or auto_detect_machine(build_dir)
        manifest_path = find_manifest(build_dir, args.manifest)
        output_dir = Path("./output").resolve()
        return cls(
            build_dir=build_dir,
            manifest_path=manifest_path,
            machine=machine,
            output_dir=output_dir,
            verbose=getattr(args, "verbose", False),
        )

    def discover(self) -> list[PackageInfo]:
        if self._packages is None:
            self._packages = discover_packages(
                self.manifest_path, self.build_dir, self.machine, self.verbose
            )
        return self._packages

    @property
    def sources_dir(self) -> Path:
        return self.output_dir / "sources"

    def print_header(self) -> None:
        print(f"Build dir : {self.build_dir}")
        print(f"Machine   : {self.machine}")
        print(f"Manifest  : {self.manifest_path}")
        print(f"Output    : {self.output_dir}")


# ═══════════════════════════════════════════════════════════════════════════════
# Collector — collect sources per installed package in three categories
# ═══════════════════════════════════════════════════════════════════════════════

def copy_source(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.chmod(0o644)
    shutil.copy2(src, dst)
    return True


def _get_compiled_srcs(work_ver: Path) -> set[Path]:
    log_file = work_ver / "temp" / "log.do_compile"
    if not log_file.exists():
        return set()
    try:
        cwd = _get_initial_cwd(work_ver)
        cmds = parse_compile_log(log_file, cwd)
        return {cmd.src for cmd in cmds}
    except Exception:
        return set()


def _count_files(d: Path) -> int:
    if not d.exists():
        return 0
    return sum(1 for f in d.rglob("*") if f.is_file())


class Collector:
    def __init__(self, session: YoctoSession, clean: bool = False):
        self.session = session
        self.clean = clean
        self.out_dir = session.sources_dir

    def run(self) -> None:
        session = self.session
        session.print_header()

        if self.clean and self.out_dir.exists():
            shutil.rmtree(self.out_dir)
            print("(cleaned output dir)")

        self.out_dir.mkdir(parents=True, exist_ok=True)

        packages = session.discover()
        print(f"\nDiscovered {len(packages)} packages\n")

        kernel_image_done: dict[tuple[str, str], bool] = {}

        for pkg in packages:
            print(f"[{pkg.installed_name}]  type={pkg.pkg_type}  recipe={pkg.recipe}  ver={pkg.ver}")

            if pkg.pkg_type == "no_source":
                self.write_no_source(pkg)
                print("  → (no compiled source)")
                continue

            if pkg.pkg_type == "kernel_image":
                key = (pkg.recipe, pkg.ver)
                if not kernel_image_done.get(key):
                    counts = self.collect_kernel_image(pkg)
                    kernel_image_done[key] = True
                    print(f"  → c={counts['c']}  h={counts['h']}  S={counts['S']}  missing={counts['missing']}")
                else:
                    note_dir = self.out_dir / pkg.installed_name
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
                counts = self.collect_kernel_module(pkg)
                print(f"  → c={counts['c']}  h={counts.get('h', 0)}  S={counts['S']}  missing={counts['missing']}")
                continue

            counts = self.collect_userspace(pkg)
            print(f"  → sources={counts['compiled_used']}  missing={counts['missing']}")

        self.write_manifest(packages)
        pkg_dirs = len([d for d in self.out_dir.iterdir() if d.is_dir()])
        print(f"Done. {pkg_dirs} package directories in {self.out_dir}")

    def collect_userspace(self, pkg_info: PackageInfo) -> dict:
        build_dir = self.session.build_dir
        split_root = pkg_info.work_ver / "packages-split"
        pkg_split  = split_root / pkg_info.yocto_pkg
        prefix     = pkg_info.recipe_prefix

        counts = {"compiled_used": 0, "missing": 0}
        pkg_out = self.out_dir / pkg_info.installed_name

        compiled_srcs: set[Path] = _get_compiled_srcs(pkg_info.work_ver)

        installed_elfs = find_installed_elfs(pkg_split)
        if installed_elfs:
            dwarf_items: list[tuple[Path, str]] = []
            dwarf_abs:   set[Path] = set()

            for elf in installed_elfs:
                dbg = find_debug_counterpart(elf, pkg_split)
                target = dbg if (dbg and dbg.exists()) else elf
                for path in extract_dwarf_cu_sources(target):
                    if path.startswith(prefix):
                        rel = path[len(prefix):]
                        if rel and not rel.startswith("<"):
                            src = pkg_info.work_ver / rel
                            dst = strip_src_root(rel)
                            if src not in dwarf_abs:
                                dwarf_items.append((src, dst))
                                dwarf_abs.add(src)
                    elif build_dir and "/work-shared/" in path:
                        ws_idx = path.find("/work-shared/")
                        ws_rel = path[ws_idx + 1:]
                        src = build_dir / "tmp" / ws_rel
                        after_ws = ws_rel.split("/", 1)[1] if "/" in ws_rel else ""
                        dst = strip_src_root(after_ws) if after_ws else ""
                        if dst and not dst.startswith("<") and src not in dwarf_abs:
                            dwarf_items.append((src, dst))
                            dwarf_abs.add(src)

            if dwarf_items:
                for src, dst_rel in dwarf_items:
                    if copy_source(src, pkg_out / dst_rel):
                        counts["compiled_used"] += 1
                    else:
                        counts["missing"] += 1

                debugsources = pkg_info.work_ver / "debugsources.list"
                if debugsources.exists():
                    for debug_path in read_debugsources(debugsources):
                        src_h = None
                        dst_rel_h = None
                        if debug_path.startswith(prefix):
                            rel = debug_path[len(prefix):]
                            if not rel or rel.startswith("<") or not rel.endswith(".h"):
                                continue
                            src_h = pkg_info.work_ver / rel
                            dst_rel_h = strip_src_root(rel)
                        elif build_dir and "/work-shared/" in debug_path:
                            if not debug_path.endswith(".h"):
                                continue
                            ws_idx = debug_path.find("/work-shared/")
                            ws_rel = debug_path[ws_idx + 1:]
                            src_h = build_dir / "tmp" / ws_rel
                            after_ws = ws_rel.split("/", 1)[1] if "/" in ws_rel else ""
                            dst_rel_h = strip_src_root(after_ws) if after_ws else ""
                        if src_h and dst_rel_h:
                            if copy_source(src_h, pkg_out / dst_rel_h):
                                counts["compiled_used"] += 1

                return counts

            # No DWARF data but compile log has entries — collect from log
            if compiled_srcs:
                for abs_src in compiled_srcs:
                    try:
                        rel = str(abs_src.relative_to(pkg_info.work_ver))
                    except ValueError:
                        continue
                    dst_rel = strip_src_root(rel)
                    if copy_source(abs_src, pkg_out / dst_rel):
                        counts["compiled_used"] += 1

                return counts

        # Fallback: recipe-level debugsources.list
        debugsources = pkg_info.work_ver / "debugsources.list"
        paths = read_debugsources(debugsources)

        for debug_path in paths:
            if not debug_path.startswith(prefix):
                continue
            rel = debug_path[len(prefix):]
            if not rel or rel.startswith("<"):
                continue
            src     = pkg_info.work_ver / rel
            dst_rel = strip_src_root(rel)
            if copy_source(src, pkg_out / dst_rel):
                counts["compiled_used"] += 1
            else:
                counts["missing"] += 1

        return counts

    def collect_kernel_image(self, pkg_info: PackageInfo) -> dict:
        k = pkg_info.kernel
        if k is None:
            return {"c": 0, "S": 0, "h": 0, "missing": 0, "error": "no kernel info"}

        module_objs = k.module_objs()
        pkg_out = self.out_dir / pkg_info.installed_name
        counts = {"c": 0, "S": 0, "h": 0, "missing": 0}

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

        src_prefix = str(k.src_dir)
        collected_h: set[str] = set()
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

        return counts

    def collect_kernel_module(self, pkg_info: PackageInfo) -> dict:
        k = pkg_info.kernel
        if k is None:
            return {"c": 0, "S": 0, "h": 0, "missing": 0, "error": "no kernel info"}

        pkg_out = self.out_dir / pkg_info.installed_name
        counts = {"c": 0, "S": 0, "h": 0, "missing": 0}

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

    def write_no_source(self, pkg_info: PackageInfo) -> None:
        pkg_out = self.out_dir / pkg_info.installed_name
        pkg_out.mkdir(parents=True, exist_ok=True)

    def write_manifest(self, packages: list[PackageInfo]) -> None:
        rows = []
        for p in sorted(packages, key=lambda x: x.installed_name):
            d = self.out_dir / p.installed_name
            cu = _count_files(d)
            rows.append((p.installed_name, p.recipe, p.ver, cu, str(d)))

        manifest = self.out_dir / "MANIFEST.txt"
        header = (f"{'package':<55} {'recipe':<20} {'version':<45}"
                  f" {'source_files':>12}  source_dir\n")
        sep = "-" * 145 + "\n"
        lines = [header, sep]
        for name, rec, ver, cu, sdir in rows:
            lines.append(
                f"{name:<55} {rec:<20} {ver:<45}"
                f" {cu:>12}  {sdir}\n"
            )
        manifest.write_text("".join(lines))
        print(f"\nManifest: {manifest}")


# ═══════════════════════════════════════════════════════════════════════════════
# Verifier — cross-check collected sources against installed rootfs binaries
# ═══════════════════════════════════════════════════════════════════════════════

class Verifier:
    def __init__(self, session: YoctoSession):
        self.session = session
        self.out_dir = session.sources_dir

    def run(self) -> int:
        session = self.session
        session.print_header()
        print(f"Sources   : {self.out_dir}")

        if not self.out_dir.exists():
            raise SystemExit(f"Sources directory not found: {self.out_dir}\n"
                             "Run 'python3 yocto/source_audit.py collect' first.")

        packages = session.discover()
        print(f"\nDiscovered {len(packages)} packages\n")
        print("=" * 72)

        results: dict[str, str] = {}
        kernel_image_verified: dict[tuple[str, str], str] = {}

        for pkg in sorted(packages, key=lambda p: p.installed_name):
            print(f"\n[{pkg.installed_name}]")

            if pkg.pkg_type == "no_source":
                r = self.verify_no_source(pkg)
                print(f"  {'OK' if r['status']=='OK' else 'FAIL'}: package dir "
                      f"{'present' if r['status']=='OK' else 'MISSING'} (empty — no compiled source)")
                results[pkg.installed_name] = r["status"]
                continue

            if pkg.pkg_type == "kernel_image":
                key = (pkg.recipe, pkg.ver)
                if key not in kernel_image_verified:
                    r = self.verify_kernel_image(pkg)
                    kernel_image_verified[key] = pkg.installed_name
                    print("  Method: .o file cross-check (vmlinux has no DWARF)")
                    print(f"  Collected: {r.get('total_collected', 0)}")
                    print(f"  Verified (non-module .o present): {r.get('verified', 0)}")
                    if r.get("missing_o"):
                        print_list("Collected but .o missing", r["missing_o"])
                    if r.get("is_module_src"):
                        print_list("Collected but .o is module-owned", r["is_module_src"])
                    if r.get("uncollected"):
                        print_list("Non-module .o exists but NOT collected", r["uncollected"])
                    if r["status"] == "OK":
                        print("  PERFECT MATCH")
                    results[pkg.installed_name] = r["status"]
                else:
                    primary = kernel_image_verified[key]
                    note = self.out_dir / pkg.installed_name / f"SAME_AS_{primary}.txt"
                    ok = note.exists() or (self.out_dir / pkg.installed_name).exists()
                    print(f"  Shares sources with {primary} — {'OK' if ok else 'FAIL'}")
                    results[pkg.installed_name] = "OK" if ok else "FAIL"
                continue

            if pkg.pkg_type == "kernel_module":
                r = self.verify_kernel_module(pkg)
                print(f"  Expected (from .mod): {r.get('expected', [])}")
                print(f"  Collected:            {r.get('collected', [])}")
                if r.get("missing"): print_list("MISSING", r["missing"])
                if r.get("extra"):   print_list("EXTRA",   r["extra"])
                if r["status"] == "OK": print("  PERFECT MATCH")
                results[pkg.installed_name] = r["status"]
                continue

            r = self.verify_userspace(pkg)
            status = r.get("status", "ERROR")
            results[pkg.installed_name] = status

            if status == "NO_BINARIES":
                print(f"  WARN: no ELFs in packages-split/{pkg.yocto_pkg}/")
            elif status == "NO_DWARF_SOURCES":
                print(f"  WARN: no own-recipe DWARF CUs "
                      f"({r['elfs']} ELF(s), {r['debug_found']} with .debug)")
                print(f"  Collected: {len(list_collected_files(self.out_dir, pkg.installed_name))} files")
            else:
                dbg = r.get("debug_found", 0)
                total = len(r.get("binaries", []))
                print(f"  Binaries: {', '.join(r['binaries'])}  ({dbg}/{total} with .debug)")
                print(f"  DWARF sources (own recipe): {r['dwarf']}")
                print(f"  Collected:                  {r['collected']}")
                if r.get("missing"):
                    print_list("MISSING from sources/", r["missing"])
                if r.get("extra_c"):
                    print_list("EXTRA .c files (not in DWARF)", r["extra_c"])
                if not r.get("missing") and not r.get("extra_c"):
                    print("  PERFECT MATCH  (.h extras are expected — DWARF CU-level only)")

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

        return 0 if not fail_pkgs else 1

    def verify_no_source(self, pkg_info: PackageInfo) -> dict:
        exists = (self.out_dir / pkg_info.installed_name).is_dir()
        return {"status": "OK" if exists else "FAIL",
                "detail": "" if exists else "package directory missing"}

    def verify_userspace(self, pkg_info: PackageInfo) -> dict:
        split_root = pkg_info.work_ver / "packages-split"
        pkg_split  = split_root / pkg_info.yocto_pkg
        prefix     = pkg_info.recipe_prefix

        installed_elfs = find_installed_elfs(pkg_split)
        if not installed_elfs:
            return {"status": "NO_BINARIES", "pkg_split": str(pkg_split)}

        dwarf_sources: set[str] = set()
        debug_found = 0

        for elf in installed_elfs:
            dbg = find_debug_counterpart(elf, pkg_split)
            target = dbg if (dbg and dbg.exists()) else elf
            if dbg and dbg.exists():
                debug_found += 1
            for path in extract_dwarf_cu_sources(target):
                if path.startswith(prefix):
                    rel = path[len(prefix):]
                    if rel and not rel.startswith("<"):
                        dwarf_sources.add(strip_src_root(rel))

        if not dwarf_sources:
            return {
                "status": "NO_DWARF_SOURCES",
                "elfs": len(installed_elfs),
                "debug_found": debug_found,
            }

        collected = list_collected_files(self.out_dir, pkg_info.installed_name)
        missing   = dwarf_sources - collected
        extra_c   = {f for f in (collected - dwarf_sources) if f.endswith(".c")}

        return {
            "status":      "OK" if not missing else "MISSING",
            "dwarf":       len(dwarf_sources),
            "collected":   len(collected),
            "missing":     sorted(missing),
            "extra_c":     sorted(extra_c),
            "binaries":    [e.name for e in installed_elfs],
            "debug_found": debug_found,
        }

    def verify_kernel_module(self, pkg_info: PackageInfo) -> dict:
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

        collected = list_collected_files(self.out_dir, pkg_info.installed_name)
        missing = expected  - collected
        extra   = collected - expected

        return {
            "status":    "OK" if not missing and not extra else "MISMATCH",
            "expected":  sorted(expected),
            "collected": sorted(collected),
            "missing":   sorted(missing),
            "extra":     sorted(extra),
        }

    def verify_kernel_image(self, pkg_info: PackageInfo) -> dict:
        k = pkg_info.kernel
        if k is None:
            return {"status": "NO_KERNEL_INFO"}

        src_dir = self.out_dir / pkg_info.installed_name
        if not src_dir.exists():
            return {"status": "NO_SOURCES_DIR", "detail": str(src_dir)}

        module_objs = k.module_objs()

        missing_o:     list[str] = []
        is_module_src: list[str] = []
        uncollected:   list[str] = []
        verified = 0

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


# ═══════════════════════════════════════════════════════════════════════════════
# HTML template for the interactive source report
# ═══════════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Yocto Source Report — {image}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root{{
  --bg:#f5f7fa;--card:#fff;--border:#e0e4ea;
  --text:#1a1d23;--muted:#6b7280;--accent:#4f86c6;
  --rad:10px;--shadow:0 2px 8px rgba(0,0,0,.08);
  --cu:#27ae60;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}}
header{{background:#1a1d23;color:#fff;padding:20px 32px}}
header h1{{font-size:1.4rem;font-weight:600}}
header p{{color:#9ca3af;font-size:.85rem;margin-top:4px}}
.wrap{{max-width:1600px;margin:0 auto;padding:24px 24px 60px}}

/* Legend */
.legend{{display:flex;gap:18px;margin-bottom:18px;flex-wrap:wrap}}
.leg-item{{display:flex;align-items:center;gap:6px;font-size:.82rem;color:var(--muted)}}
.leg-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0}}

/* Cards */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);padding:16px 18px;box-shadow:var(--shadow)}}
.card .val{{font-size:1.8rem;font-weight:700}}
.card .lbl{{color:var(--muted);font-size:.78rem;margin-top:2px}}
.c1 .val{{color:#4f86c6}}.c2 .val{{color:var(--nu)}}.c3 .val{{color:var(--cu)}}
.c4 .val{{color:#e07b39}}.c5 .val{{color:#e74c3c}}

/* Charts */
.charts{{display:grid;grid-template-columns:1fr 260px;gap:18px;margin-bottom:24px}}
@media(max-width:800px){{.charts{{grid-template-columns:1fr}}}}
.cc{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);padding:18px;box-shadow:var(--shadow)}}
.cc h2{{font-size:.85rem;font-weight:600;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}}

/* Table */
.tbl-wrap{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);box-shadow:var(--shadow);overflow:hidden}}
.toolbar{{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap}}
.toolbar h2{{font-size:.85rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;flex:1}}
.toolbar input,.toolbar select{{border:1px solid var(--border);border-radius:6px;padding:5px 9px;font-size:.83rem;outline:none}}
.toolbar input{{width:180px}}
table{{width:100%;border-collapse:collapse;font-size:.83rem}}
th{{background:#f0f2f6;padding:9px 12px;text-align:left;font-weight:600;color:var(--muted);
    font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;
    cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{background:#e5e8ef}}
th.sorted{{color:var(--text)}}
td{{padding:8px 12px;border-top:1px solid var(--border);vertical-align:middle}}
tr.data-row:hover td{{background:#f9fafb;cursor:pointer}}
.badge{{display:inline-block;padding:2px 7px;border-radius:999px;font-size:.72rem;font-weight:500;color:#fff}}
.num{{font-variant-numeric:tabular-nums;text-align:right}}
.muted-text{{color:var(--muted);font-style:italic;font-size:.8rem}}
.zero{{color:#ccc}}

/* Mini bar */
.mini-bar{{display:flex;height:8px;border-radius:4px;overflow:hidden;min-width:80px;background:#e9ecef}}
.mini-bar div{{flex-shrink:0}}

/* Detail panel */
tr.detail-row td{{padding:0;border-top:none}}
.detail-panel{{background:#fafbfc;border-top:2px solid #e0e4ea;padding:16px 20px;display:none}}
.detail-panel.open{{display:block}}
.cat-tabs{{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:14px}}
.cat-tab{{padding:7px 16px;cursor:pointer;font-size:.82rem;font-weight:600;border-bottom:3px solid transparent;margin-bottom:-2px;color:var(--muted)}}
.cat-tab.active{{border-bottom-color:var(--accent);color:var(--text)}}
.cat-tab:hover{{color:var(--text)}}
.cat-pane{{display:none}}.cat-pane.active{{display:block}}
.detail-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}}
.detail-section{{background:#fff;border:1px solid var(--border);border-radius:8px;padding:12px 14px}}
.detail-section h4{{font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:6px}}
.detail-section h4 .cnt{{background:#e9ecef;color:var(--text);border-radius:999px;padding:1px 7px;font-size:.72rem}}
.file-list{{font-family:monospace;font-size:.74rem;max-height:220px;overflow-y:auto;line-height:1.75}}
.cap-note{{color:var(--muted);font-size:.72rem;margin-top:4px;font-style:italic}}
.info-row{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:10px;font-size:.8rem}}
.info-row span{{color:var(--muted)}}.info-row strong{{color:var(--text)}}
.ext-table{{font-size:.78rem;border-collapse:collapse;width:100%;margin-bottom:10px}}
.ext-table td{{padding:2px 6px}}.ext-table td:last-child{{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}}
.ext-tag{{display:inline-block;background:#f0f2f6;border-radius:3px;padding:0px 5px;font-family:monospace;font-size:.73rem}}
.shared-badge{{display:inline-flex;align-items:center;gap:4px;background:#fff3cd;
               border:1px solid #ffc107;border-radius:4px;padding:2px 8px;font-size:.75rem;margin-bottom:8px}}
.type-filter-row{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}}
.type-btn{{border:1px solid var(--border);border-radius:4px;padding:3px 9px;font-size:.75rem;cursor:pointer;background:#fff}}
.type-btn.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
</style>
</head>
<body>

<header>
  <h1>Yocto Source Report</h1>
  <p>Image: <strong>{image}</strong> &nbsp;&middot;&nbsp;
     Machine: <strong>{machine}</strong> &nbsp;&middot;&nbsp;
     Generated: {generated}</p>
</header>

<div class="wrap">

<!-- Summary cards -->
<div class="cards">
  <div class="card c4"><div class="val">{total_pkgs}</div><div class="lbl">Installed packages</div></div>
  <div class="card c3"><div class="val">{total_cu}</div><div class="lbl">Source files</div></div>
  <div class="card" style="border-left:3px solid #2980b9"><div class="val" style="color:#2980b9">{total_installed}</div><div class="lbl">Installed files</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="cc">
    <h2>Source files per package</h2>
    <canvas id="barChart" height="300"></canvas>
  </div>
  <div class="cc">
    <h2>Package types</h2>
    <canvas id="donutChart"></canvas>
  </div>
</div>

<!-- Table -->
<div class="tbl-wrap">
  <div class="toolbar">
    <h2>All packages <span id="filteredCount" style="font-weight:400;color:#9ca3af"></span></h2>
    <input id="search" type="search" placeholder="Filter packages…">
    <select id="typeFilter">
      <option value="">All types</option>
      <option value="Userspace">Userspace</option>
      <option value="Kernel image">Kernel image</option>
      <option value="Kernel module">Kernel module</option>
      <option value="No compiled source">No compiled source</option>
    </select>
  </div>
  <table id="pkgTable">
    <thead><tr>
      <th data-col="name">Package <span class="si">↕</span></th>
      <th data-col="recipe">Recipe <span class="si">↕</span></th>
      <th data-col="type_label">Type <span class="si">↕</span></th>
      <th data-col="cu_total" style="text-align:right">Source Files <span class="si">↕</span></th>
      <th data-col="installed_total" style="text-align:right">Installed <span class="si">↕</span></th>
    </tr></thead>
    <tbody id="tblBody"></tbody>
  </table>
</div>

</div>

<script>
const DATA = {data_json};
const MAX_CU  = Math.max(...DATA.map(d=>d.cu_total), 1);

// ── Charts ───────────────────────────────────────────────────────────────────
const barData = DATA.filter(d=>d.cu_total>0)
                    .sort((a,b)=>b.cu_total-a.cu_total);
new Chart(document.getElementById('barChart'),{{
  type:'bar',
  data:{{
    labels:barData.map(d=>d.name),
    datasets:[
      {{label:'Source Files',data:barData.map(d=>d.cu_total),  backgroundColor:'#27ae60', stack:'s'}},
    ]
  }},
  options:{{
    indexAxis:'y', responsive:true,
    plugins:{{legend:{{position:'top'}},tooltip:{{mode:'index'}}}},
    scales:{{
      x:{{stacked:true,grid:{{color:'#f0f2f6'}}}},
      y:{{stacked:true,ticks:{{font:{{size:10}}}}}}
    }}
  }}
}});

const typeCounts={{}};
DATA.forEach(d=>{{typeCounts[d.type_label]=(typeCounts[d.type_label]||0)+1}});
new Chart(document.getElementById('donutChart'),{{
  type:'doughnut',
  data:{{
    labels:Object.keys(typeCounts),
    datasets:[{{data:Object.values(typeCounts),
      backgroundColor:['#4f86c6','#e07b39','#6dbf67','#b0b0b0'],
      borderWidth:2,borderColor:'#fff'}}]
  }},
  options:{{cutout:'62%',plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}},padding:12}}}}}}}}
}});

// ── Table ────────────────────────────────────────────────────────────────────
let sortCol='cu_total', sortAsc=false, filterText='', filterType='';

function fmt(n){{
  return n===0?'<span class="zero">0</span>':n.toLocaleString();
}}

function miniBar(cu){{
  if(!cu) return '';
  return `<div style="display:flex;align-items:center;gap:6px">
    <div class="mini-bar" style="width:100px">
      <div style="width:100%;background:#27ae60"></div>
    </div>
    <span style="font-size:.72rem;color:#888">${{cu}}</span>
  </div>`;
}}

function extTable(ext){{
  if(!ext||!Object.keys(ext).length) return '<em style="color:#ccc;font-size:.75rem">—</em>';
  return '<table class="ext-table">' +
    Object.entries(ext).slice(0,12).map(([e,c])=>
      `<tr><td><span class="ext-tag">${{e}}</span></td><td>${{c}}</td></tr>`
    ).join('') +
    (Object.keys(ext).length>12?`<tr><td colspan="2" style="color:var(--muted);font-size:.72rem">… +${{Object.keys(ext).length-12}} more types</td></tr>`:'') +
    '</table>';
}}

function fileList(files, color, total){{
  if(!files||!files.length) return '<em style="color:#ccc;font-size:.75rem">none</em>';
  const items = files.map(f=>`<div style="color:${{color}}">${{f}}</div>`).join('');
  const cap = total>files.length
    ? `<div class="cap-note">Showing ${{files.length}} of ${{total}} files</div>`:'';
  return `<div class="file-list">${{items}}</div>${{cap}}`;
}}

function makeTypeFilter(files, panelId){{
  const exts = [...new Set(files.map(f=>{{
    const m=f.match(/\\.([^.]+)$/); return m?'.'+m[1]:'(none)';
  }}))] .sort();
  if(exts.length<=1) return '';
  const btns = exts.map(e=>`<button class="type-btn" data-ext="${{e}}" onclick="toggleTypeFilter(this,'${{panelId}}')">${{e}}</button>`).join('');
  return `<div class="type-filter-row" id="tfr-${{panelId}}">${{btns}}</div>`;
}}

window.toggleTypeFilter=function(btn,panelId){{
  btn.classList.toggle('active');
  const active=[...document.querySelectorAll(`#tfr-${{panelId}} .type-btn.active`)].map(b=>b.dataset.ext);
  const list=document.querySelector(`#fl-${{panelId}}`);
  if(!list) return;
  list.querySelectorAll('div[data-ext]').forEach(el=>{{
    el.style.display = (!active.length||active.includes(el.dataset.ext))?'':'none';
  }});
}};

function fileListFiltered(files, color, total, panelId){{
  if(!files||!files.length) return '<em style="color:#ccc;font-size:.75rem">none</em>';
  const items = files.map(f=>{{
    const m=f.match(/\\.([^.]+)$/); const ext=m?'.'+m[1]:'(none)';
    return `<div style="color:${{color}}" data-ext="${{ext}}">${{f}}</div>`;
  }}).join('');
  const cap = total>files.length
    ? `<div class="cap-note">Showing ${{files.length}} of ${{total}} files</div>`:'';
  return `<div class="file-list" id="fl-${{panelId}}">${{items}}</div>${{cap}}`;
}}

function pane(id, label, color, files, ext, total, active, srcBinMap){{
  const tfr = makeTypeFilter(files, id);
  // If srcBinMap provided, annotate files with their binary
  let fileItems;
  if(srcBinMap && Object.keys(srcBinMap).length){{
    fileItems = files.map(f=>{{
      const m=f.match(/\\.([^.]+)$/); const ext=m?'.'+m[1]:'(none)';
      const bins = srcBinMap[f];
      const annot = bins && bins.length
        ? ` <span style="color:#2980b9;font-size:.68rem;font-weight:500">← ${{bins.join(', ')}}</span>` : '';
      return `<div style="color:${{color}}" data-ext="${{ext}}">${{f}}${{annot}}</div>`;
    }}).join('');
    const cap = total>files.length
      ? `<div class="cap-note">Showing ${{files.length}} of ${{total}} files</div>`:'';
    fileItems = `<div class="file-list" id="fl-${{id}}">${{fileItems}}</div>${{cap}}`;
  }} else {{
    fileItems = fileListFiltered(files, color, total, id);
  }}
  return `<div class="cat-pane${{active?' active':''}}" id="cp-${{id}}">
    <div style="color:var(--muted);font-size:.78rem;margin-bottom:8px">
      <strong style="color:${{color}}">${{total.toLocaleString()}}</strong> files
    </div>
    ${{tfr}}
    <div class="detail-grid">
      <div class="detail-section">
        <h4>File types <span class="cnt">${{Object.keys(ext).length}}</span></h4>
        ${{extTable(ext)}}
      </div>
      <div class="detail-section" style="grid-column:span 2">
        <h4 style="color:${{color}}">${{label}} <span class="cnt">${{total}}</span></h4>
        ${{fileItems}}
      </div>
    </div>
  </div>`;
}}

function fmtSize(bytes){{
  if(bytes<1024) return bytes+' B';
  if(bytes<1024*1024) return (bytes/1024).toFixed(1)+' KB';
  return (bytes/1024/1024).toFixed(1)+' MB';
}}

function installedPane(id, files, total, elfCount, binarySources, active){{
  if(!files||!files.length) return `<div class="cat-pane${{active?' active':''}}" id="cp-${{id}}"><em style="color:#ccc">No installed files</em></div>`;
  const items = files.map(f=>{{
    const elfBadge = f.is_elf ? ' <span class="badge" style="background:#2980b9;font-size:.65rem">ELF</span>' : '';
    const srcs = binarySources[f.path];
    let srcList = '';
    if(srcs && srcs.length){{
      srcList = `<div style="margin-left:18px;color:#27ae60;font-size:.7rem">${{srcs.map(s=>'↳ '+s).join('<br>')}}</div>`;
    }}
    return `<div style="font-family:monospace;font-size:.74rem;line-height:1.75">
      <span style="color:var(--text)">${{f.path}}</span>
      <span style="color:var(--muted);font-size:.68rem;margin-left:6px">${{fmtSize(f.size)}}</span>
      ${{elfBadge}}${{srcList}}</div>`;
  }}).join('');
  const cap = total>files.length
    ? `<div class="cap-note">Showing ${{files.length}} of ${{total}} files</div>`:'';
  const mapped = Object.keys(binarySources).length;
  return `<div class="cat-pane${{active?' active':''}}" id="cp-${{id}}">
    <div style="color:var(--muted);font-size:.78rem;margin-bottom:8px">
      <strong style="color:#2980b9">${{total}}</strong> files · <strong>${{elfCount}}</strong> ELF binaries${{mapped?' · <strong>'+mapped+'</strong> with source mapping':''}}
    </div>
    <div class="detail-section" style="max-height:300px;overflow-y:auto">${{items}}</div>
    ${{cap}}
  </div>`;
}}

function renderDetail(d, idx){{
  if(d.same_as)
    return `<div class="detail-panel open"><em>Sources shared with <strong>${{d.same_as}}</strong>.</em></div>`;

  const shared = d.shared_with&&d.shared_with.length
    ? `<div class="shared-badge">⚠ Shares recipe with: ${{d.shared_with.join(', ')}}</div>`:'';

  const info = `<div class="info-row">
    <span>Recipe: <strong>${{d.recipe}}</strong></span>
    <span>Version: <strong>${{d.version}}</strong></span>
    <span>Type: <strong>${{d.type_label}}</strong></span>
    ${{d.coverage?`<span>Compile log: <strong>${{d.coverage.covered}}/${{d.coverage.compile_total}}</strong> in binary</span>`:''}}
  </div>`;

  const cuPane   = pane(`cu-${{idx}}`,   'Source files',     '#27ae60', d.cu_files,  d.cu_ext,  d.cu_total,  !d.no_src, d.source_binaries);
  const instPane = installedPane(`inst-${{idx}}`, d.installed_files, d.installed_total, d.installed_elf, d.binary_sources||{{}}, d.no_src);

  return `<div class="detail-panel open">
    ${{info}}${{shared}}
    <div class="cat-tabs" data-idx="${{idx}}">
      <div class="cat-tab${{!d.no_src?' active':''}}" data-pane="cp-cu-${{idx}}" onclick="switchTab(this)">
        Source Files <strong style="color:#27ae60">${{d.cu_total}}</strong></div>
      <div class="cat-tab${{d.no_src?' active':''}}" data-pane="cp-inst-${{idx}}" onclick="switchTab(this)">
        Installed Files <strong style="color:#2980b9">${{d.installed_total}}</strong></div>
    </div>
    ${{cuPane}}${{instPane}}
  </div>`;
}}

window.switchTab=function(tabEl){{
  const tabs = tabEl.closest('.cat-tabs');
  const panel = tabs.parentElement;
  tabs.querySelectorAll('.cat-tab').forEach(t=>t.classList.remove('active'));
  panel.querySelectorAll('.cat-pane').forEach(p=>p.classList.remove('active'));
  tabEl.classList.add('active');
  const target = document.getElementById(tabEl.dataset.pane);
  if(target) target.classList.add('active');
}};

function renderTable(){{
  const q=filterText.toLowerCase();
  let rows=DATA.filter(d=>
    (!q||d.name.includes(q)||d.recipe.includes(q))&&
    (!filterType||d.type_label===filterType)
  );
  rows.sort((a,b)=>{{
    let av=a[sortCol],bv=b[sortCol];
    if(typeof av==='string') av=av.toLowerCase(),bv=bv.toLowerCase();
    return sortAsc?(av>bv?1:-1):(av<bv?1:-1);
  }});

  document.getElementById('filteredCount').textContent=
    rows.length<DATA.length?`(${{rows.length}} of ${{DATA.length}})`:'';

  const tbody=document.getElementById('tblBody');
  tbody.innerHTML=rows.map((d,idx)=>{{
    return `<tr class="data-row" data-name="${{d.name}}">
      <td><strong>${{d.name}}</strong></td>
      <td style="color:#555">${{d.recipe}}</td>
      <td><span class="badge" style="background:${{d.color}}">${{d.type_label}}</span></td>
      <td class="num" style="color:#27ae60">${{fmt(d.cu_total)}}</td>
      <td class="num" style="color:#2980b9">${{fmt(d.installed_total)}}</td>
    </tr>
    <tr class="detail-row"><td colspan="5">${{renderDetail(d,idx)}}</td></tr>`;
  }}).join('');

  tbody.querySelectorAll('tr.data-row').forEach(tr=>{{
    tr.addEventListener('click',()=>{{
      const panel=tr.nextElementSibling.querySelector('.detail-panel');
      if(!panel) return;
      const isOpen=panel.classList.contains('open');
      tbody.querySelectorAll('.detail-panel.open').forEach(p=>p.classList.remove('open'));
      if(!isOpen) panel.classList.add('open');
    }});
  }});

  document.querySelectorAll('th[data-col]').forEach(th=>{{
    th.classList.toggle('sorted',th.dataset.col===sortCol);
    const ic=th.querySelector('.si');
    if(ic) ic.textContent=th.dataset.col===sortCol?(sortAsc?'↑':'↓'):'↕';
  }});
}}

document.querySelectorAll('th[data-col]').forEach(th=>{{
  th.addEventListener('click',()=>{{
    sortCol===th.dataset.col?sortAsc=!sortAsc:(sortCol=th.dataset.col,sortAsc=false);
    renderTable();
  }});
}});
document.getElementById('search').addEventListener('input',e=>{{filterText=e.target.value;renderTable()}});
document.getElementById('typeFilter').addEventListener('change',e=>{{filterType=e.target.value;renderTable()}});

renderTable();
</script>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Reporter — generate an interactive HTML report of collected sources
# ═══════════════════════════════════════════════════════════════════════════════

def _list_files_in(d: Path) -> list[dict]:
    if not d.exists():
        return []
    result = []
    for f in d.rglob("*"):
        if not f.is_file():
            continue
        rel = str(f.relative_to(d))
        ext = f.suffix.lower() or "(no ext)"
        result.append({"path": rel, "ext": ext})
    return result


def _ext_counts(files: list[dict]) -> dict[str, int]:
    c = Counter(f["ext"] for f in files)
    return dict(sorted(c.items(), key=lambda x: -x[1]))


def _dwarf_cross_check(installed_files: list[dict], pkg_split: Path,
                        cu_file_set: set[str]) -> dict:
    binary_sources: dict[str, list[str]] = {}
    source_binaries: dict[str, list[str]] = {}

    for f in installed_files:
        if not f["is_elf"]:
            continue
        elf_path = pkg_split / f["path"].lstrip("/")
        if not elf_path.exists():
            continue
        debug = find_debug_counterpart(elf_path, pkg_split)
        if not debug:
            continue
        dwarf_srcs = extract_dwarf_cu_sources(debug)
        matched: list[str] = []
        for dpath in dwarf_srcs:
            dbase = os.path.basename(dpath)
            for cu_path in cu_file_set:
                if os.path.basename(cu_path) == dbase:
                    matched.append(cu_path)
        matched = sorted(set(matched))
        if matched:
            binary_sources[f["path"]] = matched
            for src in matched:
                source_binaries.setdefault(src, []).append(f["path"])

    return {"binary_sources": binary_sources, "source_binaries": source_binaries}


class Reporter:
    def __init__(self, session: YoctoSession):
        self.session = session
        self.out_dir = session.sources_dir
        self.output = session.output_dir / "report.html"

    def run(self) -> None:
        session = self.session

        if not self.out_dir.exists():
            raise SystemExit(f"Sources dir not found: {self.out_dir}\n"
                             "Run 'python3 yocto/source_audit.py collect' first.")

        print(f"Discovering packages…")
        packages = session.discover()

        print(f"Collecting data for {len(packages)} packages…")
        rows = self.collect_data(packages)

        html = self.render_html(rows)
        self.output.write_text(html)

        total_cu  = sum(r["cu_total"]  for r in rows)
        total_installed = sum(r["installed_total"] for r in rows)

        print(f"Report: {self.output}")
        print(f"  Source files      : {total_cu:,}")
        print(f"  Installed files   : {total_installed:,}")

    def collect_data(self, packages: list[PackageInfo]) -> list[dict]:
        build_dir = self.session.build_dir
        machine = self.session.machine
        pkgdata_runtime = build_dir / "tmp" / "pkgdata" / machine / "runtime"

        work_ver_map: dict[str, list[str]] = {}
        for pkg in packages:
            if pkg.work_ver and pkg.pkg_type == "userspace":
                work_ver_map.setdefault(str(pkg.work_ver), []).append(pkg.installed_name)

        rows = []
        for pkg in sorted(packages, key=lambda p: p.installed_name):
            pkg_dir = self.out_dir / pkg.installed_name
            no_src  = pkg.pkg_type == "no_source"
            same_as = next(pkg_dir.glob("SAME_AS_*.txt"), None) if pkg_dir.exists() else None

            cu_files = _list_files_in(pkg_dir)
            cu_ext   = _ext_counts(cu_files)

            coverage: dict | None = None
            if pkg.pkg_type == "userspace":
                cov = check_coverage(pkg, self.out_dir)
                st  = cov.get("status", "")
                if st not in ("NO_WORK_DIR", "NO_LOG", "NO_CMDS"):
                    coverage = {
                        "compile_total": cov["total"],
                        "covered":       cov["covered"],
                        "not_collected": cov.get("not_collected", []),
                    }

            shared_with: list[str] = []
            if pkg.work_ver and pkg.pkg_type == "userspace":
                peers = work_ver_map.get(str(pkg.work_ver), [])
                shared_with = [p for p in peers if p != pkg.installed_name]

            pkg_split = (pkg.work_ver / "packages-split" / pkg.yocto_pkg
                         if pkg.work_ver else None)
            installed_files = get_installed_files(
                pkgdata_runtime, pkg.yocto_pkg,
                pkg_split=pkg_split)

            xcheck: dict = {"binary_sources": {}, "source_binaries": {}}
            elf_count = sum(1 for f in installed_files if f["is_elf"])
            if elf_count and pkg_split and cu_files:
                cu_path_set = {f["path"] for f in cu_files}
                xcheck = _dwarf_cross_check(installed_files, pkg_split, cu_path_set)

            rows.append({
                "name":       pkg.installed_name,
                "recipe":     pkg.recipe,
                "version":    pkg.ver,
                "type":       pkg.pkg_type,
                "type_label": TYPE_LABEL.get(pkg.pkg_type, pkg.pkg_type),
                "color":      TYPE_COLOR.get(pkg.pkg_type, "#888"),
                "cu_total":   len(cu_files),
                "cu_ext":     cu_ext,
                "cu_files":   [f["path"] for f in cu_files[:300]],
                "no_src":     no_src,
                "same_as":    same_as.stem.replace("SAME_AS_", "") if same_as else None,
                "coverage":   coverage,
                "shared_with": shared_with,
                "installed_files": installed_files[:500],
                "installed_total": len(installed_files),
                "installed_elf":   elf_count,
                "binary_sources":  xcheck["binary_sources"],
                "source_binaries": xcheck["source_binaries"],
            })
        return rows

    def render_html(self, rows: list[dict]) -> str:
        total_cu  = sum(r["cu_total"]  for r in rows)
        total_installed = sum(r["installed_total"] for r in rows)

        image = (self.session.manifest_path.stem
                 if self.session.manifest_path
                 else "unknown")

        return HTML_TEMPLATE.format(
            image      = image,
            machine    = self.session.machine,
            generated  = datetime.now().strftime("%Y-%m-%d %H:%M"),
            total_pkgs = len(rows),
            total_cu   = f"{total_cu:,}",
            total_installed = f"{total_installed:,}",
            data_json  = json.dumps(rows, indent=None),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CLI — unified entry point
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="source-audit",
        description="Collect, verify, and test Yocto image source files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect",
        help="Collect sources into ./output/sources/")
    add_common_args(p_collect)
    p_collect.add_argument("--clean", action="store_true",
        help="Remove output directory before collecting")

    p_verify = sub.add_parser("verify",
        help="Cross-check collected sources against DWARF debug info")
    add_common_args(p_verify)

    p_test = sub.add_parser("test",
        help="Check coverage and optionally re-compile")
    add_common_args(p_test)
    p_test.add_argument("--compile", action="store_true",
        help="Re-run compile commands using collected sources and compare .o files")
    p_test.add_argument("-p", "--packages", metavar="PKG[,PKG…]", default="",
        help="Comma-separated list of installed package names to test (default: all)")

    p_report = sub.add_parser("report",
        help="Generate interactive HTML report")
    add_common_args(p_report)

    p_all = sub.add_parser("all",
        help="Run collect + report in sequence")
    add_common_args(p_all)
    p_all.add_argument("--clean", action="store_true",
        help="Remove output directory before collecting")

    return parser


def cmd_collect(args) -> int:
    session = YoctoSession.from_args(args)
    collector = Collector(session, clean=args.clean)
    collector.run()
    return 0


def cmd_verify(args) -> int:
    session = YoctoSession.from_args(args)
    verifier = Verifier(session)
    return verifier.run()


def cmd_test(args) -> int:
    session = YoctoSession.from_args(args)
    session.print_header()

    out_dir = session.sources_dir
    pkg_filter = set(args.packages.split(",")) if args.packages else set()

    if pkg_filter:
        print(f"Filter    : {', '.join(sorted(pkg_filter))}")

    if not out_dir.exists():
        raise SystemExit(f"Sources directory not found: {out_dir}\n"
                         "Run 'python3 yocto/source_audit.py collect' first.")

    packages = session.discover()
    userspace = [p for p in packages
                 if p.pkg_type == "userspace"
                 and (not pkg_filter or p.installed_name in pkg_filter)]
    print(f"\nDiscovered {len(packages)} packages, "
          f"{len(userspace)} userspace (will test)\n")
    print("=" * 72)

    tmp_root = session.build_dir / "tmp" / "test_sources_tmp" if args.compile else None
    if tmp_root:
        tmp_root.mkdir(parents=True, exist_ok=True)

    summary: dict[str, str] = {}

    for pkg in sorted(userspace, key=lambda p: p.installed_name):
        print(f"\n[{pkg.installed_name}]  (recipe={pkg.recipe} ver={pkg.ver})")

        cov = check_coverage(pkg, out_dir)
        status = cov.get("status", "ERROR")

        if status == "NO_WORK_DIR":
            print("  SKIP: work dir not found")
            summary[pkg.installed_name] = "SKIP"
            continue
        if status in ("NO_LOG", "NO_CMDS"):
            pkg_src_dir = out_dir / pkg.installed_name
            has_sources = (pkg_src_dir.exists()
                          and any(pkg_src_dir.iterdir())
                          and any(pkg_src_dir.iterdir()))
            if has_sources:
                label = "no log.do_compile" if status == "NO_LOG" else "no compile commands in log"
                print(f"  OK (sources collected, {label})")
                summary[pkg.installed_name] = "OK"
            else:
                label = "no log.do_compile" if status == "NO_LOG" else "no compile commands found in log"
                print(f"  SKIP: {label}")
                summary[pkg.installed_name] = "SKIP"
            continue

        total   = cov["total"]
        covered = cov["covered"]
        not_coll = cov["not_collected"]
        outside  = cov["outside"]

        print(f"  Compile commands : {total}")
        print(f"  Covered          : {covered}/{total}"
              + (f"  ✓" if covered == total else ""))
        if not_coll:
            print_list("Not collected (in work_ver)", not_coll)
        if outside:
            print_list("Outside work_ver (generated/external)", outside)

        if args.compile:
            print(f"  Running compile test …")
            r = compile_test(pkg, out_dir, tmp_root, verbose=args.verbose)
            ct_status = r.get("status", "ERROR")

            if ct_status in ("NO_WORK_DIR", "NO_LOG", "NO_CMDS"):
                print(f"  Compile test SKIP: {ct_status}")
            else:
                print(f"  Compile test → "
                      f"pass={r['pass']}  fail={r['fail']}  "
                      f"mismatch={r['mismatch']}  skip={r['skip']}")
                if r["failures"]:
                    print_list(
                        "FAIL",
                        [f"{f['rel']}: {f['error'].splitlines()[0]}"
                         for f in r["failures"]],
                    )
                if r["mismatches"]:
                    print_list(
                        ".o differs (expected: debug-prefix-map changes path)",
                        r["mismatches"],
                    )
                if r["pass"] == r["total"] and not r["fail"]:
                    print("  ALL COMPILED OK")

            pkg_status = "FAIL" if ct_status == "FAIL" else "OK"
        else:
            pkg_status = "OK"

        summary[pkg.installed_name] = pkg_status

    if tmp_root and tmp_root.exists():
        shutil.rmtree(tmp_root, ignore_errors=True)

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    ok_pkgs   = [p for p, s in summary.items() if s == "OK"]
    skip_pkgs = [p for p, s in summary.items() if s == "SKIP"]
    warn_pkgs = [p for p, s in summary.items() if s in ("INCOMPLETE", "MISMATCH")]
    fail_pkgs = [p for p, s in summary.items() if s == "FAIL"]

    print(f"  OK       : {len(ok_pkgs)}")
    print(f"  SKIP     : {len(skip_pkgs)}  (no log / no compile cmds)")
    print(f"  INCOMPLETE: {len(warn_pkgs)}  (some compiled sources not in collection)")
    for p in warn_pkgs:
        print(f"    {p}  [{summary[p]}]")
    print(f"  FAIL     : {len(fail_pkgs)}  (compile errors)")
    for p in fail_pkgs:
        print(f"    {p}")

    return 0 if not fail_pkgs else 1


def cmd_report(args) -> int:
    session = YoctoSession.from_args(args)
    reporter = Reporter(session)
    reporter.run()
    return 0


def cmd_all(args) -> int:
    session = YoctoSession.from_args(args)
    print("=== COLLECT ===\n")
    collector = Collector(session, clean=args.clean)
    collector.run()
    print("\n\n=== REPORT ===\n")
    reporter = Reporter(session)
    reporter.run()
    return 0


def main():
    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        "collect": cmd_collect,
        "verify":  cmd_verify,
        "test":    cmd_test,
        "report":  cmd_report,
        "all":     cmd_all,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
