#!/usr/bin/env python3
"""
Shared discovery utilities for Yocto source collection and verification.

Works with any Yocto version by reading pkgdata, the rootfs manifest,
and tmp/work directory structure.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_EXTS = {".c", ".h", ".S", ".s", ".cpp", ".cc", ".cxx", ".C"}

# File names that indicate a kernel image package
KERNEL_IMAGE_GLOBS = ("bzImage*", "zImage*", "Image", "vmlinuz*",
                      "uImage*", "fitImage*", "vmlinux")

# DWARF attribute parser
_ATTR_RE = re.compile(r"DW_AT_(?:name|comp_dir)\s*:\s+(?:\(indirect [^\)]+\):\s*)?(.+)")


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class KernelInfo:
    build_dir: Path   # linux-*-build/ inside the kernel work dir
    src_dir: Path     # work-shared/<machine>/kernel-source/

    @property
    def modules_order(self) -> Path:
        return self.build_dir / "modules.order"

    def module_objs(self) -> set[Path]:
        """Set of .o paths (absolute) that belong to kernel modules."""
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
    installed_name: str       # name in rootfs manifest (e.g. libc6)
    yocto_pkg: str            # packages-split dir name  (e.g. glibc)
    recipe: str               # PN                       (e.g. glibc)
    ver: str                  # PV-PR                    (e.g. 2.35-r0)
    work_ver: Path | None     # tmp/work/<arch>/<recipe>/<ver>/
    pkg_type: str             # userspace | kernel_image | kernel_module | no_source
    recipe_prefix: str = ""   # /usr/src/debug/{recipe}/{ver}/
    kernel: KernelInfo | None = None
    # For kernel modules: list of .o paths relative to kbuild, from .mod file
    kernel_mod_obj_rels: list[str] = field(default_factory=list)


# ── Auto-detection ────────────────────────────────────────────────────────────

def auto_detect_machine(build_dir: Path) -> str:
    """
    Detect the MACHINE name from tmp/pkgdata/<machine>/ directory.
    Raises SystemExit if ambiguous (use --machine in that case).
    """
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
    """
    Resolve a manifest.  Accepts:
      - an absolute or relative path to an existing .manifest file, OR
      - an image name (e.g. 'core-image-minimal') — searches deploy/images/
    """
    p = Path(image_or_path)
    if p.exists():
        return p.resolve()

    deploy = build_dir / "tmp" / "deploy" / "images"
    if not deploy.exists():
        raise SystemExit(f"Deploy images dir not found: {deploy}")

    # Search all machine subdirs
    candidates: list[Path] = []
    for machine_dir in deploy.iterdir():
        if not machine_dir.is_dir():
            continue
        for m in machine_dir.glob(f"{image_or_path}*.manifest"):
            candidates.append(m)

    if not candidates:
        raise SystemExit(f"No manifest found for '{image_or_path}' under {deploy}")

    # Prefer the non-timestamped symlink/file
    no_ts = [c for c in candidates if not re.search(r"\d{14}", c.name)]
    if no_ts:
        return sorted(no_ts)[0]
    return sorted(candidates)[-1]


# ── pkgdata helpers ───────────────────────────────────────────────────────────

def build_pkgname_map(pkgdata_runtime: Path) -> dict[str, str]:
    """
    Return {installed_pkg_name: yocto_packages_split_dir} by scanning
    PKG:<yocto_pkg>: <installed_name> entries in pkgdata runtime files.
    """
    mapping: dict[str, str] = {}
    if not pkgdata_runtime.exists():
        return mapping
    for f in pkgdata_runtime.iterdir():
        if f.suffix == ".packaged" or not f.is_file():
            continue
        try:
            for line in f.read_text(errors="replace").splitlines():
                if line.startswith("PKG:"):
                    parts = line.split(":", 2)
                    if len(parts) == 3:
                        yocto_pkg      = parts[1].strip()
                        installed_name = parts[2].strip()
                        mapping[installed_name] = yocto_pkg
        except OSError:
            pass
    return mapping


def parse_pkgdata_file(path: Path) -> dict[str, str]:
    """Parse a pkgdata runtime file into {key: value}."""
    data: dict[str, str] = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            k, _, v = line.partition(":")
            k = k.strip()
            if k and " " not in k:      # skip continuation / embedded lines
                data[k] = v.strip()
    except OSError:
        pass
    return data


def parse_manifest(manifest_path: Path) -> list[tuple[str, str, str]]:
    """Return [(pkg, arch, ver), ...] from a rootfs .manifest file."""
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


# ── Work-directory helpers ────────────────────────────────────────────────────

def find_work_ver_dir(work: Path, recipe: str, ver: str) -> Path | None:
    """
    Find tmp/work/<arch>/<recipe>/<ver>/ by glob, filtering to
    immediate children of tmp/work/ (not nested matches).
    Prefers the dir that has debugsources.list, then packages-split.
    """
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
    """Find the linux-*-build directory inside a kernel recipe work dir."""
    for d in work_ver.iterdir():
        if d.is_dir() and d.name.startswith("linux-") and d.name.endswith("-build"):
            return d
    return None


def find_kernel_src_dir(build_dir: Path, machine: str) -> Path | None:
    """Find kernel-source under tmp/work-shared/<machine>/."""
    p = build_dir / "tmp" / "work-shared" / machine / "kernel-source"
    return p if p.exists() else None


# ── ELF helpers ───────────────────────────────────────────────────────────────

def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def find_installed_elfs(pkg_split_dir: Path) -> list[Path]:
    """All non-symlink ELF files under packages-split/{pkg}/."""
    if not pkg_split_dir.exists():
        return []
    return [
        p for p in pkg_split_dir.rglob("*")
        if p.is_file() and not p.is_symlink() and is_elf(p)
    ]


def find_debug_counterpart(elf: Path, pkg_split_dir: Path) -> Path | None:
    """
    Find the unstripped .debug counterpart for an installed ELF.
    Searches all *-dbg dirs in the same packages-split root.
    """
    split_root = pkg_split_dir.parent
    rel = elf.relative_to(pkg_split_dir)
    name = elf.name

    # 1. Canonical location: {pkg}-dbg/same-parent/.debug/{name}
    canonical = (split_root / (pkg_split_dir.name + "-dbg")
                 / rel.parent / ".debug" / name)
    if canonical.exists():
        return canonical

    # 2. Scan all *-dbg dirs for .debug/{name}
    for dbg_dir in split_root.iterdir():
        if not (dbg_dir.name.endswith("-dbg") and dbg_dir.is_dir()):
            continue
        for candidate in dbg_dir.rglob(f".debug/{name}"):
            if candidate.is_file():
                return candidate
    return None


# ── DWARF source path extraction ──────────────────────────────────────────────

def extract_dwarf_cu_sources(elf_path: Path, timeout: int = 180) -> set[str]:
    """
    Extract normalised absolute compilation-unit source paths from DWARF.
    Handles the layout where DW_AT_name precedes DW_AT_comp_dir in each CU.
    """
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


# ── Package classification ────────────────────────────────────────────────────

def is_kernel_recipe(recipe: str) -> bool:
    return recipe.startswith("linux-") or recipe == "linux"


def _classify_kernel_pkg(yocto_pkg: str, work_ver: Path) -> tuple[str, list[str]]:
    """
    Returns (pkg_type, [module .ko paths relative to kbuild]).
    pkg_type is 'kernel_image', 'kernel_module', or 'no_source'.
    """
    pkg_split = work_ver / "packages-split" / yocto_pkg
    if not pkg_split.exists():
        return "no_source", []

    # Kernel image?
    for glob in KERNEL_IMAGE_GLOBS:
        if list(pkg_split.rglob(glob)):
            return "kernel_image", []

    # Kernel modules (.ko)?
    ko_files = list(pkg_split.rglob("*.ko"))
    if ko_files:
        return "kernel_module", [str(f.relative_to(pkg_split)) for f in ko_files]

    return "no_source", []


def _get_module_obj_rels(
    pkg_split: Path, kbuild: Path, ko_rels_in_split: list[str]
) -> list[str]:
    """
    For each .ko installed by this package, read its .mod file in kbuild
    to find the constituent .o file paths (relative to kbuild).
    """
    obj_rels: list[str] = []
    for ko_rel in ko_rels_in_split:
        ko_name = Path(ko_rel).name
        # Locate the same .ko inside kbuild
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


# ── Main discovery entry point ────────────────────────────────────────────────

def discover_packages(
    manifest_path: Path,
    build_dir: Path,
    machine: str,
    verbose: bool = False,
) -> list[PackageInfo]:
    """
    Read the rootfs manifest and resolve each installed package to a
    PackageInfo (work dir, recipe, type, etc.) via pkgdata.
    """
    pkgdata_runtime = build_dir / "tmp" / "pkgdata" / machine / "runtime"
    work = build_dir / "tmp" / "work"

    pkgname_map = build_pkgname_map(pkgdata_runtime)
    manifest_pkgs = parse_manifest(manifest_path)

    # Caches to avoid redundant work
    _work_cache:   dict[tuple[str, str], Path | None] = {}
    _kernel_cache: dict[Path, KernelInfo | None] = {}

    packages: list[PackageInfo] = []

    for installed_pkg, _arch, _ver in manifest_pkgs:
        yocto_pkg = pkgname_map.get(installed_pkg, installed_pkg)

        # ── Resolve pkgdata runtime file ──────────────────────────────────────
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
        ver    = f"{pv}-{pr}" if pv else "unknown"

        # ── Find work dir ─────────────────────────────────────────────────────
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

        # ── Kernel recipe ─────────────────────────────────────────────────────
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

        # ── Userspace recipe ──────────────────────────────────────────────────
        debugsources = work_ver / "debugsources.list"
        if not debugsources.exists():
            pkg_type = "no_source"
        else:
            # Check if this specific sub-package has its own ELF binary.
            # If not (e.g. busybox-hwclock), sources belong to the sibling
            # package that contains the actual binary — mark as no_source.
            pkg_split = work_ver / "packages-split" / yocto_pkg
            pkg_type = "userspace" if find_installed_elfs(pkg_split) else "no_source"

        packages.append(PackageInfo(
            installed_name=installed_pkg, yocto_pkg=yocto_pkg,
            recipe=recipe, ver=ver, work_ver=work_ver,
            pkg_type=pkg_type, recipe_prefix=recipe_prefix,
        ))

    return packages


# ── Source file utilities ─────────────────────────────────────────────────────

def read_debugsources(path: Path) -> list[str]:
    """Parse a null- or newline-terminated debugsources.list file."""
    data = path.read_bytes()
    sep  = b"\x00" if b"\x00" in data else b"\n"
    return [
        p.decode("utf-8", errors="replace").strip()
        for p in data.split(sep) if p.strip()
    ]


_COLLECTION_SUBDIRS = frozenset({"_compiled_not_used", "_never_used"})


def list_collected_files(output_dir: Path, pkg: str) -> set[str]:
    """Relative paths of all source files under output_dir/pkg/ (excludes category subdirs)."""
    d = output_dir / pkg
    if not d.exists():
        return set()
    return {
        str(p.relative_to(d))
        for p in d.rglob("*")
        if p.is_file() and p.suffix in SOURCE_EXTS
        and p.relative_to(d).parts[0] not in _COLLECTION_SUBDIRS
    }


def strip_src_root(rel: str) -> str:
    """Strip the leading source-root component from a work-dir-relative path.

    Yocto unpacks sources into a versioned subdirectory of WORKDIR:
      busybox-1.35.0/archival/...  →  archival/...
      git/socket.c                 →  socket.c
      dropbear-2020.81/svr-auth.c  →  svr-auth.c

    The first path component is an unpack/fetch artifact and adds no
    information when stored in the per-package output directory.
    """
    parts = Path(rel).parts
    return str(Path(*parts[1:])) if len(parts) > 1 else rel


def is_build_dir(dirname: str) -> bool:
    """Return True if dirname looks like an out-of-source build directory."""
    n = dirname.lower()
    if n in ("build", "builds", "_build", ".build"):
        return True
    if n.startswith("build-") or n.endswith("-build"):
        return True
    # Cross-compile tuples like x86_64-poky-linux or aarch64-oe-linux
    if re.search(r"^[a-z0-9_]+-(?:poky|oe)-", n):
        return True
    return False


# ── Shared argparse helpers ───────────────────────────────────────────────────

def add_common_args(parser) -> None:
    """Add --build-dir, --manifest, --machine, --verbose to an argparse parser."""
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
    """
    Validate and resolve --build-dir, --manifest, --machine.
    Returns (build_dir, manifest_path, machine).
    """
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
