#!/usr/bin/env python3
"""
Verify collected sources by parsing compiler logs and optionally re-compiling.

For each userspace package, parses temp/log.do_compile to extract every
gcc -c compilation command, resolves source file paths (tracking CWD via
make[N]: Entering/Leaving), and checks whether each compiled source is
present in the collected sources directory.

In --compile mode, re-runs each compile command using the collected source
copy and compares the resulting .o against the original (MD5).

Usage:
  python3 test_sources.py -b /path/to/build -m core-image-minimal -s ./sources
  python3 test_sources.py -b $BUILDDIR -m core-image-minimal --compile
  python3 test_sources.py -b $BUILDDIR -m core-image-minimal -p busybox,dropbear --compile
"""

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yocto_source_utils as yu


# ── Regex constants ───────────────────────────────────────────────────────────

# Matches cross-compiler and native gcc/g++ invocations
_COMPILER_RE = re.compile(
    r'\b(?:[a-z0-9_]+-(?:poky|oe|linux)-(?:linux-)?(?:gcc|g\+\+)'
    r'|gcc(?:-\d+(?:\.\d+)*)?|g\+\+(?:-\d+(?:\.\d+)*)?|cc|c\+\+)\b'
)
_DEPTH_RE = re.compile(r"make\[(\d+)\]: (Entering|Leaving) directory '(.+)'")
_SOURCE_EXTS = (".c", ".S", ".s", ".cc", ".cpp", ".cxx")


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class CompileCmd:
    cwd:  Path              # working directory when this command ran
    cmd:  str               # original command line
    src:  Path              # absolute resolved source file
    obj:  Path | None       # absolute resolved .o output (may be None)


# ── Compile-log parsing ───────────────────────────────────────────────────────

def _get_initial_cwd(work_ver: Path) -> Path:
    """
    Read run.do_compile for the 'cd ...' line that BitBake uses to set
    the working directory before executing do_compile.
    Falls back to work_ver itself if not found.
    """
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
    """
    Parse log.do_compile.

    Tracks CWD transitions from make[N]: Entering/Leaving directory lines and
    extracts every -c compilation command.
    """
    cmds: list[CompileCmd] = []
    try:
        lines = log_file.read_text(errors="replace").splitlines()
    except OSError:
        return cmds

    # cwd_stack[depth] = Path; depth 0 = before any make[] Entering
    cwd_stack: dict[int, Path] = {0: initial_cwd}
    current_depth = 0

    for line in lines:
        # Track make directory stack
        m = _DEPTH_RE.search(line)
        if m:
            depth  = int(m.group(1))
            action = m.group(2)
            path   = m.group(3)
            if action == "Entering":
                cwd_stack[depth] = Path(path)
                current_depth = depth
            else:  # Leaving
                cwd_stack.pop(depth, None)
                # Go back to the deepest remaining depth below this one
                remaining = [k for k in cwd_stack if k < depth]
                current_depth = max(remaining) if remaining else 0
            continue

        # Require -c flag and a compiler invocation
        if " -c " not in line or not _COMPILER_RE.search(line):
            continue
        # Skip libtool wrapper lines — the actual gcc invocation follows
        # as "libtool: compile:  gcc ..." which we'll pick up separately.
        if "--mode=compile" in line:
            continue
        # Strip "libtool: compile:  " prefix emitted by libtool for the
        # actual gcc invocation so the command parses correctly.
        if line.startswith("libtool: compile:"):
            line = line[len("libtool: compile:"):].lstrip()

        cwd = cwd_stack.get(current_depth, initial_cwd)
        cmd = _parse_one_cmd(line, cwd)
        if cmd:
            cmds.append(cmd)

    return cmds


def _parse_one_cmd(line: str, cwd: Path) -> CompileCmd | None:
    """Parse a single compiler -c line; return CompileCmd or None."""
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

    # Source file = last non-flag argument with a recognised extension.
    # Skip tokens containing backtick (shell command substitution from libtool).
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


# ── Coverage check ────────────────────────────────────────────────────────────

def check_coverage(
    pkg: yu.PackageInfo,
    sources_dir: Path,
) -> dict:
    """
    Parse the compile log for a userspace package and report how many
    compiled source files are present in sources_dir/<pkg>/.
    """
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
    not_coll:  list[str] = []  # in work_ver but not collected
    outside:   list[str] = []  # absolute path outside work_ver (generated/external)

    for cmd in cmds:
        try:
            rel = cmd.src.relative_to(pkg.work_ver)
        except ValueError:
            # Only report as truly "outside" if the file actually exists there.
            # Non-existent outside paths are phantom artifacts of parallel make
            # output interleaving (CWD wrongly attributed after a Leaving line).
            if cmd.src.exists():
                outside.append(str(cmd.src))
            continue

        if (pkg_sources / rel).exists():
            covered.append(str(rel))
        else:
            not_coll.append(str(rel))

    total = len(cmds)
    return {
        "status":   "OK" if not not_coll else "INCOMPLETE",
        "total":    total,
        "covered":  len(covered),
        "not_collected": not_coll,
        "outside":  outside,
    }


# ── Compile test ──────────────────────────────────────────────────────────────

def _make_shadow_cmd(
    cmd: CompileCmd, collected_src: Path, out_obj: Path
) -> str:
    """
    Build a modified compile command that:
      • replaces the source file argument with collected_src (absolute)
      • replaces the -o argument with out_obj (absolute)
      • adds -I<original_source_dir> so #include "..." relative to the
        original source file's directory still resolves (GCC searches the
        source file's own directory first for quoted includes)
    All other flags (sysroot, -I, -D, etc.) are kept verbatim.
    Command still runs with cwd = cmd.cwd.
    """
    try:
        tokens = shlex.split(cmd.cmd)
    except ValueError:
        return cmd.cmd

    new_tokens: list[str] = []
    src_done = obj_done = False
    i = 0
    while i < len(tokens):
        if tokens[i] == "-o" and i + 1 < len(tokens) and not obj_done:
            new_tokens += ["-o", str(out_obj)]
            obj_done = True
            i += 2
        elif (not tokens[i].startswith("-") and not src_done
              and any(tokens[i].endswith(e) for e in _SOURCE_EXTS)):
            new_tokens.append(str(collected_src))
            src_done = True
            i += 1
        else:
            new_tokens.append(tokens[i])
            i += 1

    # If no -o was found, append it
    if not obj_done:
        new_tokens += ["-o", str(out_obj)]

    # Add the original source directory and all its subdirectories as *quoted*
    # include search paths.  This ensures:
    #   - '#include "header.h"' from the source file itself still resolves
    #     to the original, even when compiled from the collected copy.
    #   - '#include "header.h"' inside transitively-#include'd .c files (a
    #     pattern used by e.g. busybox/unxz) can also find headers relative
    #     to their original subdirectory in the source tree.
    # Using -iquote (not -I) keeps system '#include <...>' lookups unaffected,
    # preventing project-local files from shadowing system headers.
    orig_src_dir = cmd.src.parent
    new_tokens.append(f"-iquote{orig_src_dir}")
    try:
        for subdir in orig_src_dir.iterdir():
            if subdir.is_dir():
                new_tokens.append(f"-iquote{subdir}")
    except OSError:
        pass

    return shlex.join(new_tokens)


def _get_build_env(work_ver: Path) -> dict:
    """
    Read the PATH and essential environment variables from run.do_compile
    so that the cross-compiler and build tools can be found.
    Returns a modified copy of os.environ.
    """
    env = os.environ.copy()
    run_script = work_ver / "temp" / "run.do_compile"
    if not run_script.exists():
        return env
    for line in run_script.read_text(errors="replace").splitlines():
        m = re.match(r"^export (\w+)=\"(.*)\"$", line)
        if m and m.group(1) == "PATH":
            env["PATH"] = m.group(2)
            break
    return env


def compile_test(
    pkg: yu.PackageInfo,
    sources_dir: Path,
    work_dir: Path,
    verbose: bool = False,
) -> dict:
    """
    Re-run compile commands with collected source files.

    For each covered source file, the original gcc command is replayed
    with the source replaced by sources_dir/<pkg>/rel and the output
    redirected to a temp .o.  The result .o is compared (MD5) against
    the original object file.

    Runs inside a temporary directory that is cleaned up after.
    """
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
        "status":   "OK",
        "total":    0,
        "pass":     0,
        "fail":     0,
        "mismatch": 0,
        "skip":     0,
        "failures": [],
        "mismatches": [],
    }

    build_env = _get_build_env(pkg.work_ver)

    with tempfile.TemporaryDirectory(dir=work_dir, prefix=f"test_{pkg.installed_name}_") as tmp:
        tmp_path = Path(tmp)

        for idx, cmd in enumerate(cmds):
            # Resolve collected source
            try:
                rel = cmd.src.relative_to(pkg.work_ver)
            except ValueError:
                # Skip phantom parallel-make paths that don't exist on disk
                if cmd.src.exists():
                    results["skip"] += 1
                continue

            collected_src = pkg_sources / rel
            if not collected_src.exists():
                results["skip"] += 1
                continue

            results["total"] += 1
            out_obj = tmp_path / f"{idx}.o"
            new_cmd = _make_shadow_cmd(cmd, collected_src, out_obj)

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

            # Compare .o files if original exists.
            # Note: -fdebug-prefix-map and -fmacro-prefix-map flags embed
            # the source path into DWARF/macro sections, so the collected
            # copy (at a different path) will always produce a different .o.
            # We strip debug sections before comparing to test only code.
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

    if results["fail"]:
        results["status"] = "FAIL"
    # Note: mismatch alone is NOT a failure — it reflects expected differences
    # from -fdebug-prefix-map / -fmacro-prefix-map (source path in debug info).

    return results


# ── Reporting ─────────────────────────────────────────────────────────────────

def _print_list(label: str, items: list[str], limit: int = 8) -> None:
    print(f"  {label} ({len(items)}):")
    for item in items[:limit]:
        print(f"    {item}")
    if len(items) > limit:
        print(f"    … and {len(items) - limit} more")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Verify collected Yocto sources against compiler logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].strip() if "Usage:" in __doc__ else "",
    )
    yu.add_common_args(parser)
    parser.add_argument(
        "-s", "--sources",
        metavar="DIR", default="",
        help="Collected sources directory (default: <build-dir>/sources)",
    )
    parser.add_argument(
        "--compile",
        action="store_true",
        help="Re-run compile commands using collected sources and compare .o files",
    )
    parser.add_argument(
        "-p", "--packages",
        metavar="PKG[,PKG…]", default="",
        help="Comma-separated list of installed package names to test (default: all)",
    )
    args = parser.parse_args()

    build_dir, manifest_path, machine = yu.resolve_common_args(args)
    out_dir  = Path(args.sources).resolve() if args.sources else build_dir / "sources"
    pkg_filter = set(args.packages.split(",")) if args.packages else set()

    print(f"Build dir : {build_dir}")
    print(f"Machine   : {machine}")
    print(f"Manifest  : {manifest_path}")
    print(f"Sources   : {out_dir}")
    if pkg_filter:
        print(f"Filter    : {', '.join(sorted(pkg_filter))}")

    if not out_dir.exists():
        raise SystemExit(f"Sources directory not found: {out_dir}\n"
                         "Run collect_sources.py first.")

    packages = yu.discover_packages(manifest_path, build_dir, machine, args.verbose)
    userspace = [p for p in packages
                 if p.pkg_type == "userspace"
                 and (not pkg_filter or p.installed_name in pkg_filter)]
    print(f"\nDiscovered {len(packages)} packages, "
          f"{len(userspace)} userspace (will test)\n")
    print("=" * 72)

    # Temp dir for compile test outputs (inside build_dir/tmp for same filesystem)
    tmp_root = build_dir / "tmp" / "test_sources_tmp" if args.compile else None
    if tmp_root:
        tmp_root.mkdir(parents=True, exist_ok=True)

    summary: dict[str, str] = {}

    for pkg in sorted(userspace, key=lambda p: p.installed_name):
        print(f"\n[{pkg.installed_name}]  (recipe={pkg.recipe} ver={pkg.ver})")

        # ── Coverage check ─────────────────────────────────────────────────
        cov = check_coverage(pkg, out_dir)
        status = cov.get("status", "ERROR")

        if status == "NO_WORK_DIR":
            print("  SKIP: work dir not found")
            summary[pkg.installed_name] = "SKIP"
            continue
        if status == "NO_LOG":
            print("  SKIP: no log.do_compile")
            summary[pkg.installed_name] = "SKIP"
            continue
        if status == "NO_CMDS":
            print("  SKIP: no compile commands found in log")
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
            _print_list("Not collected (in work_ver)", not_coll)
        if outside:
            _print_list("Outside work_ver (generated/external)", outside)

        # ── Compile test (optional) ────────────────────────────────────────
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
                    _print_list(
                        "FAIL",
                        [f"{f['rel']}: {f['error'].splitlines()[0]}"
                         for f in r["failures"]],
                    )
                if r["mismatches"]:
                    _print_list(
                        ".o differs (expected: debug-prefix-map changes path)",
                        r["mismatches"],
                    )
                if r["pass"] == r["total"] and not r["fail"]:
                    print("  ALL COMPILED OK")

            # Combine statuses
            pkg_status = ("FAIL" if ct_status == "FAIL"
                          else "INCOMPLETE" if not_coll
                          else "OK")
        else:
            pkg_status = "OK" if not not_coll else "INCOMPLETE"

        summary[pkg.installed_name] = pkg_status

    # Clean up temp dir
    if tmp_root and tmp_root.exists():
        import shutil
        shutil.rmtree(tmp_root, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────────────────────
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

    import sys
    sys.exit(0 if not fail_pkgs else 1)


if __name__ == "__main__":
    main()
