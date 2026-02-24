#!/usr/bin/env python3
"""
Generate an interactive HTML report of collected sources per installed package.

Shows per-package:
  - Source file counts (.c / .h / .S) actually collected
  - Compile-log coverage: how many compiled sources are present vs skipped
  - "Used" files (compile-confirmed), "Uncollected" files (compiled but absent),
    and all collected files in an expandable per-row detail panel

Usage:
  python3 report.py -b /path/to/build -m core-image-minimal -s ./sources -o report.html
  python3 report.py -b $BUILDDIR -m core-image-minimal
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import yocto_source_utils as yu
from test_sources import check_coverage


# ── Constants ─────────────────────────────────────────────────────────────────

TYPE_LABEL = {
    "userspace":    "Userspace",
    "kernel_image": "Kernel image",
    "kernel_module":"Kernel module",
    "no_source":    "No compiled source",
}

TYPE_COLOR = {
    "userspace":    "#4f86c6",
    "kernel_image": "#e07b39",
    "kernel_module":"#6dbf67",
    "no_source":    "#b0b0b0",
}


# ── Data collection ───────────────────────────────────────────────────────────

def _list_files(d: Path, exts: tuple) -> list[str]:
    if not d.exists():
        return []
    return sorted(
        str(f.relative_to(d))
        for f in d.rglob("*")
        if f.is_file() and f.suffix in exts
    )


def collect_data(packages: list, out_dir: Path) -> list[dict]:
    # Group packages by work_ver to flag shared recipe collections
    work_ver_map: dict[str, list[str]] = {}
    for pkg in packages:
        if pkg.work_ver and pkg.pkg_type == "userspace":
            work_ver_map.setdefault(str(pkg.work_ver), []).append(pkg.installed_name)

    rows = []
    for pkg in sorted(packages, key=lambda p: p.installed_name):
        pkg_dir = out_dir / pkg.installed_name
        no_src  = (pkg_dir / "NO_COMPILED_SOURCE.txt").exists()
        same_as = next(pkg_dir.glob("SAME_AS_*.txt"), None) if pkg_dir.exists() else None

        c_files = _list_files(pkg_dir, (".c",))
        h_files = _list_files(pkg_dir, (".h",))
        s_files = _list_files(pkg_dir, (".S", ".s"))

        # Coverage from compile log (userspace only)
        coverage: dict | None = None
        if pkg.pkg_type == "userspace":
            cov = check_coverage(pkg, out_dir)
            st  = cov.get("status", "")
            if st not in ("NO_WORK_DIR", "NO_LOG", "NO_CMDS"):
                nc = cov.get("not_collected", [])
                coverage = {
                    "compile_total": cov["total"],
                    "covered":       cov["covered"],
                    "not_collected": nc,
                }

        # Shared recipe detection
        shared_with: list[str] = []
        if pkg.work_ver and pkg.pkg_type == "userspace":
            peers = work_ver_map.get(str(pkg.work_ver), [])
            shared_with = [p for p in peers if p != pkg.installed_name]

        rows.append({
            "name":       pkg.installed_name,
            "recipe":     pkg.recipe,
            "version":    pkg.ver,
            "type":       pkg.pkg_type,
            "type_label": TYPE_LABEL.get(pkg.pkg_type, pkg.pkg_type),
            "color":      TYPE_COLOR.get(pkg.pkg_type, "#888"),
            "c":          len(c_files),
            "h":          len(h_files),
            "S":          len(s_files),
            "total":      len(c_files) + len(h_files) + len(s_files),
            "no_src":     no_src,
            "same_as":    same_as.stem.replace("SAME_AS_", "") if same_as else None,
            "coverage":   coverage,
            "shared_with": shared_with,
            # File lists (capped to keep HTML size sane)
            "c_files":    c_files[:200],
            "h_files":    h_files[:200],
            "s_files":    s_files[:100],
        })
    return rows


# ── HTML template ─────────────────────────────────────────────────────────────

_HTML = """\
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
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}}
header{{background:#1a1d23;color:#fff;padding:20px 32px}}
header h1{{font-size:1.4rem;font-weight:600}}
header p{{color:#9ca3af;font-size:.85rem;margin-top:4px}}
.wrap{{max-width:1400px;margin:0 auto;padding:24px 24px 60px}}

/* Cards */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);padding:16px 18px;box-shadow:var(--shadow)}}
.card .val{{font-size:1.8rem;font-weight:700}}
.card .lbl{{color:var(--muted);font-size:.78rem;margin-top:2px}}
.c1 .val{{color:#4f86c6}}.c2 .val{{color:#9b59b6}}.c3 .val{{color:#27ae60}}
.c4 .val{{color:#e07b39}}.c5 .val{{color:#e74c3c}}.c6 .val{{color:#16a085}}

/* Charts */
.charts{{display:grid;grid-template-columns:1fr 260px;gap:18px;margin-bottom:24px}}
@media(max-width:800px){{.charts{{grid-template-columns:1fr}}}}
.cc{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);padding:18px;box-shadow:var(--shadow)}}
.cc h2{{font-size:.85rem;font-weight:600;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}}

/* Table */
.tbl-wrap{{background:var(--card);border:1px solid var(--border);border-radius:var(--rad);box-shadow:var(--shadow);overflow:hidden}}
.toolbar{{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border)}}
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

/* Coverage bar */
.cov-wrap{{display:flex;align-items:center;gap:6px;min-width:120px}}
.cov-track{{flex:1;background:#e9ecef;border-radius:4px;height:7px;overflow:hidden;min-width:60px}}
.cov-used{{height:100%;background:#27ae60;border-radius:4px 0 0 4px}}
.cov-miss{{height:100%;background:#e74c3c}}

/* Detail panel */
tr.detail-row td{{padding:0;border-top:none}}
.detail-panel{{background:#fafbfc;border-top:2px solid #e0e4ea;padding:16px 20px;display:none}}
.detail-panel.open{{display:block}}
.detail-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-top:12px}}
.detail-section{{background:#fff;border:1px solid var(--border);border-radius:8px;padding:12px 14px}}
.detail-section h4{{font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:6px}}
.detail-section h4 .cnt{{background:#e9ecef;color:var(--text);border-radius:999px;padding:1px 7px;font-size:.72rem}}
.file-list{{font-family:monospace;font-size:.75rem;max-height:200px;overflow-y:auto;line-height:1.7}}
.file-list .f-c{{color:#4f86c6}}.file-list .f-h{{color:#9b59b6}}
.file-list .f-s{{color:#27ae60}}.file-list .f-nc{{color:#e74c3c}}
.cap-note{{color:var(--muted);font-size:.72rem;margin-top:4px;font-style:italic}}
.info-row{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:10px;font-size:.8rem}}
.info-row span{{color:var(--muted)}}.info-row strong{{color:var(--text)}}
.shared-badge{{display:inline-flex;align-items:center;gap:4px;background:#fff3cd;
               border:1px solid #ffc107;border-radius:4px;padding:2px 8px;font-size:.75rem}}
</style>
</head>
<body>

<header>
  <h1>Yocto Source Report</h1>
  <p>Image: <strong>{image}</strong> &nbsp;·&nbsp;
     Machine: <strong>{machine}</strong> &nbsp;·&nbsp;
     Generated: {generated}</p>
</header>

<div class="wrap">

<!-- Summary cards -->
<div class="cards">
  <div class="card c4"><div class="val">{total_pkgs}</div><div class="lbl">Installed packages</div></div>
  <div class="card c1"><div class="val">{total_c}</div><div class="lbl">.c source files</div></div>
  <div class="card c2"><div class="val">{total_h}</div><div class="lbl">.h header files</div></div>
  <div class="card c3"><div class="val">{total_S}</div><div class="lbl">.S assembly files</div></div>
  <div class="card"   ><div class="val">{total_files}</div><div class="lbl">Total collected</div></div>
  <div class="card c5"><div class="val">{total_uncollected}</div><div class="lbl">Compiled not collected</div></div>
  <div class="card c6"><div class="val">{cov_pct}%</div><div class="lbl">Compile coverage</div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="cc">
    <h2>Source files per package (collected .c / .h / .S)</h2>
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
      <th data-col="version">Version <span class="si">↕</span></th>
      <th data-col="type_label">Type <span class="si">↕</span></th>
      <th data-col="c" style="text-align:right">.c <span class="si">↕</span></th>
      <th data-col="h" style="text-align:right">.h <span class="si">↕</span></th>
      <th data-col="S" style="text-align:right">.S <span class="si">↕</span></th>
      <th data-col="total" style="text-align:right">Total <span class="si">↕</span></th>
      <th>Coverage / Distribution</th>
    </tr></thead>
    <tbody id="tblBody"></tbody>
  </table>
</div>

</div>

<script>
const DATA = {data_json};
const MAX_TOTAL = Math.max(...DATA.map(d=>d.total),1);

// ── Charts ───────────────────────────────────────────────────────────────────
const barData = DATA.filter(d=>d.total>0).sort((a,b)=>b.total-a.total);
new Chart(document.getElementById('barChart'),{{
  type:'bar',
  data:{{
    labels:barData.map(d=>d.name),
    datasets:[
      {{label:'.c', data:barData.map(d=>d.c), backgroundColor:'#4f86c6', stack:'s'}},
      {{label:'.h', data:barData.map(d=>d.h), backgroundColor:'#9b59b6', stack:'s'}},
      {{label:'.S', data:barData.map(d=>d.S), backgroundColor:'#27ae60', stack:'s'}},
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
let sortCol='total', sortAsc=false, filterText='', filterType='';
let openRow=null;

function fmt(n){{
  return n===0?'<span class="zero">0</span>':n.toLocaleString();
}}

function covBar(cov){{
  if(!cov) return '';
  const t=cov.compile_total, u=cov.covered, miss=t-u;
  if(t===0) return '';
  const usedPct=Math.round(u/t*100);
  const missPct=100-usedPct;
  const nc=cov.not_collected.length;
  const label=nc>0
    ? `<span style="color:#e74c3c;font-size:.75rem">${{nc}} uncollected</span>`
    : `<span style="color:#27ae60;font-size:.75rem">all covered</span>`;
  return `<div class="cov-wrap">
    <div class="cov-track">
      <div style="display:flex;height:100%">
        <div class="cov-used" style="width:${{usedPct}}%"></div>
        <div class="cov-miss" style="width:${{missPct}}%"></div>
      </div>
    </div>
    <span style="font-size:.73rem;color:#888;min-width:52px">${{u}}/${{t}}</span>
    ${{label}}
  </div>`;
}}

function distBar(d){{
  const pct=d.total?Math.round(d.total/MAX_TOTAL*100):0;
  return `<div class="cov-wrap">
    <div class="cov-track"><div style="width:${{pct}}%;height:100%;background:${{d.color}};border-radius:4px"></div></div>
    <span style="font-size:.73rem;color:#888">${{d.total}}</span>
  </div>`;
}}

function fileList(files, cls, total){{
  if(!files||!files.length) return '<em style="color:#ccc;font-size:.75rem">none</em>';
  const items = files.map(f=>`<div class="${{cls}}">${{f}}</div>`).join('');
  const cap = total>files.length
    ? `<div class="cap-note">Showing ${{files.length}} of ${{total}}</div>`:'';
  return `<div class="file-list">${{items}}</div>${{cap}}`;
}}

function renderDetail(d){{
  if(d.no_src)
    return '<div class="detail-panel open"><em>No compiled source — scripts/configs/data only.</em></div>';
  if(d.same_as)
    return `<div class="detail-panel open"><em>Sources shared with <strong>${{d.same_as}}</strong>.</em></div>`;

  const shared = d.shared_with&&d.shared_with.length
    ? `<div class="shared-badge">⚠ Shares recipe work-dir with: ${{d.shared_with.join(', ')}}</div>`:'';

  let covSection='';
  if(d.coverage){{
    const nc=d.coverage.not_collected;
    covSection=`
      <div class="detail-section">
        <h4>Compiled but NOT collected <span class="cnt">${{nc.length}}</span></h4>
        <div style="color:#888;font-size:.76rem;margin-bottom:6px">
          These files have a .o in the build dir but were not collected — optional
          features, disabled modules, or uninstalled utilities.
        </div>
        ${{fileList(nc,'f-nc',nc.length)}}
      </div>`;
  }}

  return `<div class="detail-panel open">
    <div class="info-row">
      <span>Recipe: <strong>${{d.recipe}}</strong></span>
      <span>Version: <strong>${{d.version}}</strong></span>
      <span>Type: <strong>${{d.type_label}}</strong></span>
      ${{d.coverage?`<span>Compile coverage: <strong>${{d.coverage.covered}}/${{d.coverage.compile_total}}</strong></span>`:''}}
    </div>
    ${{shared}}
    <div class="detail-grid">
      <div class="detail-section">
        <h4 style="color:#4f86c6">.c source files <span class="cnt">${{d.c}}</span></h4>
        ${{fileList(d.c_files,'f-c',d.c)}}
      </div>
      <div class="detail-section">
        <h4 style="color:#9b59b6">.h header files <span class="cnt">${{d.h}}</span></h4>
        ${{fileList(d.h_files,'f-h',d.h)}}
      </div>
      ${{d.S?`<div class="detail-section">
        <h4 style="color:#27ae60">.S assembly files <span class="cnt">${{d.S}}</span></h4>
        ${{fileList(d.s_files,'f-s',d.S)}}
      </div>`:''}}
      ${{covSection}}
    </div>
  </div>`;
}}

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
  tbody.innerHTML=rows.map(d=>{{
    const dist = d.no_src||d.same_as
      ? `<span class="muted-text">${{d.no_src?'no compiled source':'→ '+d.same_as}}</span>`
      : (d.coverage?covBar(d.coverage):distBar(d));
    return `<tr class="data-row" data-name="${{d.name}}">
      <td><strong>${{d.name}}</strong></td>
      <td style="color:#555">${{d.recipe}}</td>
      <td style="color:#888;font-size:.8rem">${{d.version}}</td>
      <td><span class="badge" style="background:${{d.color}}">${{d.type_label}}</span></td>
      <td class="num">${{fmt(d.c)}}</td>
      <td class="num">${{fmt(d.h)}}</td>
      <td class="num">${{fmt(d.S)}}</td>
      <td class="num">${{fmt(d.total)}}</td>
      <td>${{dist}}</td>
    </tr>
    <tr class="detail-row"><td colspan="9">${{renderDetail(d)}}</td></tr>`;
  }}).join('');

  // Row click to expand
  tbody.querySelectorAll('tr.data-row').forEach(tr=>{{
    tr.addEventListener('click',()=>{{
      const panel=tr.nextElementSibling.querySelector('.detail-panel');
      if(!panel) return;
      const isOpen=panel.classList.contains('open');
      // Close all
      tbody.querySelectorAll('.detail-panel.open').forEach(p=>p.classList.remove('open'));
      if(!isOpen) panel.classList.add('open');
    }});
  }});

  // Sort icons
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


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML source report for a Yocto image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].strip() if "Usage:" in __doc__ else "",
    )
    yu.add_common_args(parser)
    parser.add_argument("-s", "--sources", metavar="DIR", default="",
                        help="Collected sources dir (default: <build-dir>/sources)")
    parser.add_argument("-o", "--output", metavar="FILE", default="",
                        help="Output HTML file (default: <sources-dir>/report.html)")
    args = parser.parse_args()

    build_dir, manifest_path, machine = yu.resolve_common_args(args)
    out_dir = Path(args.sources).resolve() if args.sources else build_dir / "sources"
    output  = Path(args.output).resolve()  if args.output  else out_dir / "report.html"
    image   = manifest_path.stem if manifest_path else str(getattr(args, "manifest", ""))

    if not out_dir.exists():
        raise SystemExit(f"Sources dir not found: {out_dir}\nRun collect_sources.py first.")

    print(f"Discovering packages…")
    packages = yu.discover_packages(manifest_path, build_dir, machine, args.verbose)

    print(f"Collecting coverage data for {sum(1 for p in packages if p.pkg_type=='userspace')} userspace packages…")
    rows = collect_data(packages, out_dir)

    total_c    = sum(r["c"]     for r in rows)
    total_h    = sum(r["h"]     for r in rows)
    total_S    = sum(r["S"]     for r in rows)
    total_unc  = sum(
        len(r["coverage"]["not_collected"])
        for r in rows if r["coverage"]
    )
    # Coverage %: covered / (covered + not_collected)
    all_cov   = sum(r["coverage"]["covered"]       for r in rows if r["coverage"])
    all_ct    = sum(r["coverage"]["compile_total"]  for r in rows if r["coverage"])
    cov_pct   = round(all_cov / all_ct * 100) if all_ct else 0

    html = _HTML.format(
        image            = image,
        machine          = machine,
        generated        = datetime.now().strftime("%Y-%m-%d %H:%M"),
        total_pkgs       = len(rows),
        total_c          = f"{total_c:,}",
        total_h          = f"{total_h:,}",
        total_S          = f"{total_S:,}",
        total_files      = f"{total_c + total_h + total_S:,}",
        total_uncollected= f"{total_unc:,}",
        cov_pct          = cov_pct,
        data_json        = json.dumps(rows, indent=None),
    )

    output.write_text(html)
    print(f"Report: {output}")
    print(f"  Packages : {len(rows)}")
    print(f"  .c       : {total_c:,}")
    print(f"  .h       : {total_h:,}")
    print(f"  .S       : {total_S:,}")
    print(f"  Uncollected (compiled but absent): {total_unc:,}")
    print(f"  Coverage : {cov_pct}%  ({all_cov:,}/{all_ct:,})")


if __name__ == "__main__":
    main()
