#!/usr/bin/env python3
"""
Generate an interactive HTML report of collected sources per installed package.

Three source categories per package:
  compiled+used        Sources confirmed in the installed binary (DWARF).
  compiled+not-used    Compiled (per log.do_compile) but not in the binary.
  never-compiled       Present in the source tree, never compiled.

Shows dynamic file-type breakdown for each category and allows per-category
and per-type filtering.

Usage:
  python3 report.py -b /path/to/build -m core-image-minimal -s ./sources -o report.html
  python3 report.py -b $BUILDDIR -m core-image-minimal
"""

import argparse
import json
from collections import Counter
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

# Category directory names (None = main pkg dir)
_CAT_DIRS = {
    "compiled_used":     None,
    "compiled_not_used": "_compiled_not_used",
    "never_used":        "_never_used",
}


# ── Data collection ───────────────────────────────────────────────────────────

def _scan_dir(d: Path) -> list[dict]:
    """Return list of {path, ext} for all files under d."""
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


def _list_files_in(d: Path, skip_subdirs: frozenset) -> list[dict]:
    """Like _scan_dir but skips first-level subdirs in skip_subdirs."""
    if not d.exists():
        return []
    result = []
    for f in d.rglob("*"):
        if not f.is_file():
            continue
        parts = f.relative_to(d).parts
        if parts[0] in skip_subdirs:
            continue
        rel = str(Path(*parts))
        ext = f.suffix.lower() or "(no ext)"
        result.append({"path": rel, "ext": ext})
    return result


def _ext_counts(files: list[dict]) -> dict[str, int]:
    c = Counter(f["ext"] for f in files)
    return dict(sorted(c.items(), key=lambda x: -x[1]))


def collect_data(packages: list, out_dir: Path) -> list[dict]:
    _SKIP = frozenset({"_compiled_not_used", "_never_used"})

    work_ver_map: dict[str, list[str]] = {}
    for pkg in packages:
        if pkg.work_ver and pkg.pkg_type == "userspace":
            work_ver_map.setdefault(str(pkg.work_ver), []).append(pkg.installed_name)

    rows = []
    for pkg in sorted(packages, key=lambda p: p.installed_name):
        pkg_dir = out_dir / pkg.installed_name
        no_src  = (pkg_dir / "NO_COMPILED_SOURCE.txt").exists()
        same_as = next(pkg_dir.glob("SAME_AS_*.txt"), None) if pkg_dir.exists() else None

        # ── Per-category file lists ────────────────────────────────────────
        cu_files  = _list_files_in(pkg_dir, _SKIP)           # compiled+used
        cnu_files = _scan_dir(pkg_dir / "_compiled_not_used") # compiled+not-used
        nu_files  = _scan_dir(pkg_dir / "_never_used")        # never-used

        cu_ext  = _ext_counts(cu_files)
        cnu_ext = _ext_counts(cnu_files)
        nu_ext  = _ext_counts(nu_files)

        # Coverage from compile log
        coverage: dict | None = None
        if pkg.pkg_type == "userspace":
            cov = check_coverage(pkg, out_dir)
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

        rows.append({
            "name":       pkg.installed_name,
            "recipe":     pkg.recipe,
            "version":    pkg.ver,
            "type":       pkg.pkg_type,
            "type_label": TYPE_LABEL.get(pkg.pkg_type, pkg.pkg_type),
            "color":      TYPE_COLOR.get(pkg.pkg_type, "#888"),
            # Counts
            "cu_total":   len(cu_files),
            "cnu_total":  len(cnu_files),
            "nu_total":   len(nu_files),
            # Extension breakdowns
            "cu_ext":     cu_ext,
            "cnu_ext":    cnu_ext,
            "nu_ext":     nu_ext,
            # File lists (capped for HTML size)
            "cu_files":   [f["path"] for f in cu_files[:300]],
            "cnu_files":  [f["path"] for f in cnu_files[:300]],
            "nu_files":   [f["path"] for f in nu_files[:300]],
            # Flags
            "no_src":     no_src,
            "same_as":    same_as.stem.replace("SAME_AS_", "") if same_as else None,
            "coverage":   coverage,
            "shared_with": shared_with,
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
  --cu:#27ae60;--cnu:#e07b39;--nu:#9b59b6;
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
.c4 .val{{color:#e07b39}}.c5 .val{{color:#e74c3c}}.c6 .val{{color:var(--cnu)}}

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
  <p>Image: <strong>{image}</strong> &nbsp;·&nbsp;
     Machine: <strong>{machine}</strong> &nbsp;·&nbsp;
     Generated: {generated}</p>
</header>

<div class="wrap">

<!-- Legend -->
<div class="legend">
  <div class="leg-item"><div class="leg-dot" style="background:var(--cu)"></div>Compiled &amp; Used — in installed binary (DWARF confirmed)</div>
  <div class="leg-item"><div class="leg-dot" style="background:var(--cnu)"></div>Compiled, Not Used — compiled but not in installed binary</div>
  <div class="leg-item"><div class="leg-dot" style="background:var(--nu)"></div>Never Compiled — in source tree, never compiled</div>
</div>

<!-- Summary cards -->
<div class="cards">
  <div class="card c4"><div class="val">{total_pkgs}</div><div class="lbl">Installed packages</div></div>
  <div class="card c3"><div class="val">{total_cu}</div><div class="lbl">Compiled &amp; used</div></div>
  <div class="card c6"><div class="val">{total_cnu}</div><div class="lbl">Compiled, not used</div></div>
  <div class="card c2"><div class="val">{total_nu}</div><div class="lbl">Never compiled</div></div>
  <div class="card c1"><div class="val">{total_all}</div><div class="lbl">Total source files</div></div>
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
      <th data-col="cu_total" style="text-align:right">Compiled+Used <span class="si">↕</span></th>
      <th data-col="cnu_total" style="text-align:right">Comp.Not-Used <span class="si">↕</span></th>
      <th data-col="nu_total" style="text-align:right">Never Compiled <span class="si">↕</span></th>
      <th>Distribution</th>
    </tr></thead>
    <tbody id="tblBody"></tbody>
  </table>
</div>

</div>

<script>
const DATA = {data_json};
const MAX_CU  = Math.max(...DATA.map(d=>d.cu_total), 1);
const MAX_ALL = Math.max(...DATA.map(d=>d.cu_total+d.cnu_total+d.nu_total), 1);

// ── Charts ───────────────────────────────────────────────────────────────────
const barData = DATA.filter(d=>d.cu_total+d.cnu_total+d.nu_total>0)
                    .sort((a,b)=>(b.cu_total+b.cnu_total+b.nu_total)-(a.cu_total+a.cnu_total+a.nu_total));
new Chart(document.getElementById('barChart'),{{
  type:'bar',
  data:{{
    labels:barData.map(d=>d.name),
    datasets:[
      {{label:'Compiled+Used',    data:barData.map(d=>d.cu_total),  backgroundColor:'#27ae60', stack:'s'}},
      {{label:'Compiled Not-Used',data:barData.map(d=>d.cnu_total), backgroundColor:'#e07b39', stack:'s'}},
      {{label:'Never Compiled',   data:barData.map(d=>d.nu_total),  backgroundColor:'#9b59b6', stack:'s'}},
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

function miniBar(cu, cnu, nu){{
  const total = cu+cnu+nu;
  if(!total) return '';
  const cuP  = Math.round(cu /total*100);
  const cnuP = Math.round(cnu/total*100);
  const nuP  = 100-cuP-cnuP;
  return `<div style="display:flex;align-items:center;gap:6px">
    <div class="mini-bar" style="width:100px">
      <div style="width:${{cuP}}%;background:#27ae60"></div>
      <div style="width:${{cnuP}}%;background:#e07b39"></div>
      <div style="width:${{nuP}}%;background:#9b59b6"></div>
    </div>
    <span style="font-size:.72rem;color:#888">${{total}}</span>
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

function pane(id, label, color, files, ext, total, active){{
  const tfr = makeTypeFilter(files, id);
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
        ${{fileListFiltered(files, color, total, id)}}
      </div>
    </div>
  </div>`;
}}

function renderDetail(d, idx){{
  if(d.no_src)
    return '<div class="detail-panel open"><em>No compiled source — scripts/configs/data only.</em></div>';
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

  const cuPane  = pane(`cu-${{idx}}`,  'Compiled &amp; used files',  '#27ae60', d.cu_files,  d.cu_ext,  d.cu_total,  true);
  const cnuPane = pane(`cnu-${{idx}}`, 'Compiled, not-used files',   '#e07b39', d.cnu_files, d.cnu_ext, d.cnu_total, false);
  const nuPane  = pane(`nu-${{idx}}`,  'Never-compiled files',       '#9b59b6', d.nu_files,  d.nu_ext,  d.nu_total,  false);

  return `<div class="detail-panel open">
    ${{info}}${{shared}}
    <div class="cat-tabs" data-idx="${{idx}}">
      <div class="cat-tab active" data-pane="cp-cu-${{idx}}" onclick="switchTab(this)">
        Compiled+Used <strong style="color:#27ae60">${{d.cu_total}}</strong></div>
      <div class="cat-tab" data-pane="cp-cnu-${{idx}}" onclick="switchTab(this)">
        Compiled Not-Used <strong style="color:#e07b39">${{d.cnu_total}}</strong></div>
      <div class="cat-tab" data-pane="cp-nu-${{idx}}" onclick="switchTab(this)">
        Never Compiled <strong style="color:#9b59b6">${{d.nu_total}}</strong></div>
    </div>
    ${{cuPane}}${{cnuPane}}${{nuPane}}
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
    const dist = d.no_src||d.same_as
      ? `<span class="muted-text">${{d.no_src?'no compiled source':'→ '+d.same_as}}</span>`
      : miniBar(d.cu_total, d.cnu_total, d.nu_total);
    return `<tr class="data-row" data-name="${{d.name}}">
      <td><strong>${{d.name}}</strong></td>
      <td style="color:#555">${{d.recipe}}</td>
      <td><span class="badge" style="background:${{d.color}}">${{d.type_label}}</span></td>
      <td class="num" style="color:#27ae60">${{fmt(d.cu_total)}}</td>
      <td class="num" style="color:#e07b39">${{fmt(d.cnu_total)}}</td>
      <td class="num" style="color:#9b59b6">${{fmt(d.nu_total)}}</td>
      <td>${{dist}}</td>
    </tr>
    <tr class="detail-row"><td colspan="7">${{renderDetail(d,idx)}}</td></tr>`;
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

    print(f"Collecting data for {len(packages)} packages…")
    rows = collect_data(packages, out_dir)

    total_cu  = sum(r["cu_total"]  for r in rows)
    total_cnu = sum(r["cnu_total"] for r in rows)
    total_nu  = sum(r["nu_total"]  for r in rows)

    html = _HTML.format(
        image      = image,
        machine    = machine,
        generated  = datetime.now().strftime("%Y-%m-%d %H:%M"),
        total_pkgs = len(rows),
        total_cu   = f"{total_cu:,}",
        total_cnu  = f"{total_cnu:,}",
        total_nu   = f"{total_nu:,}",
        total_all  = f"{total_cu + total_cnu + total_nu:,}",
        data_json  = json.dumps(rows, indent=None),
    )

    output.write_text(html)
    print(f"Report: {output}")
    print(f"  Compiled+Used     : {total_cu:,}")
    print(f"  Compiled+Not-Used : {total_cnu:,}")
    print(f"  Never Compiled    : {total_nu:,}")
    print(f"  Total             : {total_cu + total_cnu + total_nu:,}")


if __name__ == "__main__":
    main()
