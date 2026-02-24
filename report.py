#!/usr/bin/env python3
"""
Generate an interactive HTML report of collected sources per installed package.

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


# ── Data collection ───────────────────────────────────────────────────────────

def _count_files(d: Path) -> dict:
    c = h = s = 0
    if d.exists():
        for f in d.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix == ".c":
                c += 1
            elif f.suffix == ".h":
                h += 1
            elif f.suffix in (".S", ".s"):
                s += 1
    return {"c": c, "h": h, "S": s}


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


def collect_data(packages: list, out_dir: Path) -> list[dict]:
    rows = []
    for pkg in sorted(packages, key=lambda p: p.installed_name):
        pkg_dir = out_dir / pkg.installed_name
        counts  = _count_files(pkg_dir)
        no_src  = (pkg_dir / "NO_COMPILED_SOURCE.txt").exists()
        same_as = next(pkg_dir.glob("SAME_AS_*.txt"), None) if pkg_dir.exists() else None
        rows.append({
            "name":     pkg.installed_name,
            "recipe":   pkg.recipe,
            "version":  pkg.ver,
            "type":     pkg.pkg_type,
            "type_label": TYPE_LABEL.get(pkg.pkg_type, pkg.pkg_type),
            "color":    TYPE_COLOR.get(pkg.pkg_type, "#888"),
            "c":        counts["c"],
            "h":        counts["h"],
            "S":        counts["S"],
            "total":    counts["c"] + counts["h"] + counts["S"],
            "no_src":   no_src,
            "same_as":  same_as.name if same_as else None,
            "src_dir":  str(pkg_dir),
        })
    return rows


# ── HTML generation ───────────────────────────────────────────────────────────

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Yocto Source Report — {image}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #f5f7fa; --card: #ffffff; --border: #e0e4ea;
    --text: #1a1d23; --muted: #6b7280; --accent: #4f86c6;
    --radius: 10px; --shadow: 0 2px 8px rgba(0,0,0,.08);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: var(--bg);
          color: var(--text); font-size: 14px; line-height: 1.5; }}
  header {{ background: #1a1d23; color: #fff; padding: 20px 32px; }}
  header h1 {{ font-size: 1.4rem; font-weight: 600; }}
  header p  {{ color: #9ca3af; font-size: .85rem; margin-top: 4px; }}
  .wrap {{ max-width: 1300px; margin: 0 auto; padding: 24px 24px 48px; }}

  /* Summary cards */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
            gap: 16px; margin-bottom: 28px; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
           border-radius: var(--radius); padding: 18px 20px;
           box-shadow: var(--shadow); }}
  .card .val {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .card .lbl {{ color: var(--muted); font-size: .8rem; margin-top: 2px; }}
  .card.c-color  .val {{ color: #4f86c6; }}
  .card.h-color  .val {{ color: #9b59b6; }}
  .card.s-color  .val {{ color: #27ae60; }}
  .card.pkg-color .val {{ color: #e07b39; }}

  /* Charts row */
  .charts {{ display: grid; grid-template-columns: 1fr 280px; gap: 20px;
             margin-bottom: 28px; }}
  @media (max-width: 800px) {{ .charts {{ grid-template-columns: 1fr; }} }}
  .chart-card {{ background: var(--card); border: 1px solid var(--border);
                 border-radius: var(--radius); padding: 20px;
                 box-shadow: var(--shadow); }}
  .chart-card h2 {{ font-size: .95rem; font-weight: 600; color: var(--muted);
                    margin-bottom: 14px; text-transform: uppercase;
                    letter-spacing: .05em; }}

  /* Table */
  .tbl-wrap {{ background: var(--card); border: 1px solid var(--border);
               border-radius: var(--radius); box-shadow: var(--shadow);
               overflow: hidden; }}
  .tbl-toolbar {{ display: flex; align-items: center; gap: 12px;
                  padding: 14px 18px; border-bottom: 1px solid var(--border); }}
  .tbl-toolbar h2 {{ font-size: .95rem; font-weight: 600; color: var(--muted);
                     text-transform: uppercase; letter-spacing: .05em; flex: 1; }}
  .tbl-toolbar input {{ border: 1px solid var(--border); border-radius: 6px;
                        padding: 6px 10px; font-size: .85rem; outline: none;
                        width: 200px; }}
  .tbl-toolbar select {{ border: 1px solid var(--border); border-radius: 6px;
                         padding: 6px 10px; font-size: .85rem; outline: none; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: #f0f2f6; padding: 10px 14px; text-align: left;
        font-weight: 600; color: var(--muted); font-size: .78rem;
        text-transform: uppercase; letter-spacing: .04em;
        cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ background: #e5e8ef; }}
  th .sort-icon {{ opacity: .4; margin-left: 4px; }}
  th.sorted .sort-icon {{ opacity: 1; }}
  td {{ padding: 9px 14px; border-top: 1px solid var(--border); vertical-align: middle; }}
  tr:hover td {{ background: #f9fafb; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px;
            font-size: .75rem; font-weight: 500; color: #fff; }}
  .bar-wrap {{ display: flex; align-items: center; gap: 8px; min-width: 140px; }}
  .bar-track {{ flex: 1; background: #e9ecef; border-radius: 4px; height: 8px;
                overflow: hidden; }}
  .bar-fill  {{ height: 100%; border-radius: 4px; transition: width .2s; }}
  .num {{ font-variant-numeric: tabular-nums; text-align: right; }}
  td.num {{ color: var(--text); }}
  .muted {{ color: var(--muted); font-style: italic; }}
  .zero  {{ color: #ccc; }}
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
    <div class="card pkg-color">
      <div class="val">{total_pkgs}</div>
      <div class="lbl">Installed packages</div>
    </div>
    <div class="card c-color">
      <div class="val">{total_c}</div>
      <div class="lbl">C source files</div>
    </div>
    <div class="card h-color">
      <div class="val">{total_h}</div>
      <div class="lbl">Header files</div>
    </div>
    <div class="card s-color">
      <div class="val">{total_S}</div>
      <div class="lbl">Assembly files</div>
    </div>
    <div class="card">
      <div class="val">{total_files}</div>
      <div class="lbl">Total source files</div>
    </div>
    <div class="card">
      <div class="val">{pkgs_with_src}</div>
      <div class="lbl">Packages with source</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts">
    <div class="chart-card">
      <h2>Source files per package</h2>
      <canvas id="barChart" height="320"></canvas>
    </div>
    <div class="chart-card">
      <h2>Package types</h2>
      <canvas id="donutChart"></canvas>
    </div>
  </div>

  <!-- Table -->
  <div class="tbl-wrap">
    <div class="tbl-toolbar">
      <h2>All packages</h2>
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
      <thead>
        <tr>
          <th data-col="name">Package <span class="sort-icon">↕</span></th>
          <th data-col="recipe">Recipe <span class="sort-icon">↕</span></th>
          <th data-col="version">Version <span class="sort-icon">↕</span></th>
          <th data-col="type_label">Type <span class="sort-icon">↕</span></th>
          <th data-col="total" style="text-align:right">Total <span class="sort-icon">↕</span></th>
          <th data-col="c"     style="text-align:right">.c <span class="sort-icon">↕</span></th>
          <th data-col="h"     style="text-align:right">.h <span class="sort-icon">↕</span></th>
          <th data-col="S"     style="text-align:right">.S <span class="sort-icon">↕</span></th>
          <th>Distribution</th>
        </tr>
      </thead>
      <tbody id="tblBody"></tbody>
    </table>
  </div>

</div><!-- /wrap -->

<script>
const DATA = {data_json};
const MAX_TOTAL = Math.max(...DATA.map(d => d.total), 1);

// ── Donut chart ──────────────────────────────────────────────────────────────
const typeCounts = {{}};
DATA.forEach(d => {{ typeCounts[d.type_label] = (typeCounts[d.type_label]||0)+1; }});
new Chart(document.getElementById('donutChart'), {{
  type: 'doughnut',
  data: {{
    labels: Object.keys(typeCounts),
    datasets: [{{ data: Object.values(typeCounts),
      backgroundColor: ['#4f86c6','#e07b39','#6dbf67','#b0b0b0'],
      borderWidth: 2, borderColor: '#fff' }}]
  }},
  options: {{
    cutout: '62%', plugins: {{
      legend: {{ position: 'bottom', labels: {{ font: {{ size: 12 }}, padding: 14 }} }}
    }}
  }}
}});

// ── Bar chart ────────────────────────────────────────────────────────────────
const barData = DATA.filter(d => d.total > 0)
  .sort((a,b) => b.total - a.total);
new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: barData.map(d => d.name),
    datasets: [
      {{ label: '.c',  data: barData.map(d=>d.c), backgroundColor: '#4f86c6', stack:'s' }},
      {{ label: '.h',  data: barData.map(d=>d.h), backgroundColor: '#9b59b6', stack:'s' }},
      {{ label: '.S',  data: barData.map(d=>d.S), backgroundColor: '#27ae60', stack:'s' }},
    ]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{ legend: {{ position: 'top' }}, tooltip: {{ mode: 'index' }} }},
    scales: {{
      x: {{ stacked: true, grid: {{ color: '#f0f2f6' }} }},
      y: {{ stacked: true, ticks: {{ font: {{ size: 11 }} }} }}
    }}
  }}
}});

// ── Table ────────────────────────────────────────────────────────────────────
let sortCol = 'total', sortAsc = false;
let filterText = '', filterType = '';

function fmt(n) {{
  return n === 0
    ? '<span class="zero">0</span>'
    : '<span>' + n.toLocaleString() + '</span>';
}}

function renderTable() {{
  const q = filterText.toLowerCase();
  let rows = DATA.filter(d =>
    (!q || d.name.includes(q) || d.recipe.includes(q)) &&
    (!filterType || d.type_label === filterType)
  );
  rows.sort((a,b) => {{
    let av = a[sortCol], bv = b[sortCol];
    if (typeof av === 'string') av = av.toLowerCase(), bv = bv.toLowerCase();
    return sortAsc ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
  }});

  const tbody = document.getElementById('tblBody');
  tbody.innerHTML = rows.map(d => {{
    const pct = d.total ? Math.round(d.total / MAX_TOTAL * 100) : 0;
    const note = d.no_src
      ? '<span class="muted">scripts/configs only</span>'
      : d.same_as
        ? '<span class="muted">→ ' + d.same_as.replace('SAME_AS_','').replace('.txt','') + '</span>'
        : `<div class="bar-wrap">
             <div class="bar-track"><div class="bar-fill"
               style="width:${{pct}}%;background:${{d.color}}"></div></div>
             <span style="font-size:.78rem;color:#888;min-width:32px;text-align:right">${{d.total}}</span>
           </div>`;
    return `<tr>
      <td><strong>${{d.name}}</strong></td>
      <td style="color:#555">${{d.recipe}}</td>
      <td style="color:#888;font-size:.8rem">${{d.version}}</td>
      <td><span class="badge" style="background:${{d.color}}">${{d.type_label}}</span></td>
      <td class="num">${{fmt(d.total)}}</td>
      <td class="num">${{fmt(d.c)}}</td>
      <td class="num">${{fmt(d.h)}}</td>
      <td class="num">${{fmt(d.S)}}</td>
      <td>${{note}}</td>
    </tr>`;
  }}).join('');

  // Highlight sorted column header
  document.querySelectorAll('th').forEach(th => {{
    th.classList.toggle('sorted', th.dataset.col === sortCol);
    const ic = th.querySelector('.sort-icon');
    if (ic && th.dataset.col === sortCol)
      ic.textContent = sortAsc ? '↑' : '↓';
    else if (ic) ic.textContent = '↕';
  }});
}}

document.querySelectorAll('th[data-col]').forEach(th => {{
  th.addEventListener('click', () => {{
    if (sortCol === th.dataset.col) sortAsc = !sortAsc;
    else {{ sortCol = th.dataset.col; sortAsc = false; }}
    renderTable();
  }});
}});
document.getElementById('search').addEventListener('input', e => {{
  filterText = e.target.value; renderTable();
}});
document.getElementById('typeFilter').addEventListener('change', e => {{
  filterType = e.target.value; renderTable();
}});

renderTable();
</script>
</body>
</html>
"""


def generate_report(
    packages: list,
    out_dir: Path,
    image: str,
    machine: str,
    output: Path,
) -> None:
    rows = collect_data(packages, out_dir)

    total_c     = sum(r["c"]     for r in rows)
    total_h     = sum(r["h"]     for r in rows)
    total_S     = sum(r["S"]     for r in rows)
    total_files = total_c + total_h + total_S
    pkgs_with_src = sum(1 for r in rows if r["total"] > 0)

    html = HTML_TEMPLATE.format(
        image      = image,
        machine    = machine,
        generated  = datetime.now().strftime("%Y-%m-%d %H:%M"),
        total_pkgs = len(rows),
        total_c    = f"{total_c:,}",
        total_h    = f"{total_h:,}",
        total_S    = f"{total_S:,}",
        total_files= f"{total_files:,}",
        pkgs_with_src = pkgs_with_src,
        data_json  = json.dumps(rows, indent=2),
    )

    output.write_text(html)
    print(f"Report written to: {output}")
    print(f"  Packages : {len(rows)}")
    print(f"  .c files : {total_c:,}")
    print(f"  .h files : {total_h:,}")
    print(f"  .S files : {total_S:,}")
    print(f"  Total    : {total_files:,}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML report of collected Yocto sources.",
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
        "-o", "--output",
        metavar="FILE", default="",
        help="Output HTML file (default: <sources-dir>/report.html)",
    )
    args = parser.parse_args()

    build_dir, manifest_path, machine = yu.resolve_common_args(args)
    out_dir = Path(args.sources).resolve() if args.sources else build_dir / "sources"

    if not out_dir.exists():
        raise SystemExit(f"Sources directory not found: {out_dir}\n"
                         "Run collect_sources.py first.")

    output = Path(args.output).resolve() if args.output else out_dir / "report.html"

    # Image name: last component of manifest stem or manifest arg
    image = manifest_path.stem if manifest_path else str(args.manifest)

    packages = yu.discover_packages(manifest_path, build_dir, machine, args.verbose)
    generate_report(packages, out_dir, image, machine, output)


if __name__ == "__main__":
    main()
