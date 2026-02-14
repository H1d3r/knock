from __future__ import annotations

import html
import ipaddress
import json
from datetime import date
from typing import Any, Dict, List, Optional

from ..version import __version__

def _build_html_report(report: Dict[str, Any], rows: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> str:
    """Build a self-contained interactive HTML report.

    Where used:
    - called by `export_report()` after scan rows are normalized.
    Why:
    - keeps report generation deterministic and isolated from DB/runtime code.
    """
    ip_set: set[str] = set()
    domain_set: set[str] = set()
    links: List[Dict[str, str]] = []
    for item in results:
        domain = str(item.get("domain") or "").strip()
        if not domain:
            continue
        domain_set.add(domain)
        for ip in item.get("ip") or []:
            ip_text = str(ip).strip()
            if not ip_text:
                continue
            ip_set.add(ip_text)
            links.append({"ip": ip_text, "domain": domain})

    ips = sorted(ip_set)
    domains = sorted(domain_set)

    results_by_domain = {str(item.get("domain") or ""): item for item in results}
    findings_by_category: Dict[str, Dict[str, Dict[str, str]]] = {}
    table_rows: List[str] = []
    for idx, row in enumerate(rows):
        domain = str(row.get("domain") or "-")
        detail_obj = results_by_domain.get(domain, {})
        issues_for_row = _detail_issues(detail_obj, row)
        for level, issue_text in issues_for_row:
            if str(level).strip().lower() == "ok":
                continue
            issue_key = str(issue_text).strip()
            if not issue_key:
                continue
            category_key = _finding_category(issue_key)
            findings_by_category.setdefault(category_key, {})
            findings_by_category[category_key].setdefault(issue_key, {})
            if domain not in findings_by_category[category_key][issue_key]:
                findings_by_category[category_key][issue_key][domain] = _finding_evidence_for_issue(
                    issue_key, detail_obj, row
                )
        detail_html = _render_human_detail(detail_obj, row, issues=issues_for_row)
        row_id = f"detail-row-{idx}"
        cert_label = _cert_label(row.get("cert_valid"))
        status_label = _status_from_issues(row, issues_for_row)
        http_status = row.get("http_status")
        https_status = row.get("https_status")
        table_rows.append(
            "<tr class='result-row' data-target='{rid}'>"
            f"<td>{html.escape(domain)}</td>"
            f"<td>{_render_ip_column(row.get('ip'))}</td>"
            f"<td>{_html_status_badge(http_status)}</td>"
            f"<td class='server-col'>{_render_server_cell(row.get('http_server'), row.get('http_server_status'), row.get('http_server_version'), row.get('http_server_latest'))}</td>"
            f"<td>{_html_status_badge(https_status)}</td>"
            f"<td class='server-col'>{_render_server_cell(row.get('https_server'), row.get('https_server_status'), row.get('https_server_version'), row.get('https_server_latest'))}</td>"
            f"<td>{_html_state_badge(cert_label, cert_label)}</td>"
            f"<td>{html.escape(str(row.get('cert_expiry') or '-'))}</td>"
            f"<td>{_render_tls_column(row.get('tls_versions'))}</td>"
            f"<td>{_html_state_badge(status_label, status_label)}</td>"
            "</tr>"
            "<tr id='{rid}' class='detail-row' style='display:none'>"
            "<td colspan='10'>{detail}</td>"
            "</tr>".format(rid=row_id, detail=detail_html)
        )

    finding_blocks: List[str] = []
    if findings_by_category:
        def _category_domain_count(issue_map: Dict[str, Dict[str, str]]) -> int:
            uniq: set[str] = set()
            for affected in issue_map.values():
                uniq.update(affected.keys())
            return len(uniq)

        ordered_categories = sorted(
            findings_by_category.items(),
            key=lambda item: (_category_domain_count(item[1]), len(item[1])),
            reverse=True,
        )

        for category_name, issue_map in ordered_categories:
            issue_sections: List[str] = []
            ordered_issues = sorted(issue_map.items(), key=lambda item: len(item[1]), reverse=True)
            for issue_text, affected in ordered_issues:
                domains_sorted = sorted(affected.items(), key=lambda item: item[0])
                rows_html = "".join(
                    "<tr>"
                    f"<td><code>{html.escape(domain_name)}</code></td>"
                    f"<td>{html.escape(evidence)}</td>"
                    "</tr>"
                    for domain_name, evidence in domains_sorted
                )
                issue_sections.append(
                    "<div class='finding-issue'>"
                    f"<div class='finding-issue-title'>{html.escape(issue_text)}"
                    f" <span class='finding-issue-count'>{len(domains_sorted)} domains</span></div>"
                    "<table class='finding-table'>"
                    "<thead><tr><th>Domain</th><th>Evidence</th></tr></thead>"
                    f"<tbody>{rows_html}</tbody>"
                    "</table>"
                    "</div>"
                )

            finding_blocks.append(
                "<details class='finding-block'>"
                "<summary>"
                f"<span class='finding-title'>{html.escape(category_name)}</span>"
                f"<span class='finding-count'>{_category_domain_count(issue_map)} domains, {len(issue_map)} issues</span>"
                "</summary>"
                "<div class='finding-body'>"
                f"{''.join(issue_sections)}"
                "</div>"
                "</details>"
            )
    findings_html = "".join(finding_blocks) if finding_blocks else "<p class='muted'>No critical confirmed issue detected.</p>"

    payload = {
        "ips": ips,
        "domains": domains,
        "links": links,
    }
    payload_json = _safe_json_for_script(payload)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'" />
  <title>Knockpy v{html.escape(str(__version__))} - Report #{html.escape(str(report.get("id")))}</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --card: #ffffff;
      --text: #0b1727;
      --muted: #546173;
      --line: #dbe5f0;
      --accent: #0b6cff;
      --ip: #e67e22;
      --dom: #1e90ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      color: var(--text);
      background: linear-gradient(180deg, #eef5ff 0%, var(--bg) 40%, #f8fafc 100%);
    }}
    .wrap {{ width: 100%; max-width: none; margin: 0; padding: clamp(10px, 1.8vw, 26px); }}
    .head, .panel {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 8px 20px rgba(22, 38, 61, 0.06);
    }}
    .head {{ padding: 18px 20px; margin-bottom: 18px; }}
    .head-title {{
      margin: 0 0 10px;
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .head-title .right {{
      margin-left: auto;
      white-space: nowrap;
    }}
    .head h2 .ver {{
      font-size: 0.66em;
      font-weight: 500;
      vertical-align: top;
      margin-left: 2px;
    }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px 16px; color: var(--muted); }}
    .meta b {{ color: var(--text); }}
    .panel {{ padding: 14px; margin-bottom: 18px; }}
    details.panel > summary {{
      cursor: pointer;
      font-weight: 600;
      margin: 0;
    }}
    .correlation-content {{ display: none; }}
    details.panel[open] .correlation-content {{ display: block; }}
    .toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; align-items: center; }}
    .toolbar input {{
      border: 1px solid var(--line);
      background: #fff;
      border-radius: 8px;
      padding: 7px 10px;
      min-width: 220px;
    }}
    .toolbar button {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 7px 10px;
      cursor: pointer;
    }}
    #graph {{
      width: 100%;
      height: min(68vh, 760px);
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      touch-action: none;
    }}
    .legend {{ display: flex; gap: 18px; color: var(--muted); margin: 8px 0 0; font-size: 13px; }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }}
    .table-wrap {{ overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; background: #fff; table-layout: fixed; }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 8px;
      text-align: left;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      vertical-align: top;
    }}
    th {{ position: sticky; top: 0; background: #f7fbff; }}
    thead .filter-row th {{
      top: 37px;
      background: #f9fcff;
      padding-top: 6px;
      padding-bottom: 6px;
    }}
    .table-filter {{
      width: 100%;
      min-width: 90px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 5px 7px;
      font-size: 12px;
      color: var(--text);
      background: #fff;
    }}
    .ip-col {{
      display: inline-flex;
      flex-direction: column;
      gap: 2px;
      max-width: 100%;
    }}
    .ip-col code {{
      font-size: 12px;
      white-space: nowrap;
    }}
    .muted {{ color: var(--muted); }}
    .result-row {{ cursor: pointer; }}
    .result-row:hover {{ background: #f8fbff; }}
    .detail-row td {{ background: #fbfdff; }}
    .detail-box {{
      padding: 10px 8px;
      white-space: normal;
    }}
    .detail-section {{
      margin-bottom: 10px;
    }}
    .detail-section:last-child {{
      margin-bottom: 0;
    }}
    .detail-title {{
      font-size: 12px;
      font-weight: 700;
      color: #2a3a4f;
      margin: 0 0 6px;
      text-transform: uppercase;
      letter-spacing: 0.02em;
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 8px;
    }}
    .detail-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 7px 9px;
      background: #fff;
    }}
    .detail-k {{
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 3px;
    }}
    .detail-v {{
      font-size: 13px;
      color: var(--text);
      word-break: break-word;
    }}
    .pair-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(120px, 1fr));
      gap: 8px;
    }}
    .pair-box {{
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 6px 8px;
      background: #fcfdff;
    }}
    .pair-k {{
      font-size: 11px;
      color: var(--muted);
      margin-bottom: 4px;
    }}
    .pair-v {{
      font-size: 13px;
      color: var(--text);
    }}
    .issues-list {{
      margin: 0;
      padding-left: 18px;
    }}
    .issue-ok {{
      color: #0f5f2f;
    }}
    .issue-warn {{
      color: #8a5300;
    }}
    .issue-bad {{
      color: #8f1d1d;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid transparent;
      font-size: 12px;
      font-weight: 600;
      line-height: 1.4;
      white-space: nowrap;
    }}
    .badge-ok, .badge-valid, .badge-http-good {{
      color: #0f5f2f;
      background: #e9f9ef;
      border-color: #bfe9cd;
    }}
    .badge-warning, .badge-http-redirect {{
      color: #8a5300;
      background: #fff5e8;
      border-color: #f4dbb3;
    }}
    .badge-invalid, .badge-http-bad {{
      color: #8f1d1d;
      background: #ffeded;
      border-color: #f2c2c2;
    }}
    .badge-dns-only, .badge-na {{
      color: #5a4f88;
      background: #f1edff;
      border-color: #ddd3ff;
    }}
    .server-text-warn {{
      color: #8a5300;
      font-weight: 600;
    }}
    .server-text-bad {{
      color: #8f1d1d;
      font-weight: 600;
    }}
    .server-col {{
      max-width: 0;
    }}
    .finding-block {{
      border: 1px solid var(--line);
      border-radius: 10px;
      margin-bottom: 10px;
      background: #fff;
    }}
    .finding-block > summary {{
      cursor: pointer;
      list-style: none;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 12px;
      font-weight: 600;
    }}
    .finding-block > summary::-webkit-details-marker {{
      display: none;
    }}
    .finding-title {{
      color: #8f1d1d;
    }}
    .finding-count {{
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .finding-body {{
      border-top: 1px solid var(--line);
      padding: 8px 12px 12px;
    }}
    .finding-table {{
      width: 100%;
      table-layout: fixed;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .finding-table th, .finding-table td {{
      border-bottom: 1px solid var(--line);
      padding: 7px 8px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .finding-table th {{
      background: #f9fcff;
      position: static;
    }}
    .finding-issue {{
      margin-bottom: 12px;
    }}
    .finding-issue:last-child {{
      margin-bottom: 0;
    }}
    .finding-issue-title {{
      font-weight: 600;
      color: #253448;
      margin: 0 0 6px;
    }}
    .finding-issue-count {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 500;
    }}
    #selection {{
      margin-top: 8px;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f9fcff;
      color: var(--muted);
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="head">
      <h2 class="head-title">
        <span>Report #{html.escape(str(report.get("id")))}</span>
        <span class="right">Knockpy <span class="ver">v{html.escape(str(__version__))}</span></span>
      </h2>
      <div class="meta">
        <div><b>Created:</b> {html.escape(str(report.get("created_at")))}</div>
        <div><b>Target:</b> {html.escape(str(report.get("target")))}</div>
        <div><b>Mode:</b> {html.escape(str(report.get("mode")))}</div>
        <div><b>Results:</b> {html.escape(str(report.get("result_count")))}</div>
      </div>
    </section>

    <section class="panel">
      <h3 style="margin: 0 0 8px">Findings Summary</h3>
      {findings_html}
    </section>

    <details id="ip-domain-correlation" class="panel">
      <summary>IP ↔ Domain Correlation</summary>
      <div class="correlation-content">
        <div class="toolbar">
          <input id="filter" placeholder="Filter by IP or domain..." />
          <button id="zoomIn">Zoom +</button>
          <button id="zoomOut">Zoom -</button>
          <button id="reset">Reset</button>
        </div>
        <svg id="graph" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid meet"></svg>
        <div class="legend">
          <span><span class="dot" style="background: var(--ip)"></span>IP nodes</span>
          <span><span class="dot" style="background: var(--dom)"></span>Domain nodes</span>
        </div>
        <div id="selection">Click a domain node to see associated IPs.</div>
      </div>
    </details>

    <section class="panel">
      <h3 style="margin: 0 0 8px">Results Table</h3>
      <div class="table-wrap">
        <table>
          <colgroup>
            <col style="width:18%">
            <col style="width:16%">
            <col style="width:6%">
            <col style="width:14%">
            <col style="width:6%">
            <col style="width:14%">
            <col style="width:7%">
            <col style="width:9%">
            <col style="width:5%">
            <col style="width:5%">
          </colgroup>
          <thead>
            <tr>
              <th>Domain</th><th>IP</th><th>HTTP</th><th>HTTP Server</th><th>HTTPS</th><th>HTTPS Server</th><th>Cert</th><th>Expiry</th><th>TLS</th><th>Status</th>
            </tr>
            <tr class="filter-row">
              <th><input class="table-filter" data-col="0" placeholder="Filter domain" /></th>
              <th><input class="table-filter" data-col="1" placeholder="Filter IP" /></th>
              <th><input class="table-filter" data-col="2" placeholder="Filter HTTP" /></th>
              <th><input class="table-filter" data-col="3" placeholder="Filter HTTP server" /></th>
              <th><input class="table-filter" data-col="4" placeholder="Filter HTTPS" /></th>
              <th><input class="table-filter" data-col="5" placeholder="Filter HTTPS server" /></th>
              <th><input class="table-filter" data-col="6" placeholder="Filter cert" /></th>
              <th><input class="table-filter" data-col="7" placeholder="Filter expiry" /></th>
              <th><input class="table-filter" data-col="8" placeholder="Filter TLS" /></th>
              <th><input class="table-filter" data-col="9" placeholder="Filter status" /></th>
            </tr>
          </thead>
          <tbody>
            {"".join(table_rows) if table_rows else '<tr><td colspan="10" class="muted">No rows</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const correlationPanel = document.getElementById('ip-domain-correlation');
    if (correlationPanel) correlationPanel.open = false;

    const data = {payload_json};
    const svg = document.getElementById('graph');
    const selection = document.getElementById('selection');
    const domainToIps = data.links.reduce((acc, link) => {{
      if (!acc[link.domain]) acc[link.domain] = [];
      if (!acc[link.domain].includes(link.ip)) acc[link.domain].push(link.ip);
      return acc;
    }}, {{}});
    const NS = 'http://www.w3.org/2000/svg';
    const group = document.createElementNS(NS, 'g');
    svg.appendChild(group);

    const width = 1200;
    const topPad = 40;
    const bottomPad = 40;
    const leftX = 190;
    const rightX = 1010;
    const rows = Math.max(data.ips.length, data.domains.length, 1);
    const rowGap = Math.max(20, Math.floor((800 - topPad - bottomPad) / rows));

    const ipPos = Object.fromEntries(data.ips.map((ip, i) => [ip, {{ x: leftX, y: topPad + i * rowGap }}]));
    const domPos = Object.fromEntries(data.domains.map((d, i) => [d, {{ x: rightX, y: topPad + i * rowGap }}]));

    function make(tag, attrs = {{}}, text = null) {{
      const el = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
      if (text !== null) el.textContent = text;
      return el;
    }}

    function draw(filterTerm = '') {{
      group.innerHTML = '';
      const term = filterTerm.trim().toLowerCase();

      for (const link of data.links) {{
        const ok = !term || link.ip.toLowerCase().includes(term) || link.domain.toLowerCase().includes(term);
        const a = ipPos[link.ip], b = domPos[link.domain];
        if (!a || !b) continue;
        group.appendChild(make('line', {{
          x1: a.x, y1: a.y, x2: b.x, y2: b.y,
          stroke: ok ? '#98aec7' : '#e8edf4',
          'stroke-width': ok ? 1.3 : 0.6,
          opacity: ok ? 0.9 : 0.25
        }}));
      }}

      for (const ip of data.ips) {{
        const p = ipPos[ip];
        const ok = !term || ip.toLowerCase().includes(term) || data.links.some(l => l.ip === ip && l.domain.toLowerCase().includes(term));
        group.appendChild(make('circle', {{
          cx: p.x, cy: p.y, r: 5.2, fill: ok ? '#e67e22' : '#f2d9bf', opacity: ok ? 1 : 0.45
        }}));
        group.appendChild(make('text', {{
          x: p.x - 10, y: p.y + 4, 'text-anchor': 'end', 'font-size': 12, fill: ok ? '#253448' : '#9eaabc'
        }}, ip));
      }}

      for (const d of data.domains) {{
        const p = domPos[d];
        const ok = !term || d.toLowerCase().includes(term) || data.links.some(l => l.domain === d && l.ip.toLowerCase().includes(term));
        const circle = make('circle', {{
          cx: p.x, cy: p.y, r: 5.2, fill: ok ? '#1e90ff' : '#cae4ff', opacity: ok ? 1 : 0.45
        }});
        const text = make('text', {{
          x: p.x + 10, y: p.y + 4, 'text-anchor': 'start', 'font-size': 12, fill: ok ? '#253448' : '#9eaabc'
        }}, d);
        const onPick = () => {{
          const ips = (domainToIps[d] || []).join(', ') || '(none)';
          selection.textContent = `Domain: ${{d}} | IPs: ${{ips}}`;
        }};
        circle.addEventListener('click', onPick);
        text.style.cursor = 'pointer';
        text.addEventListener('click', onPick);
        group.appendChild(circle);
        group.appendChild(text);
      }}
    }}

    let scale = 1.0, tx = 0, ty = 0;
    let dragging = false, lastX = 0, lastY = 0;
    function applyTransform() {{ group.setAttribute('transform', `translate(${{tx}},${{ty}}) scale(${{scale}})`); }}
    function zoom(delta) {{
      scale = Math.min(3.5, Math.max(0.35, scale + delta));
      applyTransform();
    }}

    svg.addEventListener('wheel', (e) => {{
      e.preventDefault();
      zoom(e.deltaY < 0 ? 0.1 : -0.1);
    }}, {{ passive: false }});

    svg.addEventListener('mousedown', (e) => {{ dragging = true; lastX = e.clientX; lastY = e.clientY; }});
    window.addEventListener('mouseup', () => {{ dragging = false; }});
    window.addEventListener('mousemove', (e) => {{
      if (!dragging) return;
      tx += (e.clientX - lastX);
      ty += (e.clientY - lastY);
      lastX = e.clientX; lastY = e.clientY;
      applyTransform();
    }});

    document.getElementById('zoomIn').onclick = () => zoom(0.12);
    document.getElementById('zoomOut').onclick = () => zoom(-0.12);
    document.getElementById('reset').onclick = () => {{ scale = 1; tx = 0; ty = 0; applyTransform(); }};
    document.getElementById('filter').addEventListener('input', (e) => draw(e.target.value));

    document.querySelectorAll('.result-row').forEach((row) => {{
      row.addEventListener('click', () => {{
        const targetId = row.getAttribute('data-target');
        if (!targetId) return;
        const detailRow = document.getElementById(targetId);
        if (!detailRow) return;
        const open = detailRow.style.display !== 'none';
        detailRow.style.display = open ? 'none' : '';
      }});
    }});

    function applyTableFilters() {{
      const filters = Array.from(document.querySelectorAll('.table-filter')).map((input) => {{
        const col = Number(input.getAttribute('data-col') || -1);
        const value = (input.value || '').trim().toLowerCase();
        return {{ col, value }};
      }});

      document.querySelectorAll('.result-row').forEach((row) => {{
        let match = true;
        for (const f of filters) {{
          if (!f.value || f.col < 0) continue;
          const cell = row.children[f.col];
          const raw = cell ? (cell.textContent || '').trim().toLowerCase() : '';
          if (!raw.includes(f.value)) {{
            match = false;
            break;
          }}
        }}
        row.style.display = match ? '' : 'none';
        const targetId = row.getAttribute('data-target');
        if (!targetId) return;
        const detailRow = document.getElementById(targetId);
        if (!detailRow) return;
        if (!match) {{
          detailRow.style.display = 'none';
          detailRow.setAttribute('data-allowed', '0');
        }} else {{
          detailRow.setAttribute('data-allowed', '1');
        }}
      }});
    }}

    document.querySelectorAll('.table-filter').forEach((input) => {{
      input.addEventListener('input', applyTableFilters);
    }});

    draw('');
    applyTransform();
  </script>
</body>
</html>
"""


def _fmt_detail_value(value: Any) -> str:
    if value in (None, "", []):
        return "-"
    if isinstance(value, list):
        if not value:
            return "-"
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        if not value:
            return "-"
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    return str(value)


def _safe_json_for_script(data: Any) -> str:
    # Prevent closing the script tag and HTML entity parsing inside inline JS.
    raw = json.dumps(data, ensure_ascii=False)
    return (
        raw.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _render_ip_column(value: Any) -> str:
    if isinstance(value, list):
        ips = [str(ip).strip() for ip in value if str(ip).strip()]
    else:
        text = str(value or "").strip()
        ips = [text] if text else []

    if not ips:
        return "<span class='badge badge-na'>-</span>"
    if len(ips) == 1:
        return f"<code>{html.escape(ips[0])}</code>"

    lines = "".join(f"<code>{html.escape(ip)}</code>" for ip in ips)
    return f"<div class='ip-col'>{lines}</div>"


def _render_tls_column(value: Any) -> str:
    versions: List[str] = []
    if isinstance(value, list):
        versions = [str(v).strip() for v in value if str(v).strip()]
    else:
        text = str(value or "").strip()
        if text:
            if "," in text:
                versions = [part.strip() for part in text.split(",") if part.strip()]
            else:
                versions = [text]

    if not versions:
        return "<span class='badge badge-na'>-</span>"
    if len(versions) == 1:
        return f"<code>{html.escape(versions[0])}</code>"

    lines = "".join(f"<code>{html.escape(v)}</code>" for v in versions)
    return f"<div class='ip-col'>{lines}</div>"


def _badge_class_for_state(text: str) -> str:
    value = (text or "").strip().lower()
    if value in {"ok", "valid"}:
        return f"badge-{value}"
    if value in {"warning", "invalid", "dns-only"}:
        return f"badge-{value}"
    if value in {"-", "none", ""}:
        return "badge-na"
    return "badge-na"


def _html_state_badge(value: Any, label: Optional[str] = None) -> str:
    text = "-" if value in (None, "") else str(label if label is not None else value)
    return f"<span class='badge {_badge_class_for_state(text)}'>{html.escape(text)}</span>"


def _html_status_badge(value: Any) -> str:
    if value in (None, ""):
        return _html_state_badge("-")
    try:
        code = int(value)
    except Exception:
        return _html_state_badge(str(value))
    if code >= 400:
        cls = "badge-http-bad"
    elif code >= 300:
        cls = "badge-http-redirect"
    else:
        cls = "badge-http-good"
    return f"<span class='badge {cls}'>{code}</span>"


def _render_server_cell(server: Any, status: Any, version: Any, latest: Any) -> str:
    server_text = html.escape(str(server or "-"))
    status_value = str(status or "").strip().lower()
    if status_value == "outdated":
        return f"<span class='server-text-bad'>{server_text}</span>"
    if status_value in {"advisory", "newer-than-reference"}:
        return f"<span class='server-text-warn'>{server_text}</span>"
    return server_text


def _detail_value_html(key: str, value: Any) -> str:
    if key in {"HTTP Status + Body Bytes", "HTTPS Status + Body Bytes"} and isinstance(value, (list, tuple)) and len(value) == 2:
        status_html = _html_status_badge(value[0])
        body_text = html.escape(_fmt_detail_value(value[1]))
        return (
            "<div class='pair-grid'>"
            "<div class='pair-box'>"
            "<div class='pair-k'>Status</div>"
            f"<div class='pair-v'>{status_html}</div>"
            "</div>"
            "<div class='pair-box'>"
            "<div class='pair-k'>Body Bytes</div>"
            f"<div class='pair-v'>{body_text}</div>"
            "</div>"
            "</div>"
        )
    if key in {"Status", "Certificate"}:
        return _html_state_badge(value)
    if key in {"HTTP Status", "HTTPS Status"}:
        return _html_status_badge(value)
    return html.escape(_fmt_detail_value(value))


def _render_human_detail(
    detail_obj: Dict[str, Any],
    row: Dict[str, Any],
    issues: Optional[List[tuple[str, str]]] = None,
) -> str:
    """Render expandable per-domain details for the HTML report table rows."""
    http = detail_obj.get("http") or []
    https = detail_obj.get("https") or []
    cert = detail_obj.get("cert") or []
    takeover = detail_obj.get("takeover") or {}
    notes = detail_obj.get("scan_notes") or []
    all_ips = detail_obj.get("ip") or row.get("ip")
    clean_notes = [str(n).strip() for n in notes if str(n).strip()]

    overview_pairs: List[tuple[str, Any]] = []
    if clean_notes:
        overview_pairs.append(("Notes", clean_notes))

    sections: List[tuple[str, List[tuple[str, Any]]]] = [
        (
            "Overview",
            overview_pairs,
        ),
        (
            "HTTP",
            [
                ("HTTP Status", http[0] if len(http) > 0 else row.get("http_status")),
                ("HTTP Body Bytes", http[3] if len(http) > 3 else None),
                ("HTTP Redirect", http[1] if len(http) > 1 else row.get("http_redirect")),
                ("HTTP App Redirect", http[4] if len(http) > 4 else None),
            ],
        ),
        (
            "HTTPS",
            [
                ("HTTPS Status", https[0] if len(https) > 0 else row.get("https_status")),
                ("HTTPS Body Bytes", https[3] if len(https) > 3 else None),
                ("HTTPS Redirect", https[1] if len(https) > 1 else row.get("https_redirect")),
                ("HTTPS App Redirect", https[4] if len(https) > 4 else None),
            ],
        ),
        (
            "Certificate / TLS",
            [
                ("Certificate", _cert_label(cert[0] if len(cert) > 0 else row.get("cert_valid"))),
                ("Certificate CN", cert[2] if len(cert) > 2 else row.get("cert_cn")),
            ],
        ),
        (
            "Takeover",
            [
                ("Candidate", "yes" if takeover else "no"),
                ("Status", takeover.get("status") if takeover else "-"),
                ("Provider", takeover.get("provider") if takeover else "-"),
                ("CNAME", takeover.get("cname") if takeover else "-"),
                ("Matched Fingerprints", takeover.get("matched_fingerprints") if takeover else []),
            ],
        ),
    ]
    issues = issues if issues is not None else _detail_issues(detail_obj, row)
    domain_text = str(row.get("domain") or "").strip()
    verbose_cmd = f"knockpy -d {domain_text} --verbose" if domain_text else None

    parts = ["<div class='detail-box'>"]
    for section_title, pairs in sections:
        parts.append(
            f"<div class='detail-section'><div class='detail-title'>{html.escape(section_title)}</div><div class='detail-grid'>"
        )
        for key, value in pairs:
            label = html.escape(str(key))
            rendered = _detail_value_html(str(key), value)
            parts.append(
                f"<div class='detail-item'><div class='detail-k'>{label}</div><div class='detail-v'>{rendered}</div></div>"
            )
        parts.append("</div></div>")
    parts.append("<div class='detail-section'><div class='detail-title'>Issues Found</div><div class='detail-grid'>")
    parts.append("<div class='detail-item' style='grid-column:1 / -1'>")
    parts.append("<ul class='issues-list'>")
    for level, text in issues:
        cls = "issue-ok" if level == "ok" else ("issue-warn" if level == "warn" else "issue-bad")
        parts.append(f"<li class='{cls}'>{html.escape(text)}</li>")
    parts.append("</ul></div></div>")
    if verbose_cmd:
        parts.append(
            "<div class='detail-item' style='background:#f9fcff;'>"
            "<div class='detail-k'>Verbose Tip</div>"
            "<div class='detail-v'>Use <code>--verbose</code> for deep diagnostics on this subdomain "
            "(without <code>--recon</code>/<code>--bruteforce</code>): "
            f"<code>{html.escape(verbose_cmd)}</code></div>"
            "</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def _cert_label(value: Any) -> str:
    if value is True:
        return "valid"
    if value is False:
        return "invalid"
    return "-"


def _status_from_issues(row: Dict[str, Any], issues: List[tuple[str, str]]) -> str:
    has_http = row.get("http_status") is not None
    has_https = row.get("https_status") is not None
    if not has_http and not has_https:
        return "dns-only"
    for level, _ in issues:
        if str(level).strip().lower() != "ok":
            return "warning"
    return "ok"


def _only_ipv4_list(values: List[Any]) -> List[str]:
    ipv4: List[str] = []
    for value in values:
        ip = str(value).strip()
        if not ip:
            continue
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version == 4:
            ipv4.append(ip)
    return ipv4


def _dns_name_matches(host: str, pattern: str) -> bool:
    host = host.strip(".").lower()
    pattern = pattern.strip(".").lower()
    if not host or not pattern:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        # Wildcard matches exactly one label: *.example.com -> a.example.com
        suffix = pattern[2:]
        if not suffix:
            return False
        if host == suffix:
            return False
        if host.endswith("." + suffix):
            left = host[: -(len(suffix) + 1)]
            return "." not in left
    return False


def _hostname_matches_cert(domain: str, cn: Optional[str], sans: Optional[List[str]]) -> Optional[bool]:
    host = str(domain or "").strip().lower()
    if not host:
        return None
    candidates: List[str] = []
    if isinstance(cn, str) and cn.strip():
        candidates.append(cn.strip())
    if isinstance(sans, list):
        candidates.extend(str(v).strip() for v in sans if str(v).strip())
    if not candidates:
        return None
    for pattern in candidates:
        try:
            if _dns_name_matches(host, pattern):
                return True
        except Exception:
            continue
    return False


def _detail_issues(detail_obj: Dict[str, Any], row: Dict[str, Any]) -> List[tuple[str, str]]:
    """Aggregate protocol/certificate/security issues for one row.

    The returned list drives both:
    - `Issues Found` details in expanded row
    - top-level status badge (`ok`/`warning`/`dns-only`)
    """
    http = detail_obj.get("http") or []
    https = detail_obj.get("https") or []
    cert = detail_obj.get("cert") or []
    takeover = detail_obj.get("takeover") or {}

    http_status = http[0] if len(http) > 0 else row.get("http_status")
    https_status = https[0] if len(https) > 0 else row.get("https_status")
    http_app_redirect = http[4] if len(http) > 4 else None
    https_app_redirect = https[4] if len(https) > 4 else None

    cert_valid = cert[0] if len(cert) > 0 else row.get("cert_valid")
    cert_expiry = cert[1] if len(cert) > 1 else row.get("cert_expiry")
    cert_cn = cert[2] if len(cert) > 2 else row.get("cert_cn")
    tls_versions = cert[3] if len(cert) > 3 and cert[3] else row.get("tls_versions")
    tls_verbose = (detail_obj.get("verbose") or {}).get("tls") or {}
    cert_sans = tls_verbose.get("san") if isinstance(tls_verbose, dict) else None

    def _as_int(value: Any) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except Exception:
            return None

    http_code = _as_int(http_status)
    https_code = _as_int(https_status)
    https_ok = https_code is not None and 200 <= https_code < 400

    issues: List[tuple[str, str]] = []
    seen_msgs: set[str] = set()
    weak_tls_best: set[str] = set()
    weak_tls_msg: Optional[str] = None

    def _collect_weak_tls_from_text(text: str) -> set[str]:
        msg_l = str(text or "").strip().lower()
        if "weak tls versions detected" not in msg_l:
            return set()
        out: set[str] = set()
        for item in ("TLS 1.0", "TLS 1.1"):
            if item.lower() in msg_l:
                out.add(item)
        if "sslv" in msg_l:
            # Keep coarse SSLv marker if present in message.
            out.add("SSLv*")
        return out

    def _add_issue(level: str, text: str) -> None:
        msg = str(text).strip()
        if not msg:
            return
        weak_set = _collect_weak_tls_from_text(msg)
        if weak_set:
            nonlocal weak_tls_best, weak_tls_msg
            if weak_set.issubset(weak_tls_best):
                return
            weak_tls_best |= weak_set
            ordered = [v for v in ("SSLv*", "TLS 1.0", "TLS 1.1") if v in weak_tls_best]
            weak_tls_msg = f"Weak TLS versions detected: {', '.join(ordered)}."
            # Replace prior weak-tls messages so only the most complete one remains.
            issues[:] = [(lv, m) for lv, m in issues if "weak tls versions detected" not in m.lower()]
            seen_msgs_copy = {m for _, m in issues}
            seen_msgs.clear()
            seen_msgs.update(seen_msgs_copy)
            if weak_tls_msg in seen_msgs:
                return
            seen_msgs.add(weak_tls_msg)
            issues.append((level, weak_tls_msg))
            return
        if msg in seen_msgs:
            return
        seen_msgs.add(msg)
        issues.append((level, msg))

    if http_code is None and https_code is None:
        _add_issue("warn", "No HTTP/HTTPS response received. Check DNS, firewall, or timeout.")
    # Treat common application-level denials/misses as informational (not warning):
    # - 403: often expected access control
    # - 404: often expected missing route
    soft_http_statuses = {403, 404}
    soft_https_statuses = {403, 404}
    if http_code is not None and http_code >= 400 and http_code not in soft_http_statuses and https_ok:
        _add_issue("warn", f"HTTP returned {http_code}, but HTTPS is reachable. Browser may auto-upgrade to HTTPS.")
    if http_code is not None and http_code >= 400 and http_code not in soft_http_statuses and not https_ok:
        _add_issue("warn", f"HTTP returned error status {http_code}.")
    if https_code is not None and https_code >= 400 and https_code not in soft_https_statuses:
        _add_issue("warn", f"HTTPS returned error status {https_code}.")
    if http_app_redirect:
        _add_issue("warn", f"HTTP application-level redirect detected: {http_app_redirect}")
    if https_app_redirect:
        _add_issue("warn", f"HTTPS application-level redirect detected: {https_app_redirect}")
    if https_code is None:
        _add_issue("warn", "HTTPS endpoint not reachable or not responding.")

    takeover_status = str(takeover.get("status") or "").strip().lower()
    takeover_provider = str(takeover.get("provider") or "unknown")
    takeover_cname = str(takeover.get("cname") or "-")
    if takeover_status == "likely":
        _add_issue("bad", f"Possible subdomain takeover likely ({takeover_provider}) via CNAME {takeover_cname}.")
    elif takeover_status == "possible":
        _add_issue("warn", f"Possible subdomain takeover to verify ({takeover_provider}) via CNAME {takeover_cname}.")

    expiry_expired = False
    if cert_expiry:
        try:
            expiry_expired = date.fromisoformat(str(cert_expiry)) < date.today()
        except Exception:
            expiry_expired = False

    weak_tls: List[str] = []
    if isinstance(tls_versions, list):
        weak_tls = [v for v in tls_versions if isinstance(v, str) and (v.startswith("SSLv") or v in ("TLS 1.0", "TLS 1.1"))]
    elif isinstance(tls_versions, str):
        weak_tls = [v.strip() for v in tls_versions.split(",") if v.strip() in ("TLS 1.0", "TLS 1.1") or v.strip().startswith("SSLv")]

    domain_name = str(row.get("domain") or detail_obj.get("domain") or "").strip().lower()
    cn_match = _hostname_matches_cert(domain_name, str(cert_cn) if cert_cn else None, cert_sans if isinstance(cert_sans, list) else None)
    cn_mismatch_probable = cert_valid is False and cn_match is False
    if cert_valid is False:
        _add_issue("bad", "Certificate validation failed.")
        if cn_mismatch_probable and cert_cn:
            _add_issue("bad", f"Likely hostname mismatch: certificate CN/SAN ({cert_cn}) does not match domain.")
        elif not expiry_expired and not weak_tls:
            _add_issue("bad", "Certificate trust/chain verification failed (not an obvious CN mismatch).")
        if expiry_expired:
            _add_issue("bad", f"Certificate expired on {cert_expiry}.")
    if weak_tls:
        _add_issue("bad", f"Weak TLS versions detected: {', '.join(weak_tls)}.")
    elif cert_valid is None and https_code is not None:
        _add_issue("warn", "Certificate check unavailable despite HTTPS response.")

    # Web server version checks (from export row enrichment).
    for proto in ("http", "https"):
        status = str(row.get(f"{proto}_server_status") or "").strip().lower()
        version = row.get(f"{proto}_server_version")
        latest = row.get(f"{proto}_server_latest")
        if status == "outdated":
            _add_issue("bad", f"{proto.upper()} server potentially outdated ({version} < {latest}).")
        elif status == "advisory":
            _add_issue("warn", f"{proto.upper()} server version check is advisory; verify patch level at OS/vendor level.")

    # Include all warning/critical findings from verbose security checks when available.
    verbose = detail_obj.get("verbose") or {}
    security = verbose.get("security") or {}
    checks = security.get("checks") or {}
    if isinstance(checks, dict):
        for check_name, check in checks.items():
            if not isinstance(check, dict):
                continue
            level = str(check.get("level") or "").strip().lower()
            summary = str(check.get("summary") or "").strip()
            if not summary:
                continue
            prefix = check_name.replace("_", " ").strip().capitalize()
            if level in {"warning", "critical"}:
                _add_issue("warn" if level == "warning" else "bad", f"{prefix}: {summary}")

    # Surface scan-level notes if they describe a problem.
    # AXFR note handling:
    # - "allowed" is a real issue (zone transfer exposed)
    # - failed/refused/denied/closed are informational and should not raise warnings.
    for note in detail_obj.get("scan_notes") or []:
        text = str(note).strip()
        if not text:
            continue
        low = text.lower()
        if "axfr on root domain:" in low:
            if "allowed" in low:
                _add_issue("bad", text)
            continue
        if any(x in low for x in ("failed", "error", "timeout", "allowed", "warning", "invalid", "outdated")):
            _add_issue("warn", text)

    # Report only critical and high-confidence findings.
    critical_issues = [item for item in issues if str(item[0]).strip().lower() == "bad"]
    if critical_issues:
        return critical_issues
    return [("ok", "No critical confirmed issue detected.")]


def _finding_evidence_for_issue(issue_text: str, detail_obj: Dict[str, Any], row: Dict[str, Any]) -> str:
    """Build issue-specific evidence text for findings summary rows."""
    issue = str(issue_text or "").strip().lower()
    takeover = detail_obj.get("takeover") or {}
    takeover_status = str(takeover.get("status") or "").strip().lower()
    takeover_provider = str(takeover.get("provider") or "-").strip()
    takeover_cname = str(takeover.get("cname") or "-").strip()
    matched_fp = takeover.get("matched_fingerprints") or []
    http = detail_obj.get("http") or []
    https = detail_obj.get("https") or []
    cert = detail_obj.get("cert") or []
    verbose = detail_obj.get("verbose") or {}
    tls_verbose = verbose.get("tls") if isinstance(verbose, dict) else {}
    tls_verbose = tls_verbose if isinstance(tls_verbose, dict) else {}

    domain_name = str(row.get("domain") or detail_obj.get("domain") or "-").strip()
    http_status = http[0] if len(http) > 0 else row.get("http_status")
    https_status = https[0] if len(https) > 0 else row.get("https_status")
    http_server = str(http[2] if len(http) > 2 else row.get("http_server") or "-").strip()
    https_server = str(https[2] if len(https) > 2 else row.get("https_server") or "-").strip()
    cert_expiry = cert[1] if len(cert) > 1 else row.get("cert_expiry")
    cert_cn = str(cert[2] if len(cert) > 2 else row.get("cert_cn") or "-").strip()
    tls_versions = cert[3] if len(cert) > 3 else row.get("tls_versions")
    san_values = tls_verbose.get("san") or []
    strict_error = str(tls_verbose.get("strict_error") or "-").strip()
    issuer = str(tls_verbose.get("issuer") or "-").strip()
    protocol = str(tls_verbose.get("protocol") or "-").strip()
    cipher = str(tls_verbose.get("cipher") or "-").strip()

    http_version = row.get("http_server_version")
    http_latest = row.get("http_server_latest")
    https_version = row.get("https_server_version")
    https_latest = row.get("https_server_latest")

    evidence_parts: List[str] = []
    if "server potentially outdated" in issue:
        is_https = issue.startswith("https ")
        if is_https:
            evidence_parts.append("service=HTTPS")
            evidence_parts.append(f"banner={https_server}")
            evidence_parts.append(f"status={https_status if https_status is not None else '-'}")
            if https_version or https_latest:
                evidence_parts.append(f"version={https_version or '-'} latest_ref={https_latest or '-'}")
        else:
            evidence_parts.append("service=HTTP")
            evidence_parts.append(f"banner={http_server}")
            evidence_parts.append(f"status={http_status if http_status is not None else '-'}")
            if http_version or http_latest:
                evidence_parts.append(f"version={http_version or '-'} latest_ref={http_latest or '-'}")
    elif "hostname mismatch" in issue:
        evidence_parts.append("service=HTTPS/TLS certificate")
        evidence_parts.append(f"domain={domain_name}")
        evidence_parts.append(f"cert_cn={cert_cn}")
        evidence_parts.append(f"https_banner={https_server}")
        evidence_parts.append(f"issuer={issuer}")
        if isinstance(san_values, list) and san_values:
            evidence_parts.append(f"san={', '.join(str(v) for v in san_values[:6])}")
    elif "certificate validation failed" in issue or "certificate trust/chain verification failed" in issue:
        evidence_parts.append("service=HTTPS/TLS")
        evidence_parts.append(f"strict_error={strict_error}")
        evidence_parts.append(f"issuer={issuer}")
    elif "certificate expired" in issue:
        evidence_parts.append("service=HTTPS/TLS")
        evidence_parts.append(f"cert_expiry={cert_expiry or '-'}")
        evidence_parts.append(f"issuer={issuer}")
    elif "weak tls versions detected" in issue:
        evidence_parts.append("service=HTTPS/TLS")
        if isinstance(tls_versions, list) and tls_versions:
            evidence_parts.append(f"tls={', '.join(str(v) for v in tls_versions)}")
        evidence_parts.append(f"protocol={protocol}")
        evidence_parts.append(f"cipher={cipher}")
    elif "subdomain takeover" in issue:
        evidence_parts.append("service=DNS CNAME + HTTP/HTTPS fingerprint")
        evidence_parts.append(f"provider={takeover_provider}")
        evidence_parts.append(f"cname={takeover_cname}")
        evidence_parts.append(f"takeover_status={takeover_status or '-'}")
        if matched_fp:
            evidence_parts.append(f"matched_fp={', '.join(str(v) for v in matched_fp)}")
        evidence_parts.append(f"http={http_status if http_status is not None else '-'} https={https_status if https_status is not None else '-'}")
    elif "axfr" in issue or "zone transfer" in issue:
        evidence_parts.append("service=DNS AXFR")
        evidence_parts.append(f"note={issue_text}")
    elif "http returned" in issue or "https returned" in issue or "redirect" in issue:
        evidence_parts.append("service=HTTP/HTTPS")
        evidence_parts.append(f"http={http_status if http_status is not None else '-'} https={https_status if https_status is not None else '-'}")
        evidence_parts.append(f"http_banner={http_server}")
        evidence_parts.append(f"https_banner={https_server}")
    else:
        if http_status is not None or https_status is not None:
            evidence_parts.append(
                f"HTTP={http_status if http_status is not None else '-'} HTTPS={https_status if https_status is not None else '-'}"
            )
        if takeover_status in {"likely", "possible"}:
            evidence_parts.append(f"takeover={takeover_status} provider={takeover_provider} cname={takeover_cname}")
        if cert_expiry:
            evidence_parts.append(f"cert_expiry={cert_expiry}")
        if isinstance(tls_versions, list) and tls_versions:
            evidence_parts.append(f"tls={', '.join(str(v) for v in tls_versions)}")
    return " | ".join(evidence_parts) if evidence_parts else "-"


def _finding_category(issue_text: str) -> str:
    """Return a category label used to group findings in HTML summary."""
    text = str(issue_text or "").strip().lower()
    if not text:
        return "Security finding"
    if "takeover" in text:
        return "Subdomain takeover"
    if "certificate" in text or "tls" in text or "hostname mismatch" in text:
        return "TLS / certificate"
    if "server potentially outdated" in text or "server version" in text:
        return "Web server version"
    if "axfr" in text or "zone transfer" in text:
        return "DNS AXFR exposure"
    if "http returned" in text or "https returned" in text or "redirect" in text:
        return "HTTP/HTTPS behavior"
    if "header" in text:
        return "Security headers"
    return "Security finding"
