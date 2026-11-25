#!/usr/bin/env python3
"""Build the static GitHub Pages directory in docs/ from data/*.json."""

from __future__ import annotations

import datetime as dt
import html
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DOCS_DIR = ROOT / "docs"
SITE_URL = "https://secops-tools.github.io/threat-intelligence-tools/"
REPO_URL = "https://github.com/secops-tools/threat-intelligence-tools"
GSC_META_TAG = '<meta name="google-site-verification" content="HqgfQrEQATXaycciOAu8GzuJP8BSRHtaR1JrgBtnApU" />'


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def status_badge(status: str) -> str:
    lower = status.lower()
    if lower == "online":
        cls = "badge-online"
    elif lower.startswith("online"):
        cls = "badge-auth"
    else:
        cls = "badge-offline"
    return f'<span class="badge {cls}">{esc(status)}</span>'


def render_tools_rows(tools: list[dict[str, Any]]) -> str:
    rows = []
    for t in tools:
        self_hosted = "Yes" if t["self_hosted"] else "No"
        search_blob = " ".join(
            [
                t["name"],
                t["category"],
                t["purpose"],
                t["product_type"],
                " ".join(t["formats"]),
                t["commercial_use"],
                " ".join(t["integrations"]),
            ]
        ).lower()
        rows.append(
            f'<tr data-category="{esc(t["category"])}" data-selfhosted="{self_hosted.lower()}" '
            f'data-search="{esc(search_blob)}">'
            f'<td><a href="{esc(t["url"])}" target="_blank" rel="noopener noreferrer">{esc(t["name"])}</a>'
            f'<div class="sub">{esc(t["category"])}</div></td>'
            f'<td>{esc(t["product_type"])}</td>'
            f'<td>{esc(t["purpose"])}</td>'
            f'<td>{esc(", ".join(t["formats"][:3]))}</td>'
            f'<td>{esc(t["api_key"])}</td>'
            f'<td>{esc(t["free_limits"])}</td>'
            f'<td>{esc(t["commercial_use"])}</td>'
            f'<td>{self_hosted}</td>'
            f"</tr>"
        )
    return "\n".join(rows)


def render_platforms_rows(platforms: list[dict[str, Any]]) -> str:
    rows = []
    for p in platforms:
        self_hosted = "Yes" if p["self_hosted"] else "No"
        rows.append(
            "<tr>"
            f'<td><a href="{esc(p["url"])}" target="_blank" rel="noopener noreferrer">{esc(p["name"])}</a></td>'
            f'<td>{esc(p["type"])}</td>'
            f'<td>{esc(p["purpose"])}</td>'
            f'<td>{esc(", ".join(p["formats"][:4]))}</td>'
            f'<td>{esc(p["license"])}</td>'
            f'<td>{esc(p["commercial_use"])}</td>'
            f'<td>{self_hosted}</td>'
            f'<td>{esc(", ".join(p["integrations"][:4]))}</td>'
            "</tr>"
        )
    return "\n".join(rows)


def render_feeds_rows(feeds: list[dict[str, Any]], status_by_id: dict[str, dict[str, Any]]) -> str:
    rows = []
    for f in feeds:
        st = status_by_id.get(f["id"], {})
        status = st.get("status", "Unchecked")
        ms = f'{st["response_ms"]} ms' if st.get("response_ms") is not None else "-"
        last_mod = st.get("last_modified") or "-"
        fmt_chk = st.get("format_check") or "-"
        search_blob = " ".join(
            [
                f["name"],
                f["category"],
                " ".join(f["ioc_types"]),
                " ".join(f["formats"]),
                f["license"],
                f["commercial_use"],
                status,
            ]
        ).lower()
        rows.append(
            f'<tr data-category="{esc(f["category"])}" data-search="{esc(search_blob)}">'
            f'<td><a href="{esc(f["url"])}" target="_blank" rel="noopener noreferrer">{esc(f["name"])}</a>'
            f'<div class="sub">{esc(f["category"])}</div></td>'
            f'<td>{status_badge(status)}</td>'
            f'<td><code>{esc(ms)}</code></td>'
            f'<td>{esc(last_mod)}</td>'
            f'<td>{esc(fmt_chk)}</td>'
            f'<td>{esc(", ".join(f["ioc_types"]))}</td>'
            f'<td>{esc(", ".join(f["formats"][:3]))}</td>'
            f'<td>{esc(f["api_key"])}</td>'
            f'<td>{esc(f["commercial_use"])}</td>'
            "</tr>"
        )
    return "\n".join(rows)


def build_html(
    tools: list[dict[str, Any]],
    platforms: list[dict[str, Any]],
    feeds: list[dict[str, Any]],
    status_data: dict[str, Any],
) -> str:
    status_by_id = {row["id"]: row for row in status_data.get("results", [])}
    checked_at = status_data.get("checked_at", "pending")
    online_count = status_data.get("online", 0)
    tool_categories = sorted({t["category"] for t in tools})
    feed_categories = sorted({f["category"] for f in feeds})

    tool_cat_options = "\n".join(f'<option value="{esc(c)}">{esc(c)}</option>' for c in tool_categories)
    feed_cat_options = "\n".join(f'<option value="{esc(c)}">{esc(c)}</option>' for c in feed_categories)

    ld_json = json.dumps(
        {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": "Best Threat Intelligence Tools, Platforms & Feeds",
            "description": (
                "A curated and automatically updated directory of threat intelligence tools, "
                "platforms, APIs, and feeds for cybersecurity professionals."
            ),
            "url": SITE_URL,
            "isPartOf": {
                "@type": "SoftwareSourceCode",
                "name": "threat-intelligence-tools",
                "codeRepository": REPO_URL,
                "programmingLanguage": "Python",
                "license": "https://opensource.org/licenses/MIT",
            },
        },
        indent=2,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  {GSC_META_TAG}
  <title>Best Threat Intelligence Tools, Platforms &amp; Feeds (Free &amp; Open Source)</title>
  <meta name="description" content="A curated and automatically updated directory of {len(tools)} threat intelligence tools, {len(platforms)} platforms, and {len(feeds)} live-checked threat intelligence feeds with Python CLI utilities." />
  <link rel="canonical" href="{SITE_URL}" />
  <meta property="og:type" content="website" />
  <meta property="og:title" content="Best Threat Intelligence Tools, Platforms &amp; Feeds" />
  <meta property="og:description" content="Compare {len(tools)} threat intelligence tools, {len(platforms)} TIP platforms, and {len(feeds)} threat feeds with daily status checks and Python CLI scripts." />
  <meta property="og:url" content="{SITE_URL}" />
  <script type="application/ld+json">
{ld_json}
  </script>
  <style>
    :root {{
      --bg: #0b1017;
      --surface: #121923;
      --surface-alt: #161f2c;
      --border: #243042;
      --text: #e6edf3;
      --muted: #93a3b8;
      --accent: #38bdf8;
      --accent-soft: rgba(56, 189, 248, 0.14);
      --green: #34d399;
      --amber: #fbbf24;
      --red: #f87171;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1240px; margin: 0 auto; padding: 32px 20px 64px; }}
    header {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 28px;
    }}
    .top-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
    }}
    .eyebrow {{
      font-size: 13px;
      color: var(--muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .nav {{
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 14px;
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(28px, 4vw, 38px);
      line-height: 1.2;
      letter-spacing: -0.02em;
    }}
    .lead {{
      margin: 0 0 20px;
      max-width: 820px;
      color: var(--muted);
      font-size: 16px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .stat {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
    }}
    .stat-val {{
      font-size: 24px;
      font-weight: 700;
      color: var(--text);
    }}
    .stat-lbl {{
      font-size: 13px;
      color: var(--muted);
    }}
    section {{ margin-top: 40px; }}
    h2 {{
      margin: 0 0 8px;
      font-size: 22px;
      letter-spacing: -0.01em;
    }}
    .section-note {{
      margin: 0 0 16px;
      color: var(--muted);
      font-size: 14px;
      max-width: 820px;
    }}
    .controls {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}
    input[type="search"], select {{
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 9px 12px;
      font-size: 14px;
    }}
    input[type="search"] {{ min-width: 260px; flex: 1; max-width: 420px; }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13.5px;
      text-align: left;
    }}
    th, td {{
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{
      background: var(--surface-alt);
      color: var(--muted);
      font-weight: 600;
      white-space: nowrap;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
    .sub {{
      font-size: 12px;
      color: var(--muted);
      margin-top: 2px;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12.5px;
      background: rgba(255, 255, 255, 0.06);
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      white-space: nowrap;
    }}
    .badge-online {{ background: rgba(52, 211, 153, 0.15); color: var(--green); }}
    .badge-auth {{ background: rgba(251, 191, 36, 0.15); color: var(--amber); }}
    .badge-offline {{ background: rgba(248, 113, 113, 0.15); color: var(--red); }}
    .cli-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }}
    .card h3 {{ margin: 0 0 6px; font-size: 15px; }}
    .card p {{ margin: 0 0 10px; font-size: 13.5px; color: var(--muted); }}
    footer {{
      margin-top: 56px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="top-bar">
        <div class="eyebrow">secops-tools / threat-intelligence-tools</div>
        <nav class="nav">
          <a href="#feeds">Live feed status</a>
          <a href="#platforms">Platforms</a>
          <a href="#tools">Tools</a>
          <a href="#cli">CLI utilities</a>
          <a href="{REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub repository</a>
        </nav>
      </div>
      <h1>Best Threat Intelligence Tools, Platforms &amp; Feeds</h1>
      <p class="lead">
        A directory of threat intelligence tools, platforms, APIs, and public feeds for security engineers, SOC analysts, and system administrators. Feed reachability, response latency, and <code>Last-Modified</code> headers update daily via GitHub Actions.
      </p>
      <div class="stats">
        <div class="stat">
          <div class="stat-val">{len(tools)}</div>
          <div class="stat-lbl">Threat intelligence tools</div>
        </div>
        <div class="stat">
          <div class="stat-val">{len(platforms)}</div>
          <div class="stat-lbl">Threat intelligence platforms</div>
        </div>
        <div class="stat">
          <div class="stat-val">{online_count} / {len(feeds)}</div>
          <div class="stat-lbl">Feeds reachable ({esc(checked_at)})</div>
        </div>
        <div class="stat">
          <div class="stat-val">7</div>
          <div class="stat-lbl">Python stdlib CLI utilities</div>
        </div>
      </div>
    </header>

    <section id="feeds">
      <h2>Threat intelligence feed status</h2>
      <p class="section-note">
        Checked daily by <code>scripts/check-feeds.py</code>. Endpoint reachability does not prove that indicators inside a feed are fresh or low in false positives; review <code>Last-Modified</code> headers and your allowlist before blocking traffic.
      </p>
      <div class="controls">
        <input id="feed-search" type="search" placeholder="Filter feeds by name, IOC type, format, or license..." />
        <select id="feed-cat">
          <option value="">All feed categories</option>
          {feed_cat_options}
        </select>
      </div>
      <div class="table-wrap">
        <table id="feeds-table">
          <thead>
            <tr>
              <th>Feed</th>
              <th>Status</th>
              <th>Response</th>
              <th>Last-Modified</th>
              <th>Format check</th>
              <th>IOC types</th>
              <th>Formats</th>
              <th>API key</th>
              <th>Commercial use</th>
            </tr>
          </thead>
          <tbody>
            {render_feeds_rows(feeds, status_by_id)}
          </tbody>
        </table>
      </div>
    </section>

    <section id="platforms">
      <h2>Threat intelligence platforms</h2>
      <p class="section-note">
        Open-source threat intelligence platforms handle local IOC storage and correlation without per-seat licensing. Commercial platforms add closed-source collection, analyst reporting, and vendor SLAs.
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Platform</th>
              <th>Type</th>
              <th>Purpose</th>
              <th>Formats</th>
              <th>License</th>
              <th>Commercial use</th>
              <th>Self-hosted</th>
              <th>Integrations</th>
            </tr>
          </thead>
          <tbody>
            {render_platforms_rows(platforms)}
          </tbody>
        </table>
      </div>
    </section>

    <section id="tools">
      <h2>Threat intelligence tools</h2>
      <p class="section-note">
        Filter by category, self-hosting support, or keyword. Commercial use reflects the license or terms of the free tier.
      </p>
      <div class="controls">
        <input id="tool-search" type="search" placeholder="Filter tools by name, purpose, format, or integration..." />
        <select id="tool-cat">
          <option value="">All tool categories</option>
          {tool_cat_options}
        </select>
        <select id="tool-selfhosted">
          <option value="">Any hosting model</option>
          <option value="yes">Self-hosted only</option>
          <option value="no">SaaS / API only</option>
        </select>
      </div>
      <div class="table-wrap">
        <table id="tools-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Type</th>
              <th>Purpose</th>
              <th>Formats</th>
              <th>API key</th>
              <th>Free limits</th>
              <th>Commercial use</th>
              <th>Self-hosted</th>
            </tr>
          </thead>
          <tbody>
            {render_tools_rows(tools)}
          </tbody>
        </table>
      </div>
    </section>

    <section id="cli">
      <h2>Included CLI utilities</h2>
      <p class="section-note">
        Every script in <code>scripts/</code> runs on Python 3.9+ with standard library modules only.
      </p>
      <div class="cli-grid">
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/check-ip.py">check-ip.py</a></h3>
          <p>Query IP reputation across Shodan InternetDB, GreyNoise, AlienVault OTX, AbuseIPDB, and VirusTotal.</p>
          <code>python3 scripts/check-ip.py 1.1.1.1</code>
        </div>
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/check-feeds.py">check-feeds.py</a></h3>
          <p>Measure feed HTTP status, latency, Last-Modified headers, and payload structure.</p>
          <code>python3 scripts/check-feeds.py</code>
        </div>
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/check-logs.py">check-logs.py</a></h3>
          <p>Scan Nginx, Apache, or Linux auth logs against public or local IP blocklists.</p>
          <code>python3 scripts/check-logs.py /var/log/nginx/access.log</code>
        </div>
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/convert-feed.py">convert-feed.py</a></h3>
          <p>Convert indicator lists between JSON, CSV, plain text, and STIX 2.1 bundles.</p>
          <code>python3 scripts/convert-feed.py iocs.txt out.json --to stix</code>
        </div>
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/dedupe-iocs.py">dedupe-iocs.py</a></h3>
          <p>Refang, classify, and deduplicate mixed IPs, domains, URLs, and file hashes.</p>
          <code>python3 scripts/dedupe-iocs.py raw.txt -o clean.txt</code>
        </div>
        <div class="card">
          <h3><a href="{REPO_URL}/blob/main/scripts/cve-monitor.py">cve-monitor.py</a></h3>
          <p>Check CISA KEV and NIST NVD 2.0 for recent CVEs matching your software stack.</p>
          <code>python3 scripts/cve-monitor.py nginx openssh --days 30</code>
        </div>
      </div>
    </section>

    <footer>
      <div>MIT License. Data and automation scripts maintained at <a href="{REPO_URL}">secops-tools/threat-intelligence-tools</a>.</div>
      <div>Last feed sync: {esc(checked_at)}</div>
    </footer>
  </div>

  <script>
    function wireFilter(searchId, catId, selfHostedId, tableId) {{
      const searchEl = document.getElementById(searchId);
      const catEl = document.getElementById(catId);
      const hostEl = selfHostedId ? document.getElementById(selfHostedId) : null;
      const rows = Array.from(document.querySelectorAll("#" + tableId + " tbody tr"));
      function apply() {{
        const q = (searchEl.value || "").trim().toLowerCase();
        const cat = catEl.value;
        const host = hostEl ? hostEl.value : "";
        for (const row of rows) {{
          const okSearch = !q || row.dataset.search.includes(q);
          const okCat = !cat || row.dataset.category === cat;
          const okHost = !host || row.dataset.selfhosted === host;
          row.style.display = (okSearch && okCat && okHost) ? "" : "none";
        }}
      }}
      searchEl.addEventListener("input", apply);
      catEl.addEventListener("change", apply);
      if (hostEl) hostEl.addEventListener("change", apply);
    }}
    wireFilter("feed-search", "feed-cat", null, "feeds-table");
    wireFilter("tool-search", "tool-cat", "tool-selfhosted", "tools-table");
  </script>
</body>
</html>
"""


def main() -> int:
    tools = load_json(DATA_DIR / "tools.json")
    platforms = load_json(DATA_DIR / "platforms.json")
    feeds = load_json(DATA_DIR / "feeds.json")
    status_path = DATA_DIR / "feed-status.json"
    status_data = load_json(status_path) if status_path.exists() else {"checked_at": "pending", "online": 0, "results": []}

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "index.html").write_text(build_html(tools, platforms, feeds, status_data), encoding="utf-8")

    lastmod = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    sitemap = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{SITE_URL}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
"""
    (DOCS_DIR / "sitemap.xml").write_text(sitemap, encoding="utf-8")
    (DOCS_DIR / "robots.txt").write_text(f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}sitemap.xml\n", encoding="utf-8")
    (DOCS_DIR / ".nojekyll").write_text("", encoding="utf-8")

    print(f"Built GitHub Pages site in {DOCS_DIR} (index.html, sitemap.xml, robots.txt).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
