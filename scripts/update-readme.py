#!/usr/bin/env python3
"""Update generated tables and live feed status blocks inside README.md."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
README_PATH = ROOT / "README.md"


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def replace_block(text: str, marker: str, content: str) -> str:
    pattern = re.compile(
        rf"(<!-- START:{re.escape(marker)} -->\n)(.*?)(\n<!-- END:{re.escape(marker)} -->)",
        re.DOTALL,
    )
    if not pattern.search(text):
        raise ValueError(f"Missing marker pair for {marker} in README.md")
    return pattern.sub(rf"\1{content}\3", text, count=1)


def md_escape(value: str) -> str:
    return str(value).replace("|", "\\|").strip()


def build_stats(tools: list[dict[str, Any]], platforms: list[dict[str, Any]], feeds: list[dict[str, Any]], status_data: dict[str, Any]) -> str:
    checked_at = status_data.get("checked_at", "not yet run")
    online = status_data.get("online", 0)
    total_feeds = len(feeds)
    return (
        f"Catalog size: {len(tools)} threat intelligence tools, {len(platforms)} threat intelligence platforms, "
        f"and {total_feeds} threat intelligence feeds ({online}/{total_feeds} feeds reachable as of {checked_at})."
    )


def build_featured_table(tools: list[dict[str, Any]], platforms: list[dict[str, Any]], feeds: list[dict[str, Any]]) -> str:
    rows = [
        "| Tool / Source | Purpose | Product type | Formats | API key | Self-hosted |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    featured_items: list[tuple[str, str, str, str, list[str], str, bool]] = []

    for item in tools:
        if item.get("featured"):
            featured_items.append(
                (item["name"], item["url"], item["purpose"], item["product_type"], item["formats"], item["api_key"], item["self_hosted"])
            )
    for item in platforms:
        if item.get("featured"):
            featured_items.append(
                (item["name"], item["url"], item["purpose"], item["type"], item["formats"], item["api_key"], item["self_hosted"])
            )
    for item in feeds:
        if item.get("featured") and item["name"] not in {x[0] for x in featured_items}:
            featured_items.append(
                (item["name"], item["url"], f"{item['category']} ({', '.join(item['ioc_types'])})", "Threat Feed", item["formats"], item["api_key"], False)
            )

    for name, url, purpose, ptype, fmts, api_key, self_hosted in featured_items[:12]:
        rows.append(
            f"| [{md_escape(name)}]({url}) | {md_escape(purpose)} | {md_escape(ptype)} | "
            f"{md_escape(', '.join(fmts[:4]))} | {md_escape(api_key)} | {'Yes' if self_hosted else 'No'} |"
        )
    return "\n".join(rows)


def build_feed_status_table(feeds: list[dict[str, Any]], status_data: dict[str, Any]) -> str:
    by_id = {row["id"]: row for row in status_data.get("results", [])}
    rows = [
        "| Feed | Status | Response | Last-Modified header | Format check | Formats | API key |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for feed in feeds:
        st = by_id.get(feed["id"], {})
        status = st.get("status", "Unchecked")
        ms = f"{st['response_ms']} ms" if st.get("response_ms") is not None else "-"
        last_mod = st.get("last_modified") or "-"
        fmt_chk = st.get("format_check") or "-"
        fmts = ", ".join(feed.get("formats", [])[:3])
        rows.append(
            f"| [{md_escape(feed['name'])}]({feed['url']}) | {md_escape(status)} | {ms} | "
            f"{md_escape(last_mod)} | {md_escape(fmt_chk)} | {md_escape(fmts)} | {md_escape(feed['api_key'])} |"
        )
    return "\n".join(rows)


def build_platforms_table(platforms: list[dict[str, Any]]) -> str:
    rows = [
        "| Platform | Type | Purpose | Formats | License | Commercial use | Self-hosted | Integrations |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for p in platforms:
        rows.append(
            f"| [{md_escape(p['name'])}]({p['url']}) | {md_escape(p['type'])} | {md_escape(p['purpose'])} | "
            f"{md_escape(', '.join(p['formats'][:4]))} | {md_escape(p['license'])} | "
            f"{md_escape(p['commercial_use'])} | {'Yes' if p['self_hosted'] else 'No'} | "
            f"{md_escape(', '.join(p['integrations'][:4]))} |"
        )
    return "\n".join(rows)


def build_tools_catalog(tools: list[dict[str, Any]]) -> str:
    categories: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        categories.setdefault(tool["category"], []).append(tool)

    sections: list[str] = []
    for cat, items in categories.items():
        lines = [
            f"### {cat}",
            "",
            "| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for t in items:
            lines.append(
                f"| [{md_escape(t['name'])}]({t['url']}) | {md_escape(t['product_type'])} | {md_escape(t['purpose'])} | "
                f"{md_escape(', '.join(t['formats'][:3]))} | {md_escape(t['api_key'])} | "
                f"{md_escape(t['free_limits'])} | {md_escape(t['commercial_use'])} | "
                f"{'Yes' if t['self_hosted'] else 'No'} |"
            )
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def build_feeds_catalog(feeds: list[dict[str, Any]]) -> str:
    categories: dict[str, list[dict[str, Any]]] = {}
    for feed in feeds:
        categories.setdefault(feed["category"], []).append(feed)

    sections: list[str] = []
    for cat, items in categories.items():
        lines = [
            f"### {cat}",
            "",
            "| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for f in items:
            lines.append(
                f"| [{md_escape(f['name'])}]({f['url']}) | {md_escape(', '.join(f['ioc_types']))} | "
                f"{md_escape(', '.join(f['formats'][:4]))} | {md_escape(f['update_frequency'])} | "
                f"{md_escape(f['free_limits'])} | {md_escape(f['license'])} | "
                f"{md_escape(f['commercial_use'])} | {md_escape(', '.join(f['integrations'][:3]))} |"
            )
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def main() -> int:
    tools = load_json(DATA_DIR / "tools.json")
    platforms = load_json(DATA_DIR / "platforms.json")
    feeds = load_json(DATA_DIR / "feeds.json")
    status_path = DATA_DIR / "feed-status.json"
    status_data = load_json(status_path) if status_path.exists() else {"checked_at": "pending", "online": 0, "results": []}

    readme = README_PATH.read_text(encoding="utf-8")
    readme = replace_block(readme, "STATS", build_stats(tools, platforms, feeds, status_data))
    readme = replace_block(readme, "FEATURED", build_featured_table(tools, platforms, feeds))
    readme = replace_block(readme, "FEED_STATUS", build_feed_status_table(feeds, status_data))
    readme = replace_block(readme, "PLATFORMS", build_platforms_table(platforms))
    readme = replace_block(readme, "TOOLS", build_tools_catalog(tools))
    readme = replace_block(readme, "FEEDS", build_feeds_catalog(feeds))

    README_PATH.write_text(readme, encoding="utf-8")
    print(f"Updated {README_PATH} ({len(tools)} tools, {len(platforms)} platforms, {len(feeds)} feeds).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
