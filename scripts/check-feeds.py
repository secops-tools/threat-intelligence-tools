#!/usr/bin/env python3
"""Check availability, latency, freshness headers, and format validity of threat feeds."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import email.utils
import json
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_FEEDS_FILE = ROOT / "data" / "feeds.json"
DEFAULT_OUTPUT_FILE = ROOT / "data" / "feed-status.json"
USER_AGENT = "secops-tools-feed-checker/1.0 (+https://github.com/secops-tools/threat-intelligence-tools)"


def parse_last_modified(header_value: str | None) -> str | None:
    if not header_value:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(header_value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return None


def validate_sample(body: bytes, content_type: str, formats: list[str]) -> str:
    if not body:
        return "Empty response"
    lower_ct = (content_type or "").lower()
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return "Empty body"
    if "json" in lower_ct or text.startswith("{") or text.startswith("["):
        try:
            json.loads(text)
            return "Valid JSON"
        except json.JSONDecodeError:
            # Sampled prefix of a larger JSON document
            if text.startswith("{") or text.startswith("["):
                return "JSON stream"
            return "Malformed JSON"
    if "html" in lower_ct or text.lower().startswith("<!doctype html") or text.lower().startswith("<html"):
        return "HTML page"
    non_comment_lines = [
        line for line in text.splitlines() if line.strip() and not line.strip().startswith(("#", ";"))
    ]
    if non_comment_lines:
        return f"OK ({len(non_comment_lines)}+ rows)"
    if any(f.upper() in ("TXT", "CSV", "HOSTS", "RPZ") for f in formats):
        return "Header only"
    return "OK"


def check_single_feed(feed: dict[str, Any], timeout: float) -> dict[str, Any]:
    url = feed["check_url"]
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, text/csv, */*;q=0.8",
        },
        method="GET",
    )
    ssl_ctx = ssl.create_default_context()
    start = time.perf_counter()
    status_label = "Offline"
    http_status: int | None = None
    response_ms: int | None = None
    last_modified: str | None = None
    format_check = "Unchecked"
    error_msg: str | None = None

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            http_status = resp.getcode()
            sample = resp.read(65536)
            response_ms = int((time.perf_counter() - start) * 1000)
            last_modified = parse_last_modified(resp.headers.get("Last-Modified"))
            content_type = resp.headers.get("Content-Type", "")
            format_check = validate_sample(sample, content_type, feed.get("formats", []))
            if http_status and 200 <= http_status < 400:
                status_label = "Online"
            else:
                status_label = "Degraded"
    except urllib.error.HTTPError as exc:
        response_ms = int((time.perf_counter() - start) * 1000)
        http_status = exc.code
        # 401/403/405 on key-protected API endpoints still indicates the API is reachable
        if exc.code in (401, 403, 405, 429):
            status_label = "Online (Auth/Rate-Limit)"
            format_check = f"HTTP {exc.code}"
        else:
            status_label = "Offline"
            error_msg = f"HTTP {exc.code}"
            format_check = error_msg
    except urllib.error.URLError as exc:
        response_ms = int((time.perf_counter() - start) * 1000)
        reason = getattr(exc, "reason", exc)
        error_msg = str(reason)[:80]
        status_label = "Offline"
        format_check = "Timeout" if "timed out" in error_msg.lower() else "Unreachable"
    except TimeoutError:
        response_ms = int((time.perf_counter() - start) * 1000)
        status_label = "Offline"
        error_msg = "Timeout"
        format_check = "Timeout"
    except Exception as exc:  # noqa: BLE001
        response_ms = int((time.perf_counter() - start) * 1000)
        status_label = "Offline"
        error_msg = str(exc)[:80]
        format_check = "Error"

    return {
        "id": feed["id"],
        "name": feed["name"],
        "check_url": url,
        "status": status_label,
        "http_status": http_status,
        "response_ms": response_ms,
        "last_modified": last_modified,
        "format_check": format_check,
        "error": error_msg,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate availability, latency, and headers for threat intelligence feeds."
    )
    parser.add_argument(
        "--feeds",
        type=pathlib.Path,
        default=DEFAULT_FEEDS_FILE,
        help="Path to feeds.json",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=DEFAULT_OUTPUT_FILE,
        help="Path to write feed-status.json",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="Per-feed HTTP timeout in seconds (default: 12)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=12,
        help="Concurrent worker threads (default: 12)",
    )
    parser.add_argument(
        "--only",
        type=str,
        default="",
        help="Comma-separated feed IDs to check (optional)",
    )
    args = parser.parse_args()

    feeds: list[dict[str, Any]] = json.loads(args.feeds.read_text(encoding="utf-8"))
    if args.only:
        wanted = {item.strip() for item in args.only.split(",") if item.strip()}
        feeds = [f for f in feeds if f["id"] in wanted]

    results_by_id: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {executor.submit(check_single_feed, f, args.timeout): f["id"] for f in feeds}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            results_by_id[res["id"]] = res

    ordered = [results_by_id[f["id"]] for f in feeds if f["id"] in results_by_id]
    online_count = sum(1 for r in ordered if r["status"].startswith("Online"))
    offline_count = len(ordered) - online_count

    payload = {
        "checked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "checked_date": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
        "total": len(ordered),
        "online": online_count,
        "offline": offline_count,
        "results": ordered,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"Checked {len(ordered)} feeds: {online_count} online, {offline_count} offline.")
    for r in ordered:
        ms = f"{r['response_ms']} ms" if r["response_ms"] is not None else "-"
        print(f"  [{r['status']:<24}] {ms:>8}  {r['name']} ({r['format_check']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
