#!/usr/bin/env python3
"""Scan server logs (Nginx, Apache, syslog/auth.log) against threat intelligence IP feeds."""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import pathlib
import re
import ssl
import sys
import urllib.request

USER_AGENT = "secops-tools-log-checker/1.0 (+https://github.com/secops-tools/threat-intelligence-tools)"
DEFAULT_FEED_URLS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
]
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_iocs_from_lines(lines: list[str], allow_private: bool = False) -> set[str]:
    ips: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        token = line.split()[0].split(",")[0].strip()
        try:
            ip_obj = ipaddress.ip_address(token)
            if allow_private or (not ip_obj.is_private and not ip_obj.is_loopback):
                ips.add(str(ip_obj))
        except ValueError:
            continue
    return ips


def fetch_feed_ips(urls: list[str], timeout: float) -> set[str]:
    ctx = ssl.create_default_context()
    combined: set[str] = set()
    for url in urls:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                combined.update(load_iocs_from_lines(text.splitlines()))
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: failed to fetch {url}: {exc}", file=sys.stderr)
    return combined


def scan_log_file(log_path: pathlib.Path, bad_ips: set[str]) -> dict[str, dict[str, object]]:
    hits: dict[str, int] = collections.Counter()
    samples: dict[str, str] = {}
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            for match in IPV4_RE.findall(line):
                if match in bad_ips:
                    hits[match] += 1
                    if match not in samples:
                        samples[match] = f"L{line_no}: {line.strip()[:160]}"
    return {
        ip: {"count": count, "sample": samples[ip]}
        for ip, count in hits.most_common()
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Match IP addresses in server logs against local or remote threat intelligence feeds."
    )
    parser.add_argument("log_file", type=pathlib.Path, help="Path to log file (Nginx, Apache, auth.log, syslog)")
    parser.add_argument(
        "--ioc-file",
        type=pathlib.Path,
        default=None,
        help="Optional local IOC file (one IP per line). If omitted, downloads public feeds.",
    )
    parser.add_argument(
        "--feed-url",
        action="append",
        default=[],
        help="Additional remote IP feed URL (can be passed multiple times)",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds (default: 15)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON report")
    args = parser.parse_args()

    if not args.log_file.is_file():
        print(f"Log file not found: {args.log_file}", file=sys.stderr)
        return 2

    bad_ips: set[str] = set()
    if args.ioc_file:
        bad_ips.update(load_iocs_from_lines(args.ioc_file.read_text(encoding="utf-8").splitlines(), allow_private=True))
    if args.feed_url:
        bad_ips.update(fetch_feed_ips(args.feed_url, args.timeout))
    if not args.ioc_file and not args.feed_url:
        bad_ips.update(fetch_feed_ips(DEFAULT_FEED_URLS, args.timeout))

    matches = scan_log_file(args.log_file, bad_ips)
    report = {
        "log_file": str(args.log_file),
        "loaded_indicators": len(bad_ips),
        "matched_unique_ips": len(matches),
        "matches": matches,
    }

    if args.as_json:
        print(json.dumps(report, indent=2))
        return 1 if matches else 0

    print(f"Loaded {len(bad_ips)} IP indicators. Matched {len(matches)} unique IPs in {args.log_file}.")
    for ip, info in matches.items():
        print(f"  {ip:<16} hits={info['count']:<5} {info['sample']}")
    return 1 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
