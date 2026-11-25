#!/usr/bin/env python3
"""Normalize, refang/defang, classify, and deduplicate IOC files."""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import pathlib
import re
import sys

MD5_RE = re.compile(r"^[a-f0-9]{32}$")
SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def refang(text: str) -> str:
    val = text.strip()
    val = val.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    val = val.replace("[:]", ":").replace("hxxp://", "http://").replace("hxxps://", "https://")
    val = val.replace("hXXp://", "http://").replace("hXXps://", "https://")
    return val


def defang(text: str) -> str:
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def classify(ioc: str) -> str:
    lower = ioc.lower()
    try:
        ip = ipaddress.ip_address(lower)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        pass
    if lower.startswith(("http://", "https://", "ftp://")):
        return "url"
    if SHA256_RE.match(lower):
        return "sha256"
    if SHA1_RE.match(lower):
        return "sha1"
    if MD5_RE.match(lower):
        return "md5"
    if DOMAIN_RE.match(lower):
        return "domain"
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser(description="Deduplicate and classify IOC lists.")
    parser.add_argument("inputs", nargs="+", type=pathlib.Path, help="One or more input files")
    parser.add_argument("-o", "--output", type=pathlib.Path, default=None, help="Output file (defaults to stdout)")
    parser.add_argument("--defang", action="store_true", help="Defang indicators on output")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output grouped JSON")
    parser.add_argument(
        "--only-type",
        choices=["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
        default=None,
        help="Keep only a single indicator type",
    )
    args = parser.parse_args()

    total_raw = 0
    seen: dict[str, str] = {}
    counts: collections.Counter[str] = collections.Counter()

    for path in args.inputs:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            token = refang(line.split()[0].strip(",;\"'"))
            if not token:
                continue
            total_raw += 1
            ioc_type = classify(token)
            if ioc_type in ("ipv4", "ipv6", "domain", "md5", "sha1", "sha256"):
                token = token.lower()
            if args.only_type and ioc_type != args.only_type:
                continue
            if token not in seen:
                seen[token] = ioc_type
                counts[ioc_type] += 1

    items = sorted(seen.items(), key=lambda pair: (pair[1], pair[0]))
    if args.as_json:
        grouped: dict[str, list[str]] = collections.defaultdict(list)
        for token, ioc_type in items:
            grouped[ioc_type].append(defang(token) if args.defang else token)
        rendered = json.dumps(
            {
                "input_lines": total_raw,
                "unique_indicators": len(items),
                "duplicates_removed": total_raw - len(items),
                "by_type": dict(counts),
                "indicators": dict(grouped),
            },
            indent=2,
        ) + "\n"
    else:
        rendered = "\n".join(defang(token) if args.defang else token for token, _ in items) + ("\n" if items else "")

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(
            f"Processed {total_raw} lines -> {len(items)} unique indicators "
            f"({total_raw - len(items)} removed) written to {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
