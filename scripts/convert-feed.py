#!/usr/bin/env python3
"""Convert threat intelligence feeds between JSON, CSV, plain text, and STIX 2.1 bundles."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import pathlib
import re
import sys
import uuid
from typing import Any

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> str:
    val = value.strip()
    try:
        ip = ipaddress.ip_address(val)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        pass
    if val.startswith(("http://", "https://", "ftp://")):
        return "url"
    if SHA256_RE.match(val):
        return "sha256"
    if SHA1_RE.match(val):
        return "sha1"
    if MD5_RE.match(val):
        return "md5"
    if "." in val and " " not in val:
        return "domain"
    return "unknown"


def read_records(path: pathlib.Path, input_format: str) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if input_format == "json":
        data = json.loads(text)
        if isinstance(data, dict) and "objects" in data:
            records = []
            for obj in data["objects"]:
                if obj.get("type") == "indicator":
                    records.append(
                        {
                            "indicator": obj.get("name") or obj.get("pattern", ""),
                            "type": obj.get("indicator_types", ["unknown"])[0],
                            "pattern": obj.get("pattern", ""),
                        }
                    )
            return records
        if isinstance(data, list):
            return [row if isinstance(row, dict) else {"indicator": str(row), "type": detect_ioc_type(str(row))} for row in data]
        raise ValueError("Unsupported JSON structure: expected a list or STIX bundle.")
    if input_format == "csv":
        lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        reader = csv.DictReader(lines)
        return [dict(row) for row in reader]
    if input_format == "txt":
        records = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            token = line.split()[0]
            records.append({"indicator": token, "type": detect_ioc_type(token)})
        return records
    raise ValueError(f"Unsupported input format: {input_format}")


def to_stix_pattern(indicator: str, ioc_type: str) -> str:
    escaped = indicator.replace("'", "\\'")
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{escaped}']"
    if ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{escaped}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if ioc_type == "url":
        return f"[url:value = '{escaped}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{escaped}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{escaped}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{escaped}']"
    return f"[x-custom:value = '{escaped}']"


def write_records(records: list[dict[str, Any]], output_path: pathlib.Path, output_format: str) -> None:
    if output_format == "json":
        output_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        return
    if output_format == "csv":
        if not records:
            output_path.write_text("", encoding="utf-8")
            return
        fieldnames: list[str] = []
        for row in records:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        with output_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
        return
    if output_format == "txt":
        values = []
        for row in records:
            val = row.get("indicator") or row.get("ioc") or row.get("ip") or next(iter(row.values()), "")
            if val:
                values.append(str(val))
        output_path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")
        return
    if output_format == "stix":
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects = []
        for row in records:
            val = str(row.get("indicator") or row.get("ioc") or row.get("ip") or next(iter(row.values()), "")).strip()
            if not val:
                continue
            ioc_type = row.get("type") or detect_ioc_type(val)
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": val,
                    "indicator_types": ["malicious-activity"],
                    "pattern": to_stix_pattern(val, ioc_type),
                    "pattern_type": "stix",
                    "valid_from": now,
                }
            )
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }
        output_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        return
    raise ValueError(f"Unsupported output format: {output_format}")


def infer_format(path: pathlib.Path) -> str:
    ext = path.suffix.lower().lstrip(".")
    if ext in ("json", "csv", "txt", "stix"):
        return ext
    return "txt"


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert threat feeds between JSON, CSV, TXT, and STIX 2.1.")
    parser.add_argument("input_file", type=pathlib.Path, help="Input feed file")
    parser.add_argument("output_file", type=pathlib.Path, help="Output file path")
    parser.add_argument("--from", dest="from_fmt", choices=["json", "csv", "txt"], default=None, help="Input format")
    parser.add_argument("--to", dest="to_fmt", choices=["json", "csv", "txt", "stix"], default=None, help="Output format")
    args = parser.parse_args()

    in_fmt = args.from_fmt or infer_format(args.input_file)
    out_fmt = args.to_fmt or infer_format(args.output_file)
    records = read_records(args.input_file, in_fmt)
    write_records(records, args.output_file, out_fmt)
    print(f"Converted {len(records)} records from {in_fmt} to {out_fmt}: {args.output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
