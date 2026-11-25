#!/usr/bin/env python3
"""Check IP reputation across public and API-backed threat intelligence sources."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "secops-tools-ip-checker/1.0 (+https://github.com/secops-tools/threat-intelligence-tools)"
SSL_CTX = ssl.create_default_context()


def http_get_json(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0) -> tuple[int | None, Any, str | None]:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return resp.getcode(), data, None
    except urllib.error.HTTPError as exc:
        return exc.code, None, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc)


def check_internetdb(ip: str, timeout: float) -> dict[str, Any]:
    code, data, err = http_get_json(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    if code == 404:
        return {"source": "Shodan InternetDB", "status": "clean", "summary": "No open ports or vulns indexed"}
    if err or not isinstance(data, dict):
        return {"source": "Shodan InternetDB", "status": "error", "summary": err or "Unavailable"}
    ports = data.get("ports", [])
    vulns = data.get("vulns", [])
    tags = data.get("tags", [])
    status = "suspicious" if (vulns or "compromised" in tags or "malware" in tags) else "info"
    parts = [f"ports={ports[:10]}"]
    if vulns:
        parts.append(f"cves={len(vulns)}")
    if tags:
        parts.append(f"tags={tags}")
    return {"source": "Shodan InternetDB", "status": status, "summary": ", ".join(parts), "raw": data}


def check_greynoise(ip: str, timeout: float) -> dict[str, Any]:
    headers = {}
    api_key = os.environ.get("GREYNOISE_API_KEY", "").strip()
    if api_key:
        headers["key"] = api_key
    code, data, err = http_get_json(
        f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=timeout
    )
    if code == 404:
        return {"source": "GreyNoise Community", "status": "unknown", "summary": "Not observed in internet noise"}
    if err or not isinstance(data, dict):
        return {"source": "GreyNoise Community", "status": "error", "summary": err or "Unavailable"}
    classification = data.get("classification", "unknown")
    name = data.get("name", "")
    noise = data.get("noise", False)
    riot = data.get("riot", False)
    status = "malicious" if classification == "malicious" else ("clean" if riot else "info")
    summary = f"classification={classification}, noise={noise}, riot={riot}"
    if name:
        summary += f", name={name}"
    return {"source": "GreyNoise Community", "status": status, "summary": summary, "raw": data}


def check_abuseipdb(ip: str, timeout: float) -> dict[str, Any]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {"source": "AbuseIPDB", "status": "skipped", "summary": "Set ABUSEIPDB_API_KEY to enable"}
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    code, data, err = http_get_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": api_key},
        timeout=timeout,
    )
    if err or not isinstance(data, dict) or "data" not in data:
        return {"source": "AbuseIPDB", "status": "error", "summary": err or "Unavailable"}
    info = data["data"]
    score = info.get("abuseConfidenceScore", 0)
    reports = info.get("totalReports", 0)
    country = info.get("countryCode", "?")
    status = "malicious" if score >= 50 else ("suspicious" if score > 0 else "clean")
    return {
        "source": "AbuseIPDB",
        "status": status,
        "summary": f"confidence={score}%, reports={reports}, country={country}",
        "raw": info,
    }


def check_virustotal(ip: str, timeout: float) -> dict[str, Any]:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return {"source": "VirusTotal", "status": "skipped", "summary": "Set VT_API_KEY to enable"}
    code, data, err = http_get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
        timeout=timeout,
    )
    if err or not isinstance(data, dict):
        return {"source": "VirusTotal", "status": "error", "summary": err or "Unavailable"}
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    status = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")
    return {
        "source": "VirusTotal",
        "status": status,
        "summary": f"malicious={malicious}, suspicious={suspicious}, harmless={stats.get('harmless', 0)}",
        "raw": stats,
    }


def check_otx(ip: str, timeout: float) -> dict[str, Any]:
    api_key = os.environ.get("OTX_API_KEY", "").strip()
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    code, data, err = http_get_json(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers,
        timeout=timeout,
    )
    if err or not isinstance(data, dict):
        return {"source": "AlienVault OTX", "status": "error", "summary": err or "Unavailable"}
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    status = "suspicious" if pulse_count > 0 else "clean"
    return {
        "source": "AlienVault OTX",
        "status": status,
        "summary": f"pulses={pulse_count}, asn={data.get('asn', 'unknown')}",
    }


def check_ip(ip: str, timeout: float) -> dict[str, Any]:
    ipaddress.ip_address(ip)
    checks = [
        check_internetdb(ip, timeout),
        check_greynoise(ip, timeout),
        check_otx(ip, timeout),
        check_abuseipdb(ip, timeout),
        check_virustotal(ip, timeout),
    ]
    return {"ip": ip, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check IP reputation across Shodan InternetDB, GreyNoise, OTX, AbuseIPDB, and VirusTotal."
    )
    parser.add_argument("ips", nargs="+", help="One or more IPv4/IPv6 addresses to check")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout per source (default: 10s)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON")
    args = parser.parse_args()

    results = []
    for ip in args.ips:
        try:
            results.append(check_ip(ip.strip(), args.timeout))
        except ValueError as exc:
            print(f"Invalid IP '{ip}': {exc}", file=sys.stderr)
            return 2

    if args.as_json:
        print(json.dumps(results, indent=2))
        return 0

    for entry in results:
        print(f"IP: {entry['ip']}")
        for item in entry["checks"]:
            print(f"  - {item['source']:<20} [{item['status']:<10}] {item['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
