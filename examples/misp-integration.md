# MISP feed ingestion and export automation

[MISP](https://www.misp-project.org/) ships with built-in feed management for abuse.ch, CIRCL OSINT, DigitalSide, and custom CSV or text lists. This guide covers enabling reliable public feeds and converting local IOC lists into STIX 2.1 or CSV for import.

## 1. Enable default public feeds in MISP

In the MISP web interface, open **Sync Actions > List Feeds** and click **Load default feed metadata**. Good low-noise starting feeds include:

- CIRCL OSINT Feed (`https://www.circl.lu/doc/misp/feed-osint/`)
- DigitalSide Threat-Intel OSINT Feed (`https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/`)
- ThreatFox recent IOCs (`https://threatfox.abuse.ch/export/csv/recent/`)
- URLhaus recent malicious URLs (`https://urlhaus.abuse.ch/downloads/csv_recent/`)

Enable caching on each feed before enabling full event ingestion so you can test correlation volume without filling the MISP database with noisy attributes.

## 2. Convert custom text lists into STIX 2.1

If your team collects indicators in plain text or CSV files, convert them into a STIX 2.1 bundle with `scripts/convert-feed.py` before uploading to MISP or OpenCTI:

```bash
python3 scripts/dedupe-iocs.py raw-iocs.txt -o clean-iocs.txt
python3 scripts/convert-feed.py clean-iocs.txt stix-bundle.json --from txt --to stix
```

You can also convert CSV exports from ThreatFox or MalwareBazaar into JSON for downstream pipelines:

```bash
python3 scripts/convert-feed.py threatfox-recent.csv threatfox-recent.json --from csv --to json
```

## 3. Push indicators to MISP via REST API

Once you have a clean indicator list, create an event and attach attributes through the MISP REST API:

```bash
curl -fsSL -X POST "https://misp.example.internal/events/add" \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "info": "Automated public blocklist sync",
    "distribution": "0",
    "threat_level_id": "2",
    "analysis": "1"
  }'
```

Set `to_ids: true` only on indicators you have vetted for automated firewall or IDS blocking. Use `to_ids: false` for enrichment-only observables so you avoid breaking legitimate traffic.
