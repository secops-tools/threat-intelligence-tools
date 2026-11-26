# Best Threat Intelligence Tools, Platforms & Feeds

A directory of threat intelligence tools, platforms, APIs, and feeds for security engineers, SOC analysts, and system administrators. Each entry lists supported data formats (JSON, CSV, STIX, TAXII, MISP), API key requirements, free tier limits, commercial use terms, integrations, and self-hosting options.

<!-- START:STATS -->
Catalog size: 106 threat intelligence tools, 18 threat intelligence platforms, and 52 threat intelligence feeds (52/52 feeds reachable as of 2026-11-26 16:10 UTC).
<!-- END:STATS -->

## Quick comparison of popular threat intelligence tools

Most teams start with these tools and feeds when checking IPs, domains, URLs, and malware hashes.

<!-- START:FEATURED -->
| Tool / Source | Purpose | Product type | Formats | API key | Self-hosted |
| --- | --- | --- | --- | --- | --- |
| [VirusTotal](https://www.virustotal.com/) | Inspect files, URLs, domains, and IPs across 70+ antivirus engines and blocklists | API / SaaS | JSON | Required | No |
| [AbuseIPDB](https://www.abuseipdb.com/) | Crowdsourced IP abuse reports, confidence scoring, and blocklist exports | API / SaaS | JSON, CSV, TXT | Required | No |
| [GreyNoise](https://www.greynoise.io/) | Separate internet background scanners from targeted attacks | API / SaaS | JSON, CSV | Optional (Community) | No |
| [urlscan.io](https://urlscan.io/) | Render suspicious URLs in a headless browser and inspect DOM, network calls, and screenshots | API / SaaS | JSON | Required for submissions | No |
| [Shodan](https://www.shodan.io/) | Internet-wide banner search for open ports, services, SSL certificates, and CVEs | API / SaaS | JSON, CSV | Required (InternetDB is keyless) | No |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Community malware sample repository with hashes, YARA rules, and family tags | Feed / API | JSON, CSV, TXT | Required for API (free Auth-Key) | No |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Authoritative list of CVEs actively exploited in the wild with remediation due dates | Open Data / Feed | JSON, CSV | None | No |
| [MISP](https://www.misp-project.org/) | IOC storage, automated correlation, and threat sharing across SOC teams and ISACs | Open source | JSON, CSV, STIX, TAXII | Self-managed | Yes |
| [OpenCTI](https://www.opencti.io/) | STIX 2.1 knowledge graph connecting indicators, threat actors, campaigns, and MITRE ATT&CK | Open source | STIX, TAXII, JSON, CSV | Self-managed | Yes |
| [Recorded Future](https://www.recordedfuture.com/) | Real-time intelligence graph combining open web, dark web, technical feeds, and analyst reports | Enterprise | JSON, CSV, STIX, TAXII | Required | No |
| [Google Threat Intelligence (Mandiant)](https://cloud.google.com/security/products/threat-intelligence) | Frontline incident response intelligence paired with VirusTotal telemetry and actor tracking | Enterprise | JSON, STIX, TAXII | Required | No |
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | Multi-IOC & C2 (IP, Domain, URL, Hash) | Threat Feed | JSON, CSV, STIX, MISP | None (exports) / Free key (API) | No |
<!-- END:FEATURED -->

## Contents

- [Threat intelligence feed status](#threat-intelligence-feed-status)
- [Threat intelligence platforms](#threat-intelligence-platforms)
- [Threat intelligence tools by category](#threat-intelligence-tools-by-category)
- [Threat intelligence feeds by category](#threat-intelligence-feeds-by-category)
- [Included CLI utilities](#included-cli-utilities)
- [Integration examples](#integration-examples)
- [Contributing](#contributing)

## Threat intelligence feed status

A GitHub Actions job runs `scripts/check-feeds.py` once a day and writes live HTTP status, response latency, `Last-Modified` headers, and a basic content check into `data/feed-status.json`.

Endpoint reachability does not prove that indicators inside a feed are fresh or low in false positives. Check the `Last-Modified` header, the published update cycle, and your own allowlist before blocking traffic in production.

<!-- START:FEED_STATUS -->
| Feed | Status | Response | Last-Modified header | Format check | Formats | API key |
| --- | --- | --- | --- | --- | --- | --- |
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | Online | 272 ms | - | HTML page | JSON, CSV, STIX | None (exports) / Free key (API) |
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) | Online | 263 ms | - | HTML page | CSV, TXT, RPZ | None (exports) / Free key (API) |
| [MalwareBazaar Recent (abuse.ch)](https://bazaar.abuse.ch/) | Online | 287 ms | - | HTML page | CSV, JSON, TXT | None (exports) / Free key (API) |
| [Feodo Tracker IP Blocklist (abuse.ch)](https://feodotracker.abuse.ch/) | Online | 259 ms | 2026-06-30 04:53 UTC | OK (1+ rows) | TXT, CSV, JSON | None |
| [SSL Blacklist (abuse.ch)](https://sslbl.abuse.ch/) | Online | 251 ms | 2026-06-30 04:53 UTC | Header only | TXT, CSV, Suricata | None |
| [AlienVault OTX](https://otx.alienvault.com/) | Online (Auth/Rate-Limit) | 202 ms | - | HTTP 403 | JSON, CSV, STIX | Required (free) |
| [AbuseIPDB Blacklist](https://www.abuseipdb.com/) | Online (Auth/Rate-Limit) | 122 ms | - | HTTP 403 | JSON, TXT | Required (free tier) |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Online | 131 ms | 2026-11-25 13:24 UTC | OK (1737+ rows) | TXT, JSON | None |
| [Spamhaus DROPv6](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Online | 118 ms | 2026-11-20 09:32 UTC | OK (90+ rows) | TXT, JSON | None |
| [Emerging Threats Compromised IPs](https://rules.emergingthreats.net/) | Online | 185 ms | 2026-11-25 20:19 UTC | OK (568+ rows) | TXT | None |
| [CINSscore CI Army Badguys](https://cinsscore.com/) | Online | 190 ms | 2026-11-26 16:04 UTC | OK (4823+ rows) | TXT | None |
| [Blocklist.de All Attackers](https://www.blocklist.de/en/export.html) | Online | 189 ms | 2026-11-26 15:54 UTC | OK (4495+ rows) | TXT | None |
| [Blocklist.de SSH Brute Force](https://www.blocklist.de/en/export.html) | Online | 69 ms | 2026-11-26 15:54 UTC | OK (4563+ rows) | TXT | None |
| [Blocklist.de Apache / Web Attackers](https://www.blocklist.de/en/export.html) | Online | 58 ms | 2026-11-26 15:54 UTC | OK (4449+ rows) | TXT | None |
| [FireHOL Level 1](https://iplists.firehol.org/) | Online | 78 ms | - | OK (4114+ rows) | TXT (netset) | None |
| [FireHOL Level 2](https://iplists.firehol.org/) | Online | 56 ms | - | OK (4704+ rows) | TXT (netset) | None |
| [FireHOL Level 3](https://iplists.firehol.org/) | Online | 66 ms | - | OK (4730+ rows) | TXT (netset) | None |
| [SANS ISC DShield Top Attackers](https://www.dshield.org/) | Online | 119 ms | 2026-11-26 15:44 UTC | OK (20+ rows) | TXT | None |
| [GreenSnow IP Blocklist](https://greensnow.co/) | Online | 722 ms | 2026-11-26 16:10 UTC | OK (2332+ rows) | TXT | None |
| [Binary Defense Artillery Banlist](https://www.binarydefense.com/) | Online | 392 ms | 2026-11-25 23:57 UTC | OK (475+ rows) | TXT | None |
| [IPsum (Level 3+ Aggregated)](https://github.com/stamparm/ipsum) | Online | 69 ms | - | OK (4653+ rows) | TXT | None |
| [Tor Project Bulk Exit List](https://check.torproject.org/) | Online | 465 ms | 2026-11-26 15:48 UTC | OK (1260+ rows) | TXT | None |
| [Cisco Talos IP Blacklist](https://talosintelligence.com/) | Online (Auth/Rate-Limit) | 96 ms | - | HTTP 403 | TXT | None |
| [StopForumSpam Toxic IPs (7d)](https://www.stopforumspam.com/) | Online | 269 ms | - | OK (4777+ rows) | TXT | None |
| [DigitalSide Threat-Intel IPs](https://osint.digitalside.it/) | Online | 163 ms | - | OK (4398+ rows) | TXT, CSV, MISP | None |
| [DigitalSide Threat-Intel Domains](https://osint.digitalside.it/) | Online | 93 ms | - | OK (133+ rows) | TXT, CSV, MISP | None |
| [DigitalSide Threat-Intel URLs](https://osint.digitalside.it/) | Online | 307 ms | - | OK (1968+ rows) | TXT, CSV, MISP | None |
| [OpenPhish Community Feed](https://openphish.com/) | Online | 616 ms | - | OK (300+ rows) | TXT | None |
| [PhishTank Verified Phishing](https://phishtank.org/) | Online | 285 ms | - | HTML page | JSON, CSV, XML | Optional (free key recommended) |
| [CERT.pl Phishing Warning List](https://cert.pl/en/warning-list/) | Online | 828 ms | 2026-11-26 16:05 UTC | OK (3104+ rows) | TXT, JSON, CSV | None |
| [Phishing.Database Active Domains](https://github.com/Phishing-Database/Phishing.Database) | Online | 166 ms | - | OK (2325+ rows) | TXT | None |
| [Phishing Army Blocklist](https://phishing.army/) | Online | 405 ms | 2026-11-26 14:01 UTC | OK (2955+ rows) | TXT | None |
| [HaGeZi Threat Intelligence Feeds (Mini)](https://github.com/hagezi/dns-blocklists) | Online | 57 ms | - | OK (2336+ rows) | TXT, RPZ, Hosts | None |
| [StevenBlack Malware & Adware Hosts](https://github.com/StevenBlack/hosts) | Online | 43 ms | - | OK (2116+ rows) | Hosts, TXT | None |
| [ThreatView.io Malicious Domains](https://threatview.io/) | Online | 674 ms | 2026-11-26 03:06 UTC | OK (4017+ rows) | TXT | None |
| [ThreatView.io High-Confidence IPs](https://threatview.io/) | Online | 657 ms | 2026-11-26 03:06 UTC | OK (4481+ rows) | TXT | None |
| [ThreatView.io Malware MD5 Hashes](https://threatview.io/) | Online | 646 ms | 2026-11-26 03:06 UTC | OK (1986+ rows) | TXT | None |
| [Malicious IP (romainmarcoux 40k)](https://github.com/romainmarcoux/malicious-ip) | Online | 66 ms | - | OK (4468+ rows) | TXT | None |
| [CIRCL OSINT MISP Feed](https://www.circl.lu/doc/misp/feed-osint/) | Online | 706 ms | 2026-11-26 06:39 UTC | JSON stream | MISP JSON | None |
| [Botvrij.eu IOC Lists](https://www.botvrij.eu/) | Online | 291 ms | 2026-02-03 07:58 UTC | OK (4+ rows) | TXT, MISP JSON | None |
| [TweetFeed Live IOCs](https://tweetfeed.live/) | Online | 209 ms | 2026-11-26 15:30 UTC | Valid JSON | JSON, CSV | None |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Online | 166 ms | 2026-11-25 19:48 UTC | JSON stream | JSON, CSV | None |
| [FIRST EPSS Probability Feed](https://www.first.org/epss/) | Online | 268 ms | - | Valid JSON | JSON, CSV | None |
| [NIST NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Online | 1211 ms | - | Valid JSON | JSON | Optional (higher quota) |
| [OSV.dev Vulnerability API](https://osv.dev/) | Online | 178 ms | - | Valid JSON | JSON | None |
| [Shodan InternetDB API](https://internetdb.shodan.io/) | Online | 62 ms | 2026-11-26 10:01 UTC | Valid JSON | JSON | None |
| [GreyNoise Community API](https://docs.greynoise.io/reference/get_v3-community-ip) | Online (Auth/Rate-Limit) | 162 ms | - | HTTP 401 | JSON | Optional (free key for 50/wk) |
| [Ransomware.live Victims API](https://www.ransomware.live/) | Online | 763 ms | - | JSON stream | JSON, RSS | None (public endpoints) |
| [MITRE ATT&CK Enterprise STIX](https://attack.mitre.org/) | Online | 84 ms | - | Valid JSON | STIX, JSON | None |
| [Malpedia Public API](https://malpedia.caad.fkie.fraunhofer.de/) | Online | 13400 ms | - | Valid JSON | JSON, YARA | None (metadata) / Vetted (samples) |
| [YARAify (abuse.ch)](https://yaraify.abuse.ch/) | Online | 406 ms | - | HTML page | JSON, YARA | Free Auth-Key for API |
| [Proofpoint Emerging Threats Open Rules](https://rules.emergingthreats.net/open/) | Online | 218 ms | 2026-11-25 20:19 UTC | OK (1+ rows) | Suricata, Snort | None |
<!-- END:FEED_STATUS -->

## Threat intelligence platforms

Open-source threat intelligence platforms handle local IOC storage and correlation without per-seat licensing. Commercial platforms add closed-source collection, analyst reporting, and vendor SLAs.

<!-- START:PLATFORMS -->
| Platform | Type | Purpose | Formats | License | Commercial use | Self-hosted | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [MISP](https://www.misp-project.org/) | Open source | IOC storage, automated correlation, and threat sharing across SOC teams and ISACs | JSON, CSV, STIX, TAXII | AGPL-3.0 | Yes | Yes | OpenCTI, TheHive, Splunk, Elastic |
| [OpenCTI](https://www.opencti.io/) | Open source | STIX 2.1 knowledge graph connecting indicators, threat actors, campaigns, and MITRE ATT&CK | STIX, TAXII, JSON, CSV | Apache-2.0 (EE modules commercial) | Yes | Yes | MISP, Splunk, Elastic, Sentinel |
| [Yeti](https://yeti-platform.io/) | Open source | Lightweight observable and threat intelligence repository built for fast enrichment and analytics | JSON, CSV, STIX, MISP | Apache-2.0 | Yes | Yes | MISP, Timesketch, DFIR-IRIS, VirusTotal |
| [Collective Intelligence Framework (CIFv4)](https://github.com/csirtgadgets/bearded-avenger) | Open source | High-speed IOC ingestion, deduplication, and firewall/DNS blocklist generation | JSON, CSV, STIX, Bind | MPL-2.0 | Yes | Yes | Snort, Suricata, Bro/Zeek, BIND |
| [ThreatIngestor](https://github.com/InQuest/ThreatIngestor) | Open source | Modular pipeline that pulls IOCs from RSS, GitHub, and feeds into MISP, CSV, or SIEMs | CSV, JSON, MISP | GPL-2.0 | Yes | Yes | MISP, ThreatKB, SQLite, SQS |
| [OpenTAXII](https://github.com/eclecticiq/OpenTAXII) | Open source | Python TAXII 1.x server implementation for hosting and sharing STIX feeds | STIX, TAXII | BSD-3-Clause | Yes | Yes | MISP, Splunk, QRadar, TAXII clients |
| [OASIS Medallion](https://github.com/oasis-open/cti-taxii-server) | Open source | Reference TAXII 2.1 server backed by MongoDB or memory for distributing STIX 2.1 bundles | STIX, TAXII, JSON | BSD-3-Clause | Yes | Yes | OpenCTI, TAXII 2.1 clients, Sentinel |
| [Recorded Future](https://www.recordedfuture.com/) | Enterprise | Real-time intelligence graph combining open web, dark web, technical feeds, and analyst reports | JSON, CSV, STIX, TAXII | Proprietary | Paid only | No | Splunk, Sentinel, QRadar, CrowdStrike |
| [Google Threat Intelligence (Mandiant)](https://cloud.google.com/security/products/threat-intelligence) | Enterprise | Frontline incident response intelligence paired with VirusTotal telemetry and actor tracking | JSON, STIX, TAXII | Proprietary | Paid only | No | Google SecOps, Splunk, Sentinel, OpenCTI |
| [CrowdStrike Falcon Intelligence](https://www.crowdstrike.com/products/threat-intelligence/) | Enterprise | Automated EDR-linked indicator feeds, malware sandbox, and nation-state adversary profiles | JSON, STIX, TAXII, CSV | Proprietary | Paid only | No | CrowdStrike Falcon, Splunk, Sentinel, OpenCTI |
| [ThreatConnect](https://threatconnect.com/) | Enterprise | Combined TIP and SOAR platform with CAL telemetry scoring and risk quantification | JSON, CSV, STIX, TAXII | Proprietary | Paid only | Yes | Splunk, QRadar, Sentinel, CrowdStrike |
| [Anomali ThreatStream](https://www.anomali.com/products/threatstream) | Enterprise | High-volume feed aggregation, IOC lifecycle management, and SIEM/firewall distribution | JSON, CSV, STIX, TAXII | Proprietary | Paid only | Yes | Splunk, QRadar, Sentinel, Elastic |
| [EclecticIQ Intelligence Center](https://www.eclecticiq.com/) | Enterprise | STIX-native analyst workbench built for government CERTs, ISACs, and mature CTI teams | STIX, TAXII, JSON, CSV | Proprietary | Paid only | Yes | Splunk, QRadar, Sentinel, MISP |
| [ThreatQ (ThreatQuotient)](https://www.threatq.com/) | Enterprise | Data-driven TIP with custom scoring policies and bidirectional orchestration | JSON, CSV, STIX, TAXII | Proprietary | Paid only | Yes | Splunk, QRadar, CrowdStrike, ServiceNow |
| [Flashpoint Ignite](https://flashpoint.io/) | Enterprise | Closed-source cybercrime forums, illicit messaging channels, and vulnerability intelligence | JSON, CSV, STIX, TAXII | Proprietary | Paid only | No | Splunk, Sentinel, OpenCTI, MISP |
| [Intel 471 TITAN](https://intel471.com/) | Enterprise | Adversary-focused cybercrime, malware tracker, and underground intelligence | JSON, STIX, TAXII, YARA | Proprietary | Paid only | No | OpenCTI, MISP, Splunk, Sentinel |
| [SOCRadar](https://socradar.io/) | Enterprise / Freemium | External attack surface monitoring, brand protection, and dark web threat feeds | JSON, CSV, STIX, TAXII | Proprietary | Paid for enterprise | No | Splunk, Sentinel, QRadar, Wazuh |
| [Cyware Intel Exchange](https://www.cyware.com/) | Enterprise | Automated STIX/TAXII threat sharing, confidence scoring, and ISAC/ISAO collaboration | STIX, TAXII, JSON, CSV | Proprietary | Paid only | Yes | Splunk, QRadar, Sentinel, CrowdStrike |
<!-- END:PLATFORMS -->

## Threat intelligence tools by category

Every tool listed below is grouped by its primary job. Commercial use reflects the license or terms of the free tier; paid plans generally permit commercial deployment.

<!-- START:TOOLS -->
### IP, Domain & URL Reputation

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [VirusTotal](https://www.virustotal.com/) | API / SaaS | Inspect files, URLs, domains, and IPs across 70+ antivirus engines and blocklists | JSON | Required | 4 req/min, 500 req/day | Paid only | No |
| [AbuseIPDB](https://www.abuseipdb.com/) | API / SaaS | Crowdsourced IP abuse reports, confidence scoring, and blocklist exports | JSON, CSV, TXT | Required | 1,000 checks/day | Paid for commercial use | No |
| [GreyNoise](https://www.greynoise.io/) | API / SaaS | Separate internet background scanners from targeted attacks | JSON, CSV | Optional (Community) | 50 req/week (Community API) | Paid only | No |
| [urlscan.io](https://urlscan.io/) | API / SaaS | Render suspicious URLs in a headless browser and inspect DOM, network calls, and screenshots | JSON | Required for submissions | 5,000 public scans/day | Paid for private scans | No |
| [Shodan](https://www.shodan.io/) | API / SaaS | Internet-wide banner search for open ports, services, SSL certificates, and CVEs | JSON, CSV | Required (InternetDB is keyless) | Limited web queries; InternetDB free | Paid only | No |
| [Censys](https://search.censys.io/) | API / SaaS | Host and certificate search for tracking C2 infrastructure and exposed assets | JSON | Required | 250 queries/month | Paid only | No |
| [Cisco Talos Intelligence](https://talosintelligence.com/) | Web / SaaS | Check IP, domain, email sender reputation, and file SHA-256 verdicts | Web, TXT | None (web) | Web lookup free; API via Cisco SecureX | Reference only | No |
| [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) | API / SaaS | IP, URL, malware hash, and vulnerability lookup with STIX/TAXII collections | JSON, STIX, TAXII | Required for API | 5,000 records/month | Paid for commercial API | No |
| [Pulsedive](https://pulsedive.com/) | API / SaaS | Enrich IPs, domains, and URLs with risk scores, linked feeds, and active scans | JSON, CSV, STIX | Required for API | 30 req/min (Community) | Paid for commercial feeds | No |
| [Spur](https://spur.us/) | API / SaaS | Identify residential proxies, VPNs, Tor exits, and anonymization infrastructure | JSON | Required | Limited web lookups | Paid only | No |
| [Criminal IP](https://www.criminalip.io/) | API / SaaS | IP scoring, domain phishing detection, and exposed banner search | JSON | Required | 50 credits/month | Paid only | No |
| [IPQualityScore](https://www.ipqualityscore.com/) | API / SaaS | Proxy, VPN, botnet, and malicious URL reputation scoring | JSON, CSV | Required | 5,000 lookups/month | Yes (tier limits) | No |
| [CrowdSec CTI](https://www.crowdsec.net/cyber-threat-intelligence) | API / SaaS | Crowdsourced IP behavior intelligence gathered from global CrowdSec sensors | JSON | Required | 50 queries/day (Community) | Paid for commercial API | No |
| [Maltiverse](https://maltiverse.com/) | API / SaaS | Open IOC search engine scoring IPs, hostnames, URLs, and file hashes | JSON, STIX, MISP | Required for API | 100 req/day (Community) | Paid for commercial API | No |
| [IPinfo](https://ipinfo.io/) | API / SaaS | IP geolocation, ASN ownership, privacy/VPN detection, and abuse contacts | JSON, CSV, MMDB | Required | 50,000 req/month | Yes (tier limits) | No |
| [Team Cymru Scout](https://www.team-cymru.com/pure-signal-scout) | Enterprise / API | NetFlow-backed IP, ASN, and passive DNS context for threat hunting | JSON | Required | Free IP-to-ASN DNS/WHOIS; Scout paid | Paid only | No |
| [Onyphe](https://www.onyphe.io/) | API / SaaS | Cyber defense search engine correlating internet scans with threat lists | JSON, CSV | Required | Limited web lookups | Paid only | No |
| [LeakIX](https://leakix.net/) | API / SaaS | Index exposed databases, open services, and leaked configs across IPv4 | JSON | Optional (higher limits with key) | Rate-limited community API | Paid for commercial API | No |
| [RIPEstat](https://stat.ripe.net/) | Open Data / API | BGP routing, RPKI, ASN prefix, and abuse contact lookups from RIPE NCC | JSON | None | Unlimited (fair use) | Yes | No |
| [Spamhaus Lookup](https://check.spamhaus.org/) | DNSBL / API | Check IP and domain listings across SBL, XBL, PBL, DBL, and ZRD zones | DNS, JSON | Optional (DQS free key) | Free for non-commercial low volume | Paid (DQS commercial) | No |
| [Scamalytics](https://scamalytics.com/ip) | API / SaaS | IP fraud scoring for proxy, datacenter, and residential abuse detection | JSON | Required for API | 5,000 queries/month | Yes (tier limits) | No |
| [CyberGordon](https://cybergordon.com/) | Web / SaaS | Bulk enrichment of up to 100 IPs, domains, or hashes across 15+ public engines | CSV, Web | None (web) | Free web queries | Yes (web tier) | No |

### Malware Analysis & Sandboxes

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Feed / API | Community malware sample repository with hashes, YARA rules, and family tags | JSON, CSV, TXT | Required for API (free Auth-Key) | Generous free community access | Yes | No |
| [ANY.RUN](https://any.run/) | SaaS / API | Interactive cloud malware sandbox with live process trees, PCAPs, and IOC extraction | JSON, STIX, MISP | Required for API | Public Windows VM analyses | Paid only | No |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | API / SaaS | Automated Falcon Sandbox malware detonation, behavioral scoring, and IOC reports | JSON, STIX, CSV | Required | 200 req/min public queries | Paid for private API | No |
| [Hatching Tria.ge](https://tria.ge/) | API / SaaS | High-throughput malware sandbox extracting C2 configs, signatures, and memory dumps | JSON, PCAP | Required | Public researcher tier | Paid only | No |
| [Joe Sandbox](https://www.joesandbox.com/) | SaaS / On-prem | Deep malware analysis across Windows, Linux, macOS, and Android with MITRE mapping | JSON, STIX, MISP | Required | Limited public community submissions | Paid only | Yes |
| [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) | Open source | Open-source automated malware detonation, payload unpacking, and C2 config extraction | JSON, MISP, PCAP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [YARA](https://virustotal.github.io/yara/) | Open source | Pattern-matching engine for classifying malware binaries, memory dumps, and files | YARA rules, JSON | None | Unlimited (local) | Yes | Yes |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Research / API | Curated malware family encyclopedia, unpacked samples, YARA rules, and actor links | JSON, YARA, BibTeX | Required (vetted accounts for samples) | Public metadata and API free | Metadata yes; samples restricted | No |
| [UnpacMe](https://www.unpac.me/) | API / SaaS | Automated malware unpacking service returning decrypted payloads and YARA hits | JSON | Required for API | Limited public uploads | Paid only | No |
| [Intezer Analyze](https://analyze.intezer.com/) | API / SaaS | Genetic code-reuse analysis to attribute malware binaries to known families | JSON | Required | Community tier with daily cap | Paid only | No |
| [Mandiant Capa](https://github.com/mandiant/capa) | Open source | Identify malware capabilities in PE, ELF, and .NET binaries mapped to MITRE ATT&CK | JSON, YAML rules | None | Unlimited (local) | Yes | Yes |
| [Mandiant FLOSS](https://github.com/mandiant/flare-floss) | Open source | Automatically deobfuscate stack strings and encoded C2 strings from malware binaries | JSON, TXT | None | Unlimited (local) | Yes | Yes |
| [Ghidra](https://ghidra-sre.org/) | Open source | Open-source reverse engineering suite with decompiler for static malware analysis | Binaries, JSON, Python/Java scripts | None | Unlimited (local) | Yes | Yes |
| [Rizin](https://rizin.re/) | Open source | Scriptable reverse engineering and binary analysis framework (with Cutter GUI) | JSON, Binaries | None | Unlimited (local) | Yes | Yes |
| [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox) | Open source | Agentless Xen-based malware sandbox resistant to VM-evasion techniques | JSON, PCAP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [MWDB (CERT.pl)](https://github.com/CERT-Polska/mwdb-core) | Open source | Self-hosted malware repository for tracking samples, static configs, and family relationships | JSON, MISP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy) | Open source | Identify packers, compilers, cryptors, and file formats across Windows, Linux, and macOS binaries | JSON, TXT | None | Unlimited (local) | Yes | Yes |
| [ClamAV](https://www.clamav.net/) | Open source | Open-source antivirus engine supporting custom YARA and hash signatures | CVD, YARA, HDB | None | Unlimited (self-hosted) | Yes | Yes |
| [VirusShare](https://virusshare.com/) | Research / API | Large community malware sample and hash archive for security researchers | JSON, TXT | Required (vetted account) | Free for vetted researchers | Research only | No |
| [Qu1cksc0pe](https://github.com/CYB3RMX/Qu1cksc0pe) | Open source | CLI static analysis tool for Windows, Linux, macOS, Android, and document malware | TXT, JSON | Optional (VirusTotal) | Unlimited (local) | Yes | Yes |

### OSINT & Infrastructure Pivot

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Open source | Automated OSINT reconnaissance across 200+ threat intel and DNS data sources | JSON, CSV, GEXF | Optional per module | Unlimited (self-hosted) | Yes | Yes |
| [Maltego](https://www.maltego.com/) | Desktop / Enterprise | Link-analysis graph workspace for pivoting across domains, IPs, certs, and actors | CSV, GraphML, STIX | Required per transform | Community Edition (limited entities) | Paid only | Yes |
| [OWASP Amass](https://github.com/owasp-amass/amass) | Open source | Attack surface mapping and passive/active subdomain and ASN enumeration | JSON, TXT | Optional per data source | Unlimited (local) | Yes | Yes |
| [SecurityTrails](https://securitytrails.com/) | API / SaaS | Historical DNS, WHOIS, and associated domain lookups for infrastructure tracking | JSON | Required | 50 API queries/month | Paid only | No |
| [DomainTools Iris](https://www.domaintools.com/products/iris-investigate/) | Enterprise / API | Domain risk scoring, passive DNS, and WHOIS pivoting for adversary infrastructure | JSON, CSV | Required | No free API tier | Paid only | No |
| [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/) | API / SaaS | Passive DNS, SSL certificates, trackers, and host pairs (formerly RiskIQ PassiveTotal) | JSON | Required for API | Free community web access | Paid for API | No |
| [Silent Push](https://www.silentpush.com/) | API / SaaS | Pre-attack infrastructure fingerprinting using DNS, web content, and ASN patterns | JSON, STIX | Required | Community Edition available | Paid only | No |
| [Validin](https://www.validin.com/) | API / SaaS | Passive DNS, virtual host, and HTTP response pivoting for threat hunting | JSON, CSV | Required for API | Free community tier | Paid for commercial API | No |
| [crt.sh](https://crt.sh/) | Web / API | Certificate Transparency log search for discovering newly issued phishing domains | JSON, Atom, PostgreSQL | None | Rate-limited public access | Yes | No |
| [theHarvester](https://github.com/laramies/theHarvester) | Open source | CLI tool for gathering emails, subdomains, IPs, and URLs from public sources | JSON, XML | Optional per source | Unlimited (local) | Yes | Yes |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | Open source | Modular Python reconnaissance framework with marketplace data modules | JSON, CSV, XML | Optional per module | Unlimited (local) | Yes | Yes |
| [dnstwist](https://github.com/elceef/dnstwist) | Open source | Detect typosquatting, homograph phishing domains, and rogue MX records | JSON, CSV, TXT | None | Unlimited (local) | Yes | Yes |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Open source | Fast passive subdomain discovery aggregating 50+ certificate and DNS providers | JSON, TXT | Optional per provider | Unlimited (local) | Yes | Yes |
| [httpx](https://github.com/projectdiscovery/httpx) | Open source | Multi-purpose HTTP prober capturing titles, TLS fingerprints, JARM, and favicon hashes | JSON, CSV, TXT | None | Unlimited (local) | Yes | Yes |
| [DNSDumpster](https://dnsdumpster.com/) | Web / API | Passive DNS reconnaissance mapping subdomains, MX/TXT records, and ASN hosts | JSON, XLSX, Web | Required for API | Free web queries; limited free API | Paid for commercial API | No |
| [Hurricane Electric BGP Toolkit](https://bgp.he.net/) | Web | ASN peering, IP prefix allocations, RPKI, and reverse DNS lookups | Web | None | Free web lookups | Yes (manual lookup) | No |
| [ViewDNS.info](https://viewdns.info/) | Web / API | Reverse IP, reverse WHOIS, DNS history, and Chinese firewall checks | JSON, XML | Required for API | Free web tools; paid API | Paid for API | No |
| [Intelligence X](https://intelx.io/) | API / SaaS | Search engine for darknet sites, paste dumps, WHOIS records, and historical web archives | JSON, TXT | Required | Limited free searches | Paid only | No |
| [PublicWWW](https://publicwww.com/) | Web / API | Search HTML, JavaScript, and analytics IDs across websites to link phishing kits and C2 lures | CSV, TXT | Required for API | Top results free on web | Paid for API | No |

### Network & Detection Engineering

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Suricata](https://suricata.io/) | Open source | High-speed IDS/IPS and network security monitor with native IOC and rule matching | EVE JSON, PCAP, Suricata rules | None | Unlimited (self-hosted) | Yes | Yes |
| [Zeek](https://zeek.org/) | Open source | Network traffic analyzer with a built-in Intel Framework for real-time IOC matching | TSV, JSON, Zeek Intel | None | Unlimited (self-hosted) | Yes | Yes |
| [Arkime](https://arkime.com/) | Open source | Large-scale full-packet capture indexing and search for retrospective IOC hunts | PCAP, JSON, CSV | None | Unlimited (self-hosted) | Yes | Yes |
| [Sigma](https://github.com/SigmaHQ/sigma) | Open source | Generic SIEM detection rule format translatable to Splunk, Elastic, Sentinel, and QRadar | YAML | None | Unlimited | Yes | Yes |
| [Netlas](https://netlas.io/) | API / SaaS | Internet scan search engine covering HTTP responses, DNS, WHOIS, and TLS certs | JSON, CSV | Required | 50 req/day | Paid only | No |
| [FOFA](https://en.fofa.info/) | API / SaaS | Cyberspace asset search engine useful for mapping C2 panels and exposed services | JSON, CSV | Required for API | Limited web search | Paid only | No |
| [ZoomEye](https://www.zoomeye.ai/) | API / SaaS | Host and web component search engine for tracking exposed infrastructure | JSON | Required | 10,000 results/month (registered) | Paid only | No |
| [Snort](https://www.snort.org/) | Open source | Open-source network IDS/IPS matching packet signatures and IP reputation lists | Snort rules, JSON, PCAP | Optional (Oinkcode for subscriber rules) | Community rules unlimited | Yes | Yes |
| [Wazuh](https://wazuh.com/) | Open source | Open-source XDR and SIEM with built-in CDB IOC lists, VirusTotal, and AbuseIPDB integrations | JSON, CDB lists | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [Velociraptor](https://docs.velociraptor.app/) | Open source | Endpoint visibility and DFIR hunting tool running VQL queries and YARA scans across fleets | JSON, CSV, VQL | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [osquery](https://osquery.io/) | Open source | SQL-powered endpoint instrumentation for hunting processes, sockets, and persistence artifacts | JSON, SQL | None | Unlimited (self-hosted) | Yes | Yes |
| [Security Onion](https://securityonionsolutions.com/) | Open source | Turnkey Linux distribution bundling Suricata, Zeek, Elastic, Strelka, and CyberChef | JSON, PCAP, Suricata | Self-managed | Unlimited (self-hosted) | Yes (self-hosted) | Yes |
| [RITA (Real Intelligence Threat Analytics)](https://github.com/activecm/rita) | Open source | Analyze Zeek logs to detect C2 beaconing, DNS tunneling, and long connections | JSON, CSV, HTML | None | Unlimited (self-hosted) | Yes | Yes |
| [Malcolm](https://malcolm.fyi/) | Open source | CISA-backed network traffic analysis appliance integrating Zeek, Suricata, Arkime, and OpenSearch | PCAP, JSON, Zeek | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4) | Open source | TLS, HTTP, SSH, and TCP fingerprinting suite for tracking C2 clients and malware traffic | JSON, Wireshark, Zeek | None | JA4 core BSD-3-Clause | JA4 yes; JA4+ check license | Yes |

### Vulnerability & Exploit Intelligence

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Open Data / Feed | Authoritative list of CVEs actively exploited in the wild with remediation due dates | JSON, CSV | None | Unlimited | Yes | No |
| [NIST NVD](https://nvd.nist.gov/) | Open Data / API | US government CVE repository with CVSS scores, CPE matches, and CWE tags | JSON | Optional (higher rate limit) | 5 req/30s (no key), 50 req/30s (free key) | Yes | No |
| [FIRST EPSS](https://www.first.org/epss/) | Open Data / API | Daily probability scores predicting whether a CVE will be exploited in the next 30 days | JSON, CSV | None | Unlimited | Yes | No |
| [OSV.dev](https://osv.dev/) | Open source / API | Distributed open-source vulnerability database across PyPI, npm, Go, Maven, and Linux | JSON (OSV schema) | None | Unlimited | Yes | Yes |
| [OpenCVE](https://www.opencve.io/) | Open source | Self-hosted CVE alerting platform tracking vendor and product subscriptions | JSON, Webhooks | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [VulnCheck](https://vulncheck.com/) | API / SaaS | Exploit intelligence, initial access telemetry, and expanded KEV tracking | JSON | Required | Free Community tier (NVD++, KEV) | Paid for commercial feeds | No |
| [Exploit-DB](https://www.exploit-db.com/) | Open Data / CLI | Public archive of proof-of-concept exploits and vulnerable software papers | CSV, Git | None | Unlimited | Yes | Yes |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Open source | Community YAML templates for detecting CVEs, misconfigurations, and exposed panels | YAML, JSON | None | Unlimited | Yes | Yes |
| [Trivy](https://trivy.dev/) | Open source | Scan container images, filesystems, git repos, and IaC against NVD, OSV, and vendor advisories | JSON, SARIF, CycloneDX | None | Unlimited (local) | Yes | Yes |
| [Anchore Grype](https://github.com/anchore/grype) | Open source | Vulnerability scanner for container images and SBOMs with CISA KEV and EPSS enrichment | JSON, SARIF, Table | None | Unlimited (local) | Yes | Yes |
| [OWASP Dependency-Track](https://dependencytrack.org/) | Open source | Continuous SBOM monitoring platform correlating components with NVD, OSV, GitHub, and EPSS | CycloneDX, JSON, VEX | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [GitHub Advisory Database](https://github.com/advisories) | Open Data / API | Curated CVE and GHSA vulnerability feed covering npm, PyPI, Go, Maven, NuGet, and Rust | JSON (OSV), GraphQL, REST | Optional (GitHub token for higher limits) | Public API free | Yes | No |
| [AttackerKB](https://attackerkb.com/) | Web / API | Community assessments of CVE exploitability, attacker value, and real-world impact | JSON | Required for API | Free community access | Yes (terms apply) | No |
| [Vulners](https://vulners.com/) | API / SaaS | Aggregated vulnerability, exploit, and vendor advisory search engine with Linux audit API | JSON | Required | 100 credits/month (Free) | Paid for commercial API | No |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Open source | Fast YAML-based vulnerability and exposed-asset scanner powered by community templates | JSON, SARIF, YAML | None | Unlimited (local) | Yes | Yes |

### IOC Enrichment & Automation

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Open source | Observable analysis and active response engine with 150+ threat intel analyzers | JSON | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | Open source | Open-source orchestration platform querying 150+ malware and threat intel analyzers at once | JSON, STIX, MISP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Open source | Interactive matrix for mapping adversary TTPs, detection coverage, and threat profiles | JSON, STIX, SVG | None | Unlimited | Yes | Yes |
| [CyberChef](https://gchq.github.io/CyberChef/) | Open source | Browser-based toolkit for decoding payloads, defanging IOCs, and extracting indicators | TXT, JSON, Hex | None | Unlimited (runs client-side) | Yes | Yes |
| [iocextract](https://github.com/InQuest/iocextract) | Open source | Python library and CLI for extracting and refanging defanged IPs, URLs, and hashes from reports | TXT, JSON | None | Unlimited (local) | Yes | Yes |
| [TheHive](https://strangebee.com/thehive/) | Source-available / Enterprise | Security incident response and case management platform tightly coupled with MISP and Cortex | JSON, MISP | Self-managed | Community / trial tiers | Paid license | Yes |
| [DFIR-IRIS](https://www.dfir-iris.org/) | Open source | Open-source collaborative incident response platform with IOC tracking and MISP/VT modules | JSON, CSV, MISP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [Timesketch](https://timesketch.org/) | Open source | Open-source forensic timeline analysis tool with automated Sigma and Yeti IOC tagging | JSONL, CSV, Plaso | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [Shuffle SOAR](https://shuffler.io/) | Open source | Open-source security orchestration platform automating IOC enrichment and firewall blocking | JSON, OpenAPI | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [Tines](https://www.tines.com/) | SaaS / Self-hosted | No-code security automation workflows for IOC triage, phishing response, and alert enrichment | JSON, Webhooks | Required | Community Edition (3 active stories) | Yes (tier limits) | Yes |

### Credential & Leak Intelligence

| Tool | Type | Purpose | Formats | API key | Free limits | Commercial use | Self-hosted |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Have I Been Pwned](https://haveibeenpwned.com/) | API / SaaS | Check exposed corporate domains, email addresses, and stealer-log credentials | JSON | Required for API | Free web checks; paid API | Paid API | No |
| [Hudson Rock Cavalier](https://www.hudsonrock.com/) | API / SaaS | Infostealer telemetry identifying compromised employee and customer endpoints | JSON | Optional (free domain check) | Free domain exposure lookup API | Paid for full telemetry | No |
| [AIL Project](https://github.com/ail-project/ail-framework) | Open source | Open-source framework for analyzing leaks from pastes, Telegram, Tor, and dark web crawls | JSON, MISP | Self-managed | Unlimited (self-hosted) | Yes | Yes |
| [DeHashed](https://dehashed.com/) | API / SaaS | Search leaked credential databases by domain, email, username, IP, or password hash | JSON | Required | No free API tier | Paid only | No |
| [OSINT Industries](https://osint.industries/) | API / SaaS | Cross-platform account and email exposure lookups for fraud and threat investigations | JSON | Required | Paid credits | Paid only | No |
<!-- END:TOOLS -->

## Threat intelligence feeds by category

Public feeds vary widely in license terms and noise levels. Verify whether a feed allows commercial use before wiring it into customer-facing firewalls or SIEM pipelines.

<!-- START:FEEDS -->
### Multi-IOC & C2

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | IP, Domain, URL, Hash | JSON, CSV, STIX, MISP | Every 5 minutes | Unlimited public exports | CC0 1.0 | Yes | MISP, OpenCTI, Suricata |
| [AlienVault OTX](https://otx.alienvault.com/) | IP, Domain, URL, Hash, CVE | JSON, CSV, STIX, TAXII | Continuous | Unlimited community pulses | Proprietary (free community) | Yes (terms apply) | MISP, OpenCTI, Splunk |
| [CIRCL OSINT MISP Feed](https://www.circl.lu/doc/misp/feed-osint/) | IP, Domain, URL, Hash | MISP JSON | Daily | Unlimited | CC0 1.0 | Yes | MISP, OpenCTI |
| [Botvrij.eu IOC Lists](https://www.botvrij.eu/) | IP, Domain, Hash | TXT, MISP JSON | Daily | Unlimited | Open community feed | Yes | MISP, Suricata, SIEM |
| [TweetFeed Live IOCs](https://tweetfeed.live/) | IP, Domain, URL, Hash | JSON, CSV | Real-time | Unlimited | Free community feed | Yes | MISP, OpenCTI, Splunk |
| [Proofpoint Emerging Threats Open Rules](https://rules.emergingthreats.net/open/) | Suricata Rules, IP, Domain | Suricata, Snort | Daily | Unlimited | BSD-3-Clause | Yes | Suricata, Snort, Zeek |

### Malicious URLs & Domains

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) | URL, Domain, Hash | CSV, TXT, RPZ, JSON | Every 5 minutes | Unlimited public exports | CC0 1.0 | Yes | MISP, OpenCTI, BIND RPZ |
| [DigitalSide Threat-Intel Domains](https://osint.digitalside.it/) | Domain | TXT, CSV, MISP, STIX | Hourly | Unlimited | MIT | Yes | MISP, OpenCTI, Pi-hole |
| [DigitalSide Threat-Intel URLs](https://osint.digitalside.it/) | URL | TXT, CSV, MISP | Hourly | Unlimited | MIT | Yes | MISP, Proxy, SIEM |
| [HaGeZi Threat Intelligence Feeds (Mini)](https://github.com/hagezi/dns-blocklists) | Domain | TXT, RPZ, Hosts | Daily | Unlimited | GPL-3.0 | Yes | Pi-hole, AdGuard Home, Unbound |
| [StevenBlack Malware & Adware Hosts](https://github.com/StevenBlack/hosts) | Domain | Hosts, TXT | Daily | Unlimited | MIT | Yes | OS hosts, Pi-hole, CoreDNS |
| [ThreatView.io Malicious Domains](https://threatview.io/) | Domain | TXT | Daily | Unlimited | Free community feed | Yes | SIEM, DNS firewalls, MISP |

### Malware Hashes

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [MalwareBazaar Recent (abuse.ch)](https://bazaar.abuse.ch/) | SHA256, MD5, SHA1 | CSV, JSON, TXT | Hourly | Unlimited public exports | CC0 1.0 | Yes | MISP, OpenCTI, YARA |
| [ThreatView.io Malware MD5 Hashes](https://threatview.io/) | MD5 | TXT | Daily | Unlimited | Free community feed | Yes | EDR, SIEM, MISP |
| [Malpedia Public API](https://malpedia.caad.fkie.fraunhofer.de/) | Malware Family, YARA, Actor | JSON, YARA | Daily | Public metadata unlimited | Research / Mixed | Metadata yes | MISP, OpenCTI, YARA |
| [YARAify (abuse.ch)](https://yaraify.abuse.ch/) | SHA256, YARA | JSON, YARA | Continuous | Free community access | CC0 1.0 | Yes | YARA, MISP, OpenCTI |

### Botnet & C2 IPs

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Feodo Tracker IP Blocklist (abuse.ch)](https://feodotracker.abuse.ch/) | IP | TXT, CSV, JSON | Every 5 minutes | Unlimited | CC0 1.0 | Yes | Suricata, pfSense, OPNsense |
| [SSL Blacklist (abuse.ch)](https://sslbl.abuse.ch/) | IP, SSL SHA1, JA3 | TXT, CSV, Suricata | Every 15 minutes | Unlimited | CC0 1.0 | Yes | Suricata, Zeek, MISP |
| [Malicious IP (romainmarcoux 40k)](https://github.com/romainmarcoux/malicious-ip) | IP | TXT | Daily | Unlimited | MIT | Yes | SIEM, Firewall, OpenCTI |

### IP Reputation & Blocklists

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [AbuseIPDB Blacklist](https://www.abuseipdb.com/) | IP | JSON, TXT | Continuous | 5 blacklist downloads/day (10,000 IPs) | Proprietary | Paid for commercial use | Fail2ban, pfSense, Splunk |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | CIDR | TXT, JSON | Hourly | Unlimited | Free for non-resale use | Yes (internal protection) | BGP, iptables, pfSense |
| [Spamhaus DROPv6](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | IPv6 CIDR | TXT, JSON | Hourly | Unlimited | Free for non-resale use | Yes (internal protection) | BGP, ip6tables, pfSense |
| [Emerging Threats Compromised IPs](https://rules.emergingthreats.net/) | IP | TXT | Daily | Unlimited | BSD-3-Clause | Yes | Suricata, Snort, pfSense |
| [CINSscore CI Army Badguys](https://cinsscore.com/) | IP | TXT | Hourly | Unlimited | Free for internal use | Yes (non-resale) | pfSense, OPNsense, Suricata |
| [Blocklist.de All Attackers](https://www.blocklist.de/en/export.html) | IP | TXT | Every 30 minutes | Unlimited (poll max every 30 min) | Free community feed | Yes | Fail2ban, iptables, pfSense |
| [Blocklist.de SSH Brute Force](https://www.blocklist.de/en/export.html) | IP | TXT | Every 30 minutes | Unlimited | Free community feed | Yes | Fail2ban, SSH, iptables |
| [Blocklist.de Apache / Web Attackers](https://www.blocklist.de/en/export.html) | IP | TXT | Every 30 minutes | Unlimited | Free community feed | Yes | Nginx, Apache, ModSecurity |
| [FireHOL Level 1](https://iplists.firehol.org/) | IP, CIDR | TXT (netset) | Multiple times daily | Unlimited | GPL-2.0 / Aggregated | Check upstream feeds | ipset, iptables, pfSense |
| [FireHOL Level 2](https://iplists.firehol.org/) | IP, CIDR | TXT (netset) | Hourly | Unlimited | GPL-2.0 / Aggregated | Check upstream feeds | ipset, iptables, pfSense |
| [FireHOL Level 3](https://iplists.firehol.org/) | IP, CIDR | TXT (netset) | Daily | Unlimited | GPL-2.0 / Aggregated | Check upstream feeds | ipset, iptables, pfSense |
| [SANS ISC DShield Top Attackers](https://www.dshield.org/) | CIDR | TXT | Hourly | Unlimited | CC-BY-NC-SA 4.0 | Non-commercial | pfSense, Suricata, FireHOL |
| [GreenSnow IP Blocklist](https://greensnow.co/) | IP | TXT | Hourly | Unlimited | Free community feed | Yes (internal) | Fail2ban, iptables, pfSense |
| [Binary Defense Artillery Banlist](https://www.binarydefense.com/) | IP | TXT | Daily | Unlimited | Free for non-commercial / internal | Internal use only | pfSense, Suricata, Splunk |
| [IPsum (Level 3+ Aggregated)](https://github.com/stamparm/ipsum) | IP | TXT | Daily | Unlimited | Unlicense | Yes | Nginx, iptables, Wazuh |
| [Tor Project Bulk Exit List](https://check.torproject.org/) | IP | TXT | Hourly | Unlimited | BSD-3-Clause | Yes | Nginx, Cloudflare, WAF |
| [Cisco Talos IP Blacklist](https://talosintelligence.com/) | IP | TXT | Daily | Unlimited | Cisco Talos Terms | Internal use | Snort, Suricata, pfSense |
| [StopForumSpam Toxic IPs (7d)](https://www.stopforumspam.com/) | IP | TXT | Daily | Unlimited | Free community feed | Yes | Nginx, WAF, ipset |
| [DigitalSide Threat-Intel IPs](https://osint.digitalside.it/) | IP | TXT, CSV, MISP, STIX | Hourly | Unlimited | MIT | Yes | MISP, OpenCTI, Pi-hole |
| [ThreatView.io High-Confidence IPs](https://threatview.io/) | IP | TXT | Daily | Unlimited | Free community feed | Yes | Firewall, SIEM, MISP |
| [Shodan InternetDB API](https://internetdb.shodan.io/) | IP, Ports, CVE | JSON | Weekly | Free keyless lookups | Free non-commercial / research | Contact Shodan for high-volume | Python, Cortex, IntelOwl |
| [GreyNoise Community API](https://docs.greynoise.io/reference/get_v3-community-ip) | IP | JSON | Real-time | Limited unauthenticated; 50/wk with key | Proprietary (free community) | Paid only | Splunk, Sentinel, Cortex |

### Phishing & Brand Abuse

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [OpenPhish Community Feed](https://openphish.com/) | URL | TXT | Every 12 hours | Community subset (updated every 12h) | Non-commercial free tier | Paid for commercial | MISP, OpenCTI, Proxy |
| [PhishTank Verified Phishing](https://phishtank.org/) | URL | JSON, CSV, XML | Hourly | Rate-limited hourly dumps | Free community data | Yes (attribution) | MISP, OpenCTI, Mail gateways |
| [CERT.pl Phishing Warning List](https://cert.pl/en/warning-list/) | Domain | TXT, JSON, CSV, RPZ | Every 5 minutes | Unlimited | Public Domain / Open Data | Yes | BIND RPZ, Unbound, Pi-hole |
| [Phishing.Database Active Domains](https://github.com/Phishing-Database/Phishing.Database) | Domain | TXT | Daily | Unlimited | MIT | Yes | Pi-hole, Unbound, DNS firewalls |
| [Phishing Army Blocklist](https://phishing.army/) | Domain | TXT | Every 6 hours | Unlimited | CC-BY-NC 4.0 | Non-commercial | Pi-hole, AdGuard, BIND |

### Vulnerability & Exploit Feeds

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE | JSON, CSV | As exploited CVEs emerge | Unlimited | Public Domain (US Gov) | Yes | OpenCTI, MISP, Nuclei |
| [FIRST EPSS Probability Feed](https://www.first.org/epss/) | CVE | JSON, CSV | Daily | Unlimited | Open Data (FIRST) | Yes | OpenCTI, Trivy, DefectDojo |
| [NIST NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE, CPE | JSON | Every 2 hours | 5 req/30s (no key), 50 req/30s (free key) | Public Domain (US Gov) | Yes | OpenCVE, OpenCTI, Trivy |
| [OSV.dev Vulnerability API](https://osv.dev/) | CVE, GHSA, Package | JSON | Continuous | Unlimited | CC-BY-4.0 | Yes | osv-scanner, CI/CD, OpenCTI |

### Ransomware & Threat Actors

| Feed | IOC types | Formats | Update cycle | Free limits | License | Commercial use | Integrations |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [Ransomware.live Victims API](https://www.ransomware.live/) | Threat Actor, Victim, Domain | JSON, RSS | Hourly | Unlimited public API | CC-BY-SA 4.0 | Yes (attribution) | OpenCTI, MISP, Slack |
| [MITRE ATT&CK Enterprise STIX](https://attack.mitre.org/) | TTP, Threat Actor, Malware | STIX, JSON | Biannual releases | Unlimited | Apache-2.0 | Yes | OpenCTI, MISP, Sigma |
<!-- END:FEEDS -->

## Included CLI utilities

All scripts in `scripts/` use the Python 3.9+ standard library and require no third-party packages.

| Script | Purpose | Example command |
| --- | --- | --- |
| [scripts/check-ip.py](scripts/check-ip.py) | Check IP reputation across Shodan InternetDB, GreyNoise, AlienVault OTX, AbuseIPDB, and VirusTotal | `python3 scripts/check-ip.py 1.1.1.1 8.8.8.8` |
| [scripts/check-feeds.py](scripts/check-feeds.py) | Validate feed availability, response latency, `Last-Modified` headers, and payload format | `python3 scripts/check-feeds.py --only threatfox-recent,urlhaus-recent` |
| [scripts/check-logs.py](scripts/check-logs.py) | Scan Nginx, Apache, or Linux auth logs against public or local IP blocklists | `python3 scripts/check-logs.py /var/log/nginx/access.log` |
| [scripts/convert-feed.py](scripts/convert-feed.py) | Convert IOC files between JSON, CSV, plain text, and STIX 2.1 bundles | `python3 scripts/convert-feed.py iocs.txt bundle.json --to stix` |
| [scripts/dedupe-iocs.py](scripts/dedupe-iocs.py) | Refang, classify, and deduplicate mixed indicator files (IPs, domains, URLs, hashes) | `python3 scripts/dedupe-iocs.py feed1.txt feed2.txt -o clean.txt` |
| [scripts/cve-monitor.py](scripts/cve-monitor.py) | Query CISA KEV and NIST NVD for recent CVEs matching your software stack | `python3 scripts/cve-monitor.py nginx openssh --days 30` |
| [scripts/update-readme.py](scripts/update-readme.py) | Rebuild all tables in this README from `data/*.json` | `python3 scripts/update-readme.py` |

Optional environment variables unlock extra sources in `check-ip.py` and higher quotas in `cve-monitor.py`:

```bash
export ABUSEIPDB_API_KEY="your_key"
export VT_API_KEY="your_key"
export GREYNOISE_API_KEY="your_key"
export OTX_API_KEY="your_key"
export NVD_API_KEY="your_key"
```

## Integration examples

- [Nginx access log monitoring and IP blocking](examples/nginx-monitoring.md)
- [Linux server SSH and syslog threat checks](examples/linux-monitoring.md)
- [MISP feed ingestion and export automation](examples/misp-integration.md)

## Contributing

To add a tool, platform, or feed, edit the corresponding JSON file in `data/` and open a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the schema and submission rules.

## License

Catalog metadata and scripts are released under the [MIT License](LICENSE). Individual third-party feeds and tools keep their own licenses listed in the tables above.
