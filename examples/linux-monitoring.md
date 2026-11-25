# Linux server monitoring with threat intelligence feeds

You can use the scripts in this repository to audit SSH logs, check suspicious remote peers, and watch for actively exploited CVEs on Linux hosts without installing a full SIEM agent.

## 1. Scan SSH authentication logs

Check `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Rocky) against Blocklist.de SSH attackers and IPsum:

```bash
python3 scripts/check-logs.py /var/log/auth.log \
  --feed-url https://lists.blocklist.de/lists/ssh.txt \
  --feed-url https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
```

## 2. Investigate a specific IP

When a scan finds an unfamiliar IP in `auth.log` or `ss -tunap`, query Shodan InternetDB, GreyNoise, AlienVault OTX, and any API-backed providers you have configured:

```bash
export ABUSEIPDB_API_KEY="your_key"
python3 scripts/check-ip.py 185.220.101.1
```

InternetDB works without an API key and returns open ports, hostnames, and known CVEs for the IP.

## 3. Load an ipset blocklist with nftables or iptables

Fetch and deduplicate high-confidence IPv4 indicators, then load them into an `ipset` table:

```bash
curl -fsSL https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt -o /tmp/feodo.txt
python3 scripts/dedupe-iocs.py /tmp/feodo.txt --only-type ipv4 -o /tmp/feodo-clean.txt

ipset create ti_block hash:ip -exist
ipset flush ti_block
while read -r ip; do
  ipset add ti_block "$ip" -exist
done < /tmp/feodo-clean.txt

iptables -I INPUT -m set --match-set ti_block src -j DROP
```

## 4. Watch CISA KEV for installed server software

Check whether any package in your base stack appeared in the CISA Known Exploited Vulnerabilities catalog during the last 30 days:

```bash
python3 scripts/cve-monitor.py linux kernel openssh openssl nginx postgres docker --days 30
```

Add `--source both` to include NIST NVD results as well. Setting `NVD_API_KEY` raises the NVD rate limit from 5 requests per 30 seconds to 50 requests per 30 seconds.
