# Nginx access log monitoring and IP blocking

This guide shows how to check Nginx access logs against public threat intelligence feeds and optionally block high-confidence C2 and botnet IPs.

## 1. Check Nginx logs on demand

Run `scripts/check-logs.py` against your access log. By default it fetches Feodo Tracker, Emerging Threats Compromised IPs, and IPsum Level 3.

```bash
python3 scripts/check-logs.py /var/log/nginx/access.log
```

For machine-readable output that can be sent to a webhook or SIEM:

```bash
python3 scripts/check-logs.py /var/log/nginx/access.log --json > /tmp/nginx-ti-hits.json
```

The script exits with code `1` when matches are found and `0` when the log is clean, which makes it easy to hook into cron or CI alerts.

## 2. Build a local allowlisted blocklist

Before blocking traffic in Nginx, deduplicate your chosen feeds and exclude your own monitoring probes, CDNs, and office IPs.

```bash
curl -fsSL https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt -o /tmp/feodo.txt
curl -fsSL https://rules.emergingthreats.net/blockrules/compromised-ips.txt -o /tmp/et.txt

python3 scripts/dedupe-iocs.py /tmp/feodo.txt /tmp/et.txt --only-type ipv4 -o /tmp/blocklist.txt
```

Generate an Nginx `geo` or `deny` include file:

```bash
awk '{print "deny " $1 ";"}' /tmp/blocklist.txt > /etc/nginx/conf.d/ti-blocklist.inc
nginx -t && systemctl reload nginx
```

Include the generated file inside the `http` or `server` block:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    include /etc/nginx/conf.d/ti-blocklist.inc;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## 3. Schedule hourly checks

Run a cron job that refreshes the local IOC list and reports any hits from the last log rotation:

```cron
15 * * * * /usr/bin/python3 /opt/threat-intelligence-tools/scripts/check-logs.py /var/log/nginx/access.log --ioc-file /tmp/blocklist.txt --json > /var/log/nginx-ti-report.json
```

Keep blocklists narrow when applying automatic `deny` rules. Start with Feodo Tracker or Spamhaus DROP, log matches for a week, and review hits before expanding to broader feeds.
