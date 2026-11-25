# Contributing

Pull requests that add active threat intelligence tools, platforms, or public feeds are welcome. Edit the JSON source files in `data/` and regenerate `README.md` with `scripts/update-readme.py`; do not edit the generated tables directly.

## Adding an entry

1. Edit `data/tools.json`, `data/platforms.json`, or `data/feeds.json` using the same fields as existing entries.
2. Keep descriptions factual and specific to what the tool or feed does.
3. For feeds in `data/feeds.json`, provide a direct `check_url` that responds to HTTP GET without requiring interactive login.
4. Run the verification scripts locally before opening a pull request:

```bash
python3 scripts/check-feeds.py --only your-new-feed-id
python3 scripts/update-readme.py
```

## Inclusion criteria

- The project, platform, or feed must be actively maintained and reachable over HTTPS.
- Commercial tools are accepted when they publish clear documentation and API or integration details.
- Specify license and commercial use restrictions accurately so operators know what can be used in production.
