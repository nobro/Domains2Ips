# d2i.py — Domain to IP Enrichment Tool

Accepts a mixed input file of domains, subdomains, URLs, and raw IPs. Resolves each to its IP address(es), enriches the results with geolocation and organisation data via [IPinfo.io](https://ipinfo.io) and open port/vulnerability data via [Shodan InternetDB](https://internetdb.shodan.io), then generates a self-contained HTML report.

## Features

- Mixed input: domains, subdomains, full URLs, raw IPv4/IPv6 addresses in one file
- Comments (`#`) and blank lines are ignored
- Optional IPv6 resolution (`-v6`)
- Reverse DNS lookup per IP
- Enrichment via IPinfo.io (IPinfo Hostname, Org, City, Region, Country) — API key optional; report still generates without one
- Enrichment via Shodan InternetDB — free, no API key needed (ports, tags, CPEs, CVEs, hostnames)
- Private, reserved, and IPv6 addresses are automatically skipped for Shodan (not supported by InternetDB)
- Two-tab HTML report: **By IP** and **By FQDN**
- Global search, per-column filters, and sortable columns
- Clickable FQDNs and IPs that cross-link between tabs
- Per-row severity labels (Critical / Interesting / Reviewed / False Positive) and notes — persisted in browser `localStorage`
- Progress output goes to `stderr`; the report path is printed to `stdout` for easy piping
- Fully self-contained output (single `.html` file, no external dependencies)

---

## Requirements

- Python 3.9+
- An [IPinfo.io](https://ipinfo.io) API token (free tier available)

Python dependencies:

```
validators
tldextract
ipinfo
requests
```

---

## Installation

### Option A — Run directly with `uv` (no virtual environment needed)

[`uv`](https://github.com/astral-sh/uv) installs dependencies on the fly. No setup required.

```bash
uv run --with validators --with tldextract --with ipinfo --with requests d2i.py -f input.txt --ipinfo_token YOUR_TOKEN
```

### Option B — Virtual environment

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# Install dependencies
pip install validators tldextract ipinfo requests

# Run
python d2i.py -f input.txt --ipinfo_token YOUR_TOKEN
```

---

## IPinfo API Token

The tool uses [IPinfo.io](https://ipinfo.io) to look up IPinfo Hostname, organisation, city, region, and country for each IP. A free account provides up to 50,000 requests/month.

The token can be supplied in two ways:

```bash
# As a CLI argument
python d2i.py -f input.txt --ipinfo_token YOUR_TOKEN

# As an environment variable
export IPINFO_TOKEN=YOUR_TOKEN
python d2i.py -f input.txt
```

If no token is provided, IP detail columns will be empty but the rest of the report will still generate.

---

## Input File Format

One entry per line. Supported formats:

| Format | Example |
|---|---|
| Plain domain | `example.com` |
| Subdomain | `sub.example.com` |
| Full URL | `https://www.example.com/some/path` |
| Raw IPv4 | `8.8.8.8` |
| Raw IPv6 | `2606:4700:4700::1111` |
| Comment | `# this line is ignored` |
| Blank line | _(ignored)_ |

See `test_input.txt` for a ready-to-use example:

```
# Test input file
# Domains / subdomains
example.com
sub.example.com
https://www.github.com/some/path

# Raw IPs
8.8.8.8
1.1.1.1

# IPv6
2606:4700:4700::1111
```

---

## Usage

```
python d2i.py -f INPUT_FILE [--ipinfo_token TOKEN] [-v6]
```

| Argument | Description |
|---|---|
| `-f`, `--file` | Path to the input file (required) |
| `--ipinfo_token` | IPinfo.io API token (or set `IPINFO_TOKEN` env var) |
| `-v6`, `--version6` | Also resolve IPv6 addresses |

### Examples

```bash
# Basic run with the example file
python d2i.py -f test_input.txt --ipinfo_token YOUR_TOKEN

# Using uv, with IPv6 resolution enabled
uv run --with validators --with tldextract --with ipinfo --with requests \
    d2i.py -f test_input.txt --ipinfo_token YOUR_TOKEN -v6

# Using an environment variable for the token
export IPINFO_TOKEN=YOUR_TOKEN
python d2i.py -f targets.txt

# Pipe a quick list without a file (write to a temp file first)
echo -e "example.com\n8.8.8.8" > /tmp/targets.txt
python d2i.py -f /tmp/targets.txt --ipinfo_token YOUR_TOKEN

# Open the report automatically after generation (macOS)
python d2i.py -f targets.txt --ipinfo_token YOUR_TOKEN | xargs open

# Open the report automatically after generation (Linux)
python d2i.py -f targets.txt --ipinfo_token YOUR_TOKEN | xargs xdg-open
```

The report path is printed to `stdout` on completion (progress goes to `stderr`), making it easy to capture or pipe:

```bash
REPORT=$(python d2i.py -f targets.txt --ipinfo_token YOUR_TOKEN)
echo "Report saved to: $REPORT"
```

---

## Output

Reports are saved to the `results/` directory (created automatically) with a timestamped filename:

```
results/report_2026-03-07_14-04-48.html
```

Open the file in any modern browser. No server or internet connection is needed to view the report.

### Report tabs

**By IP** — one row per unique IP address, columns:
Label, IP, Reverse DNS, FQDNs, Ports, Tags, CPEs, Vulns (CVEs), Shodan Hostnames, IPinfo Hostname, Org, City, Region, Country, Notes

**By FQDN** — one row per unique FQDN, columns:
Label, FQDN, IPs, Reverse DNS, Shodan Hostnames, Ports, Vulns (CVEs), Org, Country, Notes

### Severity labels

Click the **Label** button on any row to cycle through severity states:

| Label | Use for |
|---|---|
| — | Not yet triaged |
| Critical | Confirmed high-priority finding |
| Interesting | Worth investigating further |
| Reviewed | Checked and understood |
| False Positive | Can be ignored |

Labels and notes are saved in the browser's `localStorage` and survive page refresh.

---

## Rate limiting

Shodan InternetDB enforces approximately 1 request/second. The script automatically sleeps 1.1 seconds between Shodan queries. Private/reserved IPs and IPv6 addresses are skipped entirely (InternetDB only covers public IPv4), so only public IPv4 addresses count toward the delay. For large input files, expect roughly 1 second per unique public IPv4 address in enrichment time.
