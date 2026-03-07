#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
d2i.py — Domain/IP Enrichment Tool
Accepts a mixed input file (domains, subdomains, URLs, raw IPs),
resolves and enriches with IPinfo + Shodan, and generates a rich
single self-contained HTML report.
"""

import validators
import tldextract
import argparse
import socket
import json
import sys
import os
import ipaddress
import traceback
from datetime import datetime
import ipinfo
import requests
from time import sleep


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(*args, **kwargs):
    """Writes progress output to stderr, keeping stdout clean for piping."""
    kwargs.setdefault('file', sys.stderr)
    print(*args, **kwargs)


def _new_record(ip, fqdns=None):
    """Creates a fresh IP record dict with default field values."""
    return {
        "ip": ip,
        "fqdns": list(fqdns) if fqdns else [],
        "reverse_dns": "N/A",
        "shodan_hostnames": [],
        "ports": [], "tags": [], "cpes": [], "vulns": [],
        "hostname": "N/A", "org": "N/A", "city": "N/A",
        "region": "N/A", "country": "N/A",
        "shodan_error": None, "shodan_no_info": False, "ipinfo_error": None
    }


def _is_public_ip(ip):
    """Returns True if ip is a globally routable address (not private, loopback, link-local, etc.)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Input parsing and validation
# ---------------------------------------------------------------------------

def extract_fqdn(invalidated_domain_str):
    """
    Validates and extracts an FQDN from a plain domain, subdomain, or URL string.
    Returns the FQDN string on success, or None if the input is not a valid domain or URL.
    """
    invalidated_domain_str = invalidated_domain_str.strip()
    if validators.domain(invalidated_domain_str):
        return invalidated_domain_str
    elif validators.url(invalidated_domain_str):
        temp_domain = tldextract.extract(invalidated_domain_str)
        if temp_domain.subdomain:
            extracted_domain = '.'.join(filter(None, [temp_domain.subdomain, temp_domain.domain, temp_domain.suffix]))
        else:
            extracted_domain = '.'.join(filter(None, [temp_domain.domain, temp_domain.suffix]))
        if validators.domain(extracted_domain):
            return extracted_domain
        else:
            return None
    else:
        return None


def ipinfo_get(ip_address, handler):
    """Uses ipinfo.io to get additional information about IP addresses."""
    if not handler:
        return {'Error': 'IPinfo API token not provided or empty.'}
    try:
        details = handler.getDetails(ip_address)
        relevant_keys = {'hostname', 'city', 'region', 'country', 'org'}
        return {key: details.all.get(key, 'N/A') for key in relevant_keys}
    except Exception as e:
        return {'Error': str(e)}


_SHODAN_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}


def shodan_get_info(ip_address, session=None):
    """
    Fetches data from Shodan InternetDB for a given IP.
    Returns a dictionary with 'ports', 'tags', 'cpes', 'vulns', 'error' or 'no_info'.
    Optionally accepts a requests.Session for connection reuse.
    """
    link = f"https://internetdb.shodan.io/{ip_address.strip()}"
    result = {"ports": [], "tags": [], "cpes": [], "vulns": [], "hostnames": [], "error": None, "no_info": False}
    requester = session if session is not None else requests

    try:
        response = requester.get(link, headers=_SHODAN_HEADERS, timeout=20)
        response.raise_for_status()
        data = response.json()

        if not any((data.get("ports"), data.get("tags"), data.get("hostnames"), data.get("cpes"), data.get("vulns"))):
            if "detail" in data and "No information available" in data["detail"]:
                result["no_info"] = True
                return result

        result["ports"] = data.get("ports", [])
        result["tags"] = data.get("tags", [])
        result["cpes"] = data.get("cpes", [])
        result["vulns"] = data.get("vulns", [])
        result["hostnames"] = data.get("hostnames", [])

        if not any((result["ports"], result["tags"], result["cpes"], result["vulns"], result["hostnames"])):
            result["no_info"] = True

    except requests.Timeout:
        result["error"] = "Request timed out"
    except requests.ConnectionError:
        result["error"] = "Connection error"
    except requests.HTTPError as e:
        try:
            error_detail = e.response.json()
            if "detail" in error_detail and "No information available" in error_detail["detail"]:
                result["no_info"] = True
                result["error"] = None
            else:
                result["error"] = f"HTTP error: {e} - {error_detail.get('detail', '')}"
        except json.JSONDecodeError:
            result["error"] = f"HTTP error: {e} (Non-JSON error response)"
    except json.JSONDecodeError:
        result["error"] = "Failed to decode JSON response from Shodan"
    except Exception as e:
        result["error"] = f"Shodan unexpected error: {str(e)}"

    return result


def validate_file(filepath_str):
    """Validates if the file exists and is a regular file."""
    if not os.path.isfile(filepath_str):
        raise argparse.ArgumentTypeError(f"File '{filepath_str}' does not exist.")
    return filepath_str


# ---------------------------------------------------------------------------
# Resolution and enrichment
# ---------------------------------------------------------------------------

def parse_entry(line):
    """
    Parses a single input line. Returns a dict with type/value or None if invalid.
    Handles: raw IPv4, raw IPv6, domain, subdomain, URL.
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # validators returns True on success or a ValidationFailure object on failure.
    # 'is True' avoids accidentally treating a ValidationFailure as a truthy match.
    if validators.ip_address.ipv4(line) is True:
        return {"type": "ip", "value": line}

    if validators.ip_address.ipv6(line) is True:
        return {"type": "ip", "value": line}

    # Try domain/URL extraction
    fqdn = extract_fqdn(line)
    if fqdn:
        return {"type": "domain", "value": fqdn}

    return None


def resolve_domain(fqdn, include_v6):
    """
    Resolves a FQDN to a list of unique IP addresses.
    Returns an empty list if resolution fails.
    """
    ips = []

    try:
        _, _, addresses = socket.gethostbyname_ex(fqdn)
        ips.extend(addresses)
        log(f"  * {fqdn} (IPv4) --> {', '.join(addresses)}")
    except socket.gaierror as e:
        log(f"  \033[93mWarning:\033[0m IPv4 resolution error for {fqdn}: {e}")
    except Exception as e:
        log(f"  \033[91mError:\033[0m Unexpected IPv4 resolution error for {fqdn}: {e}")

    if include_v6:
        try:
            addrinfo_ipv6 = socket.getaddrinfo(fqdn, None, socket.AF_INET6)
            ipv6_addresses = list(set(info[4][0] for info in addrinfo_ipv6))
            if ipv6_addresses:
                ips.extend(ipv6_addresses)
                log(f"  * {fqdn} (IPv6) --> {', '.join(ipv6_addresses)}")
        except socket.gaierror:
            pass
        except Exception as e:
            log(f"  \033[91mError:\033[0m Unexpected IPv6 resolution error for {fqdn}: {e}")

    return sorted(set(ips))


def build_ip_records(parsed_entries, include_v6, ipinfo_token):
    """
    Processes all parsed entries and returns a list of enriched IP records.
    Deduplicates IPs that appear multiple times across different input entries.
    """
    seen_ips = {}       # ip -> record dict
    seen_fqdns = set()  # already-resolved FQDNs, avoids redundant DNS queries

    # Phase 1: collect all IPs and their associated FQDNs
    log("\n--- Phase 1: Resolving entries ---")
    for entry in parsed_entries:
        if entry["type"] == "ip":
            ip = entry["value"]
            if ip not in seen_ips:
                seen_ips[ip] = _new_record(ip)
                log(f"  Raw IP: {ip}")
        else:
            fqdn = entry["value"]
            if fqdn in seen_fqdns:
                log(f"  Skipping duplicate domain: {fqdn}")
                continue
            seen_fqdns.add(fqdn)
            log(f"\nDomain: {fqdn}")
            resolved = resolve_domain(fqdn, include_v6)
            if not resolved:
                log(f"  No IPs resolved for {fqdn}")
                continue
            for ip in resolved:
                if ip not in seen_ips:
                    seen_ips[ip] = _new_record(ip, [fqdn])
                else:
                    if fqdn not in seen_ips[ip]["fqdns"]:
                        seen_ips[ip]["fqdns"].append(fqdn)

    log(f"\nTotal unique IPs collected: {len(seen_ips)}")

    # Phase 2: enrich each unique IP
    log("\n--- Phase 2: Enriching IPs ---")
    ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None
    shodan_session = requests.Session()
    total_ips = len(seen_ips)
    for idx, (ip, record) in enumerate(seen_ips.items(), 1):
        log(f"\n[{idx}/{total_ips}] Enriching {ip} (FQDNs: {', '.join(record['fqdns']) or 'none'})")

        # IPinfo
        if ipinfo_handler:
            log(f"  Querying IPinfo...")
        else:
            log(f"  Skipping IPinfo (no token provided)")
        ipinfo_data = ipinfo_get(ip, ipinfo_handler)
        if 'Error' not in ipinfo_data:
            record.update({
                "hostname": ipinfo_data.get("hostname", "N/A"),
                "org":      ipinfo_data.get("org",      "N/A"),
                "city":     ipinfo_data.get("city",     "N/A"),
                "region":   ipinfo_data.get("region",   "N/A"),
                "country":  ipinfo_data.get("country",  "N/A"),
            })
            log(f"    Hostname='{record['hostname']}', Org='{record['org']}'")
        else:
            record["ipinfo_error"] = ipinfo_data['Error']
            log(f"    IPinfo Error: {ipinfo_data['Error']}")

        # Reverse DNS
        log(f"  Reverse DNS lookup...")
        try:
            rev = socket.gethostbyaddr(ip)
            record["reverse_dns"] = rev[0]
            log(f"    Reverse DNS: {rev[0]}")
        except (socket.herror, socket.gaierror):
            pass
        except Exception as e:
            log(f"    Reverse DNS error: {e}")

        # Shodan — skip IPv6 (not supported by InternetDB) and private/reserved IPs
        if validators.ip_address.ipv6(ip) is True:
            log(f"  Skipping Shodan (IPv6 not supported by InternetDB)")
            record["shodan_no_info"] = True
        elif not _is_public_ip(ip):
            log(f"  Skipping Shodan (private/reserved IP: {ip})")
            record["shodan_no_info"] = True
        else:
            log(f"  Querying Shodan...")
            shodan_data = shodan_get_info(ip, session=shodan_session)
            if shodan_data["error"]:
                record["shodan_error"] = shodan_data["error"]
                log(f"    Shodan Error: {shodan_data['error']}")
            elif shodan_data["no_info"]:
                record["shodan_no_info"] = True
                log(f"    Shodan: No information available")
            else:
                record["ports"]            = shodan_data.get("ports",     [])
                record["tags"]             = shodan_data.get("tags",      [])
                record["cpes"]             = shodan_data.get("cpes",      [])
                record["vulns"]            = shodan_data.get("vulns",     [])
                record["shodan_hostnames"] = shodan_data.get("hostnames", [])
                cve_count = len(record["vulns"])
                log(f"    Ports={record['ports']}, Tags={record['tags']}, CPEs={len(record['cpes'])}, CVEs={cve_count}")
                if cve_count > 0:
                    log(f"    \033[91mCVEs found:\033[0m {', '.join(record['vulns'])}")
            sleep(1.1)  # rate-limit: only pause when a Shodan request was actually made

    return list(seen_ips.values())


def build_fqdn_index(ip_records):
    """
    Builds the By-FQDN view data from IP records.
    Each unique FQDN gets one entry aggregating all IPs, ports, vulns, orgs, countries.
    Records with no FQDNs (raw IP inputs) are excluded.
    """
    fqdn_map = {}

    for record in ip_records:
        for fqdn in record["fqdns"]:
            if fqdn not in fqdn_map:
                fqdn_map[fqdn] = {
                    "fqdn": fqdn,
                    "ips": [],
                    "reverse_dns": [],
                    "shodan_hostnames": set(),
                    "ports": set(),
                    "vulns": set(),
                    "orgs": [],
                    "countries": []
                }
            entry = fqdn_map[fqdn]
            if record["ip"] not in entry["ips"]:
                entry["ips"].append(record["ip"])
            if record["reverse_dns"] not in ("N/A", "") and record["reverse_dns"] not in entry["reverse_dns"]:
                entry["reverse_dns"].append(record["reverse_dns"])
            entry["shodan_hostnames"].update(record["shodan_hostnames"])
            entry["ports"].update(record["ports"])
            entry["vulns"].update(record["vulns"])
            if record["org"] not in ("N/A", "") and record["org"] not in entry["orgs"]:
                entry["orgs"].append(record["org"])
            if record["country"] not in ("N/A", "") and record["country"] not in entry["countries"]:
                entry["countries"].append(record["country"])

    # Convert set accumulators to sorted lists for JSON serialisation
    for entry in fqdn_map.values():
        entry["shodan_hostnames"] = sorted(entry["shodan_hostnames"])
        entry["ports"] = sorted(entry["ports"])
        entry["vulns"] = sorted(entry["vulns"])

    return list(fqdn_map.values())


def compute_summary_stats(ip_records):
    """Returns summary statistics for the report header."""
    all_fqdns = set()
    all_cves = set()
    ips_with_cves = 0

    for record in ip_records:
        all_fqdns.update(record["fqdns"])
        all_cves.update(record["vulns"])
        if record["vulns"]:
            ips_with_cves += 1

    return {
        "total_ips": len(ip_records),
        "total_fqdns": len(all_fqdns),
        "ips_with_cves": ips_with_cves,
        "total_unique_cves": len(all_cves)
    }


# ---------------------------------------------------------------------------
# HTML Report Generation
# ---------------------------------------------------------------------------

def _safe_json(obj):
    """Serializes to JSON and escapes </script> to prevent tag injection."""
    return json.dumps(obj, ensure_ascii=False).replace('</script>', r'<\/script>')


def generate_html_report(ip_records, fqdn_index, stats, output_dir="results"):
    """Generates a single self-contained HTML report file."""
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.html")
    generation_time = now.strftime("%Y-%m-%d %H:%M:%S")

    by_ip_json = _safe_json(ip_records)
    by_fqdn_json = _safe_json(fqdn_index)
    stats_json = _safe_json(stats)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>D2I Enrichment Report — {generation_time}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,sans-serif;font-size:14px;background:#f0f2f7;color:#1a1a2e;padding:16px}}
a{{color:#2c3e87}}

/* Header */
header{{margin-bottom:16px}}
h1{{font-size:1.35rem;color:#1a1a2e;font-weight:700}}
.generated{{color:#666;font-size:0.82rem;margin-top:3px}}

/* Stats bar */
.stats-bar{{display:flex;gap:20px;flex-wrap:wrap;background:#fff;border:1px solid #dde3f0;border-radius:8px;padding:10px 18px;margin-top:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.stat{{font-size:0.88rem;color:#444}}
.stat strong{{font-size:1.05rem}}
.stat-cve strong{{color:#c0392b}}

/* Search */
.search-wrap{{margin-bottom:12px;display:flex;gap:8px;align-items:center}}
#search-input{{flex:1;padding:8px 12px;border:1px solid #ccd;border-radius:5px;font-size:14px;outline:none}}
#search-input:focus{{border-color:#2c3e87;box-shadow:0 0 0 2px rgba(44,62,135,.15)}}
#search-clear{{padding:8px 14px;border:1px solid #ccd;border-radius:5px;cursor:pointer;background:#fff;font-size:13px;color:#555}}
#search-clear:hover{{background:#f0f2f7}}
.search-hint{{font-size:12px;color:#888}}

/* Tabs */
.tab-bar{{display:flex;gap:3px;margin-bottom:0}}
.tab-btn{{padding:8px 22px;border:1px solid #ccd;border-bottom:none;border-radius:5px 5px 0 0;cursor:pointer;background:#e2e6f0;font-size:13px;font-weight:500;color:#555;transition:background .15s}}
.tab-btn.active{{background:#fff;color:#2c3e87;font-weight:700;border-color:#ccd}}
.tab-btn:not(.active):hover{{background:#d0d5e8}}

/* Tab panels */
.tab-panel{{display:none;background:#fff;border:1px solid #ccd;border-radius:0 5px 5px 5px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.06)}}
.tab-panel.active{{display:block}}
.table-wrap{{overflow-x:auto}}

/* Table */
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
thead{{position:sticky;top:0;z-index:5}}
th{{background:#2c3e87;color:#fff;padding:8px 10px;text-align:left;cursor:pointer;white-space:nowrap;user-select:none;border-right:1px solid rgba(255,255,255,.15)}}
th:last-child{{border-right:none}}
th:hover{{background:#1a2a6c}}
.sort-ind{{display:inline-block;margin-left:4px;opacity:.7;font-size:10px;min-width:10px}}

/* Filter row */
.filter-row td{{background:#eef0f8;padding:3px 4px;border-bottom:1px solid #ccd}}
.col-filter{{width:100%;padding:3px 6px;border:1px solid #bbc;border-radius:3px;font-size:11px;outline:none}}
.col-filter:focus{{border-color:#2c3e87}}

/* Body rows */
tbody tr{{transition:background .1s}}
tbody tr:nth-child(even){{background:#f8f9fc}}
tbody tr:hover{{background:#edf0f9}}
td{{padding:5px 10px;vertical-align:top;max-width:260px;word-break:break-word;border-bottom:1px solid #eef}}

/* CVE row highlight */
tr.has-cve{{border-left:4px solid #e74c3c}}
tr.has-cve>td:first-child{{background:rgba(231,76,60,.05)}}

/* Badges */
.badge{{display:inline-block;border-radius:3px;padding:1px 5px;margin:1px 1px;font-size:11px;line-height:1.4;font-weight:500}}
.badge-default{{background:#e8f0fe;color:#1a56b0}}
.badge-cve{{background:#fdecea;color:#c0392b}}
.badge-port{{background:#e6f9f0;color:#1a7a4a}}
.badge-cpe{{background:#fdf6e3;color:#7a5f00}}
.badge-tag{{background:#f0e8fe;color:#5b1ab0}}
.na{{color:#aaa;font-style:italic}}
.err{{color:#c0392b;font-style:italic;font-size:11px}}
.no-info{{color:#888;font-style:italic;font-size:11px}}

/* Severity filter bar */
.sev-filter-bar{{display:flex;gap:5px;padding:8px 12px;border-bottom:1px solid #dde3f0;background:#f8f9fc;flex-wrap:wrap;align-items:center}}
.sev-filter-lbl{{font-size:11px;color:#888;margin-right:2px;font-weight:500}}
.sev-filter-btn{{padding:3px 11px;border:1px solid #ccd;border-radius:12px;cursor:pointer;background:#fff;font-size:11px;color:#555;transition:background .12s}}
.sev-filter-btn.active{{background:#2c3e87;color:#fff;border-color:#2c3e87}}
.sev-filter-btn:hover:not(.active){{background:#e8eaf6}}

/* Severity label button (in table cell) */
.sev-th,.notes-th{{width:1%;white-space:nowrap}}
.sev-btn{{border:none;cursor:pointer;border-radius:3px;padding:2px 8px;font-size:11px;white-space:nowrap;background:#f0f0f0;color:#aaa;font-family:inherit;min-width:96px;text-align:center}}
.sev-btn.sev-critical{{background:#fdecea;color:#c0392b;font-weight:600}}
.sev-btn.sev-interesting{{background:#fef0e7;color:#d35400;font-weight:600}}
.sev-btn.sev-reviewed{{background:#e9f7ef;color:#1e8449;font-weight:600}}
.sev-btn.sev-false-pos{{background:#ecf0f1;color:#7f8c8d;font-weight:600}}

/* Row severity tints */
tbody tr.row-sev-critical{{border-left:4px solid #e74c3c;background:rgba(231,76,60,.05)}}
tbody tr.row-sev-critical:nth-child(even){{background:rgba(231,76,60,.09)}}
tbody tr.row-sev-interesting{{border-left:4px solid #e67e22;background:rgba(230,126,34,.05)}}
tbody tr.row-sev-interesting:nth-child(even){{background:rgba(230,126,34,.09)}}
tbody tr.row-sev-reviewed{{border-left:4px solid #27ae60;background:rgba(39,174,96,.04)}}
tbody tr.row-sev-reviewed:nth-child(even){{background:rgba(39,174,96,.08)}}
tbody tr.row-sev-false-pos{{border-left:4px solid #bdc3c7;background:rgba(189,195,199,.07)}}
tbody tr.row-sev-false-pos:nth-child(even){{background:rgba(189,195,199,.13)}}

/* Notes input */
.notes-input{{width:100%;min-width:130px;padding:3px 6px;border:1px solid #dde;border-radius:3px;font-size:11px;background:transparent;font-family:inherit;color:#333}}
.notes-input:focus{{outline:none;border-color:#2c3e87;background:#fff}}
.notes-input::placeholder{{color:#ccc}}

/* Row count */
.row-count{{text-align:right;padding:5px 12px;color:#888;font-size:11px;border-top:1px solid #eef;background:#fafbff}}

/* Navigation links (clickable badges) */
.nav-link{{cursor:pointer;text-decoration:underline;text-underline-offset:2px}}
.nav-link:hover{{opacity:.75}}

/* Hidden */
tr.hidden{{display:none}}
</style>
</head>
<body>

<header>
  <h1>Domain &amp; IP Enrichment Report</h1>
  <p class="generated">Generated: {generation_time}</p>
  <div class="stats-bar">
    <div class="stat">Unique IPs: <strong id="s-ips">—</strong></div>
    <div class="stat">Unique FQDNs: <strong id="s-fqdns">—</strong></div>
    <div class="stat stat-cve">IPs with CVEs: <strong id="s-cve-ips">—</strong></div>
    <div class="stat stat-cve">Unique CVEs: <strong id="s-cves">—</strong></div>
  </div>
</header>

<div class="search-wrap">
  <input type="text" id="search-input" placeholder="Search IPs, FQDNs, CVEs, CPEs, ports, org, country…" autocomplete="off" spellcheck="false">
  <button id="search-clear">Clear</button>
  <span class="search-hint">Filters active tab</span>
</div>

<div class="tab-bar">
  <button class="tab-btn active" data-tab="by-ip">By IP</button>
  <button class="tab-btn" data-tab="by-fqdn">By FQDN</button>
</div>

<div id="tab-by-ip" class="tab-panel active">
  <div class="sev-filter-bar">
    <span class="sev-filter-lbl">Show:</span>
    <button class="sev-filter-btn active" data-tab="by-ip" data-sev="all">All</button>
    <button class="sev-filter-btn" data-tab="by-ip" data-sev="critical">🔴 Critical</button>
    <button class="sev-filter-btn" data-tab="by-ip" data-sev="interesting">🟠 Interesting</button>
    <button class="sev-filter-btn" data-tab="by-ip" data-sev="reviewed">🟢 Reviewed</button>
    <button class="sev-filter-btn" data-tab="by-ip" data-sev="false_pos">⬜ False Positive</button>
    <button class="sev-filter-btn" data-tab="by-ip" data-sev="none">Unlabelled</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr id="th-by-ip">
          <th class="sev-th">Label</th>
          <th data-col="ip">IP<span class="sort-ind" id="si-by-ip-ip"></span></th>
          <th data-col="reverse_dns">Reverse DNS<span class="sort-ind" id="si-by-ip-reverse_dns"></span></th>
          <th data-col="fqdns">FQDNs<span class="sort-ind" id="si-by-ip-fqdns"></span></th>
          <th data-col="ports">Ports<span class="sort-ind" id="si-by-ip-ports"></span></th>
          <th data-col="tags">Tags<span class="sort-ind" id="si-by-ip-tags"></span></th>
          <th data-col="cpes">CPEs<span class="sort-ind" id="si-by-ip-cpes"></span></th>
          <th data-col="vulns">Vulns (CVEs)<span class="sort-ind" id="si-by-ip-vulns"></span></th>
          <th data-col="shodan_hostnames">Shodan Hostnames<span class="sort-ind" id="si-by-ip-shodan_hostnames"></span></th>
          <th data-col="hostname">IPinfo Hostname<span class="sort-ind" id="si-by-ip-hostname"></span></th>
          <th data-col="org">Org<span class="sort-ind" id="si-by-ip-org"></span></th>
          <th data-col="city">City<span class="sort-ind" id="si-by-ip-city"></span></th>
          <th data-col="region">Region<span class="sort-ind" id="si-by-ip-region"></span></th>
          <th data-col="country">Country<span class="sort-ind" id="si-by-ip-country"></span></th>
          <th class="notes-th">Notes</th>
        </tr>
        <tr class="filter-row" id="fr-by-ip">
          <td></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="ip" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="reverse_dns" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="fqdns" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="ports" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="tags" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="cpes" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="vulns" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="shodan_hostnames" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="hostname" placeholder="filter IPinfo hostname…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="org" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="city" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="region" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="country" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-ip" data-col="__notes__" placeholder="filter…"></td>
        </tr>
      </thead>
      <tbody id="tbody-by-ip"></tbody>
    </table>
  </div>
  <p class="row-count" id="rc-by-ip"></p>
</div>

<div id="tab-by-fqdn" class="tab-panel">
  <div class="sev-filter-bar">
    <span class="sev-filter-lbl">Show:</span>
    <button class="sev-filter-btn active" data-tab="by-fqdn" data-sev="all">All</button>
    <button class="sev-filter-btn" data-tab="by-fqdn" data-sev="critical">🔴 Critical</button>
    <button class="sev-filter-btn" data-tab="by-fqdn" data-sev="interesting">🟠 Interesting</button>
    <button class="sev-filter-btn" data-tab="by-fqdn" data-sev="reviewed">🟢 Reviewed</button>
    <button class="sev-filter-btn" data-tab="by-fqdn" data-sev="false_pos">⬜ False Positive</button>
    <button class="sev-filter-btn" data-tab="by-fqdn" data-sev="none">Unlabelled</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr id="th-by-fqdn">
          <th class="sev-th">Label</th>
          <th data-col="fqdn">FQDN<span class="sort-ind" id="si-by-fqdn-fqdn"></span></th>
          <th data-col="ips">IPs<span class="sort-ind" id="si-by-fqdn-ips"></span></th>
          <th data-col="reverse_dns">Reverse DNS<span class="sort-ind" id="si-by-fqdn-reverse_dns"></span></th>
          <th data-col="shodan_hostnames">Shodan Hostnames<span class="sort-ind" id="si-by-fqdn-shodan_hostnames"></span></th>
          <th data-col="ports">Ports<span class="sort-ind" id="si-by-fqdn-ports"></span></th>
          <th data-col="vulns">Vulns (CVEs)<span class="sort-ind" id="si-by-fqdn-vulns"></span></th>
          <th data-col="orgs">Org<span class="sort-ind" id="si-by-fqdn-orgs"></span></th>
          <th data-col="countries">Country<span class="sort-ind" id="si-by-fqdn-countries"></span></th>
          <th class="notes-th">Notes</th>
        </tr>
        <tr class="filter-row" id="fr-by-fqdn">
          <td></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="fqdn" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="ips" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="reverse_dns" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="shodan_hostnames" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="ports" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="vulns" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="orgs" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="countries" placeholder="filter…"></td>
          <td><input class="col-filter" data-tab="by-fqdn" data-col="__notes__" placeholder="filter…"></td>
        </tr>
      </thead>
      <tbody id="tbody-by-fqdn"></tbody>
    </table>
  </div>
  <p class="row-count" id="rc-by-fqdn"></p>
</div>

<script>
const BY_IP_DATA = {by_ip_json};
const BY_FQDN_DATA = {by_fqdn_json};
const STATS = {stats_json};
const REPORT_KEY = 'd2i_{generation_time}'.replace(/[\s:]/g, '_');
var SEVERITIES = [
  {{ val: '',            label: '— Label',          cls: ''              }},
  {{ val: 'critical',    label: '🔴 Critical',       cls: 'sev-critical'   }},
  {{ val: 'interesting', label: '🟠 Interesting',    cls: 'sev-interesting' }},
  {{ val: 'reviewed',    label: '🟢 Reviewed',       cls: 'sev-reviewed'   }},
  {{ val: 'false_pos',   label: '⬜ False Positive',  cls: 'sev-false-pos'  }}
];

(function() {{
  // ---- State ----
  var state = {{
    activeTab: 'by-ip',
    searchQuery: '',
    sortConfig: {{
      'by-ip':   {{ col: null, dir: 'asc' }},
      'by-fqdn': {{ col: null, dir: 'asc' }}
    }},
    colFilters: {{
      'by-ip':   {{}},
      'by-fqdn': {{}}
    }},
    severityFilter: {{ 'by-ip': 'all', 'by-fqdn': 'all' }},
    labels: {{}},
    notes:  {{}}
  }};

  // Row cache: {{ tabId: [{{ tr, searchText, record }}] }}
  var rowCache = {{}};

  // ---- Column definitions ----
  var COLS = {{
    'by-ip': [
      {{ key: '__severity__',     type: 'severity' }},
      {{ key: 'ip',               type: 'text'     }},
      {{ key: 'reverse_dns',      type: 'text'     }},
      {{ key: 'fqdns',            type: 'fqdn-arr' }},
      {{ key: 'ports',            type: 'port'     }},
      {{ key: 'tags',             type: 'tag'      }},
      {{ key: 'cpes',             type: 'cpe'      }},
      {{ key: 'vulns',            type: 'cve'      }},
      {{ key: 'shodan_hostnames', type: 'arr'      }},
      {{ key: 'hostname',         type: 'text'     }},
      {{ key: 'org',              type: 'text'     }},
      {{ key: 'city',             type: 'text'     }},
      {{ key: 'region',           type: 'text'     }},
      {{ key: 'country',          type: 'text'     }},
      {{ key: '__notes__',        type: 'notes'    }}
    ],
    'by-fqdn': [
      {{ key: '__severity__',     type: 'severity' }},
      {{ key: 'fqdn',             type: 'text'    }},
      {{ key: 'ips',              type: 'ip-arr'  }},
      {{ key: 'reverse_dns',      type: 'arr'     }},
      {{ key: 'shodan_hostnames', type: 'arr'     }},
      {{ key: 'ports',            type: 'port'    }},
      {{ key: 'vulns',            type: 'cve'     }},
      {{ key: 'orgs',             type: 'arr'     }},
      {{ key: 'countries',        type: 'arr'     }},
      {{ key: '__notes__',        type: 'notes'   }}
    ]
  }};

  // ---- Render helpers ----
  function escHtml(s) {{
    return String(s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }}

  function renderCell(value, type, record) {{
    // Special: Shodan error/no-info for ports/tags/cpes/vulns
    if ((type === 'port' || type === 'tag' || type === 'cpe' || type === 'cve') && record) {{
      if (record.shodan_error) {{
        return '<span class="err">Shodan error</span>';
      }}
      if (record.shodan_no_info) {{
        return '<span class="no-info">No data</span>';
      }}
    }}
    if ((type === 'text') && record) {{
      if (['hostname','org','city','region','country'].indexOf(type) !== -1 && record.ipinfo_error) {{
        return '<span class="err">IPinfo error</span>';
      }}
    }}
    // IPinfo fields
    if (type === 'text' && record && record.ipinfo_error &&
        ['hostname','org','city','region','country'].indexOf('__never__') === -1) {{
      // handled below per key
    }}

    // Clickable FQDN badges (IP view → FQDN tab)
    if (type === 'fqdn-arr') {{
      if (!Array.isArray(value) || value.length === 0) return '<span class="na">—</span>';
      return value.map(function(v) {{
        return '<span class="badge badge-default nav-link" data-nav-tab="by-fqdn" data-nav-col="fqdn" data-nav-val="' + escHtml(v) + '">' + escHtml(v) + '</span>';
      }}).join('');
    }}

    // Clickable IP badges (FQDN view → IP tab)
    if (type === 'ip-arr') {{
      if (!Array.isArray(value) || value.length === 0) return '<span class="na">—</span>';
      return value.map(function(v) {{
        return '<span class="badge badge-default nav-link" data-nav-tab="by-ip" data-nav-col="ip" data-nav-val="' + escHtml(v) + '">' + escHtml(v) + '</span>';
      }}).join('');
    }}

    if (Array.isArray(value)) {{
      if (value.length === 0) return '<span class="na">—</span>';
      var cls = type === 'cve' ? 'badge-cve' :
                type === 'port' ? 'badge-port' :
                type === 'cpe' ? 'badge-cpe' :
                type === 'tag' ? 'badge-tag' : 'badge-default';
      return value.map(function(v) {{
        return '<span class="badge ' + cls + '">' + escHtml(v) + '</span>';
      }}).join('');
    }}

    if (value === null || value === undefined || value === 'N/A' || value === '') {{
      return '<span class="na">—</span>';
    }}

    return escHtml(String(value));
  }}

  function buildRow(record, tabId) {{
    var cols = COLS[tabId];
    var hasCve = Array.isArray(record.vulns) && record.vulns.length > 0;
    var tr = document.createElement('tr');
    if (hasCve) tr.classList.add('has-cve');
    var rowId = tabId === 'by-ip' ? record.ip : record.fqdn;

    // Apply stored severity class on row
    var curSev = state.labels[tabId + '_' + rowId] || '';
    var curSevInfo = SEVERITIES.find(function(s) {{ return s.val === curSev; }}) || SEVERITIES[0];
    if (curSevInfo.cls) tr.classList.add('row-' + curSevInfo.cls);

    cols.forEach(function(col) {{
      var td = document.createElement('td');

      if (col.type === 'severity') {{
        var btn = document.createElement('button');
        btn.className = 'sev-btn' + (curSevInfo.cls ? ' ' + curSevInfo.cls : '');
        btn.textContent = curSevInfo.label;
        btn.addEventListener('click', function(e) {{
          e.stopPropagation();
          var sev  = state.labels[tabId + '_' + rowId] || '';
          var idx  = SEVERITIES.findIndex(function(s) {{ return s.val === sev; }});
          var next = SEVERITIES[(idx + 1) % SEVERITIES.length];
          state.labels[tabId + '_' + rowId] = next.val;
          if (next.val) {{
            localStorage.setItem(REPORT_KEY + '_lbl_' + tabId + '_' + rowId, next.val);
          }} else {{
            localStorage.removeItem(REPORT_KEY + '_lbl_' + tabId + '_' + rowId);
          }}
          btn.textContent = next.label;
          btn.className = 'sev-btn' + (next.cls ? ' ' + next.cls : '');
          SEVERITIES.forEach(function(s) {{ if (s.cls) tr.classList.remove('row-' + s.cls); }});
          if (next.cls) tr.classList.add('row-' + next.cls);
          if (state.severityFilter[tabId] !== 'all') applyFilters(tabId);
        }});
        td.appendChild(btn);

      }} else if (col.type === 'notes') {{
        var inp = document.createElement('input');
        inp.type = 'text';
        inp.className = 'notes-input';
        inp.value = state.notes[tabId + '_' + rowId] || '';
        inp.placeholder = 'Add note…';
        inp.addEventListener('input', function() {{
          state.notes[tabId + '_' + rowId] = inp.value;
          if (inp.value) {{
            localStorage.setItem(REPORT_KEY + '_note_' + tabId + '_' + rowId, inp.value);
          }} else {{
            localStorage.removeItem(REPORT_KEY + '_note_' + tabId + '_' + rowId);
          }}
          // Refresh search text for this row in the cache
          var cache = rowCache[tabId] || [];
          for (var i = 0; i < cache.length; i++) {{
            if (cache[i].record === record) {{
              cache[i].searchText = getSearchText(record, tabId);
              break;
            }}
          }}
          if (state.searchQuery || state.colFilters[tabId]['__notes__']) applyFilters(tabId);
        }});
        td.appendChild(inp);

      }} else if (col.type === 'text' && record.ipinfo_error &&
          ['hostname','org','city','region','country'].indexOf(col.key) !== -1) {{
        td.innerHTML = '<span class="err">IPinfo error</span>';
      }} else {{
        td.innerHTML = renderCell(record[col.key], col.type, record);
      }}

      tr.appendChild(td);
    }});

    return tr;
  }}

  function getSearchText(record, tabId) {{
    var parts = [];
    if (tabId === 'by-ip') {{
      parts.push(record.ip || '');
      parts.push(record.reverse_dns || '');
      if (record.fqdns) parts.push(record.fqdns.join(' '));
      parts.push(record.org || '');
      parts.push(record.hostname || '');
      parts.push(record.country || '');
      if (record.vulns) parts.push(record.vulns.join(' '));
      if (record.cpes) parts.push(record.cpes.join(' '));
      if (record.ports) parts.push(record.ports.join(' '));
      if (record.tags) parts.push(record.tags.join(' '));
      if (record.shodan_hostnames) parts.push(record.shodan_hostnames.join(' '));
    }} else {{
      parts.push(record.fqdn || '');
      if (record.ips) parts.push(record.ips.join(' '));
      if (record.reverse_dns) parts.push(record.reverse_dns.join(' '));
      if (record.shodan_hostnames) parts.push(record.shodan_hostnames.join(' '));
      if (record.vulns) parts.push(record.vulns.join(' '));
      if (record.orgs) parts.push(record.orgs.join(' '));
      if (record.countries) parts.push(record.countries.join(' '));
      if (record.ports) parts.push(record.ports.join(' '));
    }}
    var rowId = tabId === 'by-ip' ? record.ip : record.fqdn;
    var note = state.notes[tabId + '_' + rowId] || '';
    if (note) parts.push(note);
    return parts.join(' ').toLowerCase();
  }}

  function getColText(record, col, tabId) {{
    if (col === '__notes__') {{
      var rowId = tabId === 'by-ip' ? record.ip : record.fqdn;
      return (state.notes[tabId + '_' + rowId] || '').toLowerCase();
    }}
    var v = record[col];
    if (Array.isArray(v)) return v.join(' ').toLowerCase();
    if (v === null || v === undefined) return '';
    return String(v).toLowerCase();
  }}

  // ---- Build row cache ----
  function buildCache(tabId) {{
    var data = tabId === 'by-ip' ? BY_IP_DATA : BY_FQDN_DATA;
    var cache = [];
    data.forEach(function(record) {{
      var tr = buildRow(record, tabId);
      cache.push({{
        tr: tr,
        searchText: getSearchText(record, tabId),
        record: record
      }});
    }});
    rowCache[tabId] = cache;
    // Append all rows to tbody
    var tbody = document.getElementById('tbody-' + tabId);
    tbody.innerHTML = '';
    cache.forEach(function(item) {{ tbody.appendChild(item.tr); }});
  }}

  // ---- Apply filters (toggles .hidden) ----
  function applyFilters(tabId) {{
    var q = state.searchQuery.toLowerCase();
    var filters = state.colFilters[tabId];
    var sevFilter = state.severityFilter[tabId];
    var visible = 0;
    var cache = rowCache[tabId] || [];

    cache.forEach(function(item) {{
      var show = true;
      var rowId = tabId === 'by-ip' ? item.record.ip : item.record.fqdn;

      // Global search
      if (q && item.searchText.indexOf(q) === -1) show = false;

      // Column filters (AND)
      if (show) {{
        Object.keys(filters).forEach(function(col) {{
          if (!filters[col]) return;
          var colText = getColText(item.record, col, tabId);
          if (colText.indexOf(filters[col]) === -1) show = false;
        }});
      }}

      // Severity filter
      if (show && sevFilter && sevFilter !== 'all') {{
        var rowSev = state.labels[tabId + '_' + rowId] || '';
        if (sevFilter === 'none') {{
          if (rowSev !== '') show = false;
        }} else {{
          if (rowSev !== sevFilter) show = false;
        }}
      }}

      item.tr.classList.toggle('hidden', !show);
      if (show) visible++;
    }});

    var rcEl = document.getElementById('rc-' + tabId);
    rcEl.textContent = visible + ' / ' + cache.length + ' rows';
  }}

  // ---- Sort ----
  function applySort(tabId) {{
    var sc = state.sortConfig[tabId];
    if (!sc.col) return;
    var cache = rowCache[tabId] || [];
    var col = sc.col;
    var dir = sc.dir === 'asc' ? 1 : -1;

    cache.sort(function(a, b) {{
      var av = a.record[col];
      var bv = b.record[col];
      // Arrays: sort by length for cves/ports, or join for text
      if (Array.isArray(av)) av = av.join(' ');
      if (Array.isArray(bv)) bv = bv.join(' ');
      if (av === null || av === undefined || av === 'N/A') av = '';
      if (bv === null || bv === undefined || bv === 'N/A') bv = '';
      av = String(av).toLowerCase();
      bv = String(bv).toLowerCase();
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    }});

    // Re-order DOM
    var tbody = document.getElementById('tbody-' + tabId);
    cache.forEach(function(item) {{ tbody.appendChild(item.tr); }});
    rowCache[tabId] = cache;
  }}

  function updateSortIndicators(tabId) {{
    var sc = state.sortConfig[tabId];
    COLS[tabId].forEach(function(c) {{
      var el = document.getElementById('si-' + tabId + '-' + c.key);
      if (!el) return;
      if (c.key === sc.col) {{
        el.textContent = sc.dir === 'asc' ? ' ▲' : ' ▼';
      }} else {{
        el.textContent = '';
      }}
    }});
  }}

  function render(tabId) {{
    if (!rowCache[tabId]) buildCache(tabId);
    applySort(tabId);
    applyFilters(tabId);
    updateSortIndicators(tabId);
  }}

  // ---- Cross-tab navigation ----
  function navigateTo(targetTab, filterCol, filterVal) {{
    // Reset all column filters for the target tab, then set the one we want
    state.colFilters[targetTab] = {{}};
    state.colFilters[targetTab][filterCol] = filterVal.toLowerCase();
    // Sync filter input DOM elements
    document.querySelectorAll('.col-filter').forEach(function(inp) {{
      if (inp.dataset.tab === targetTab) {{
        inp.value = (inp.dataset.col === filterCol) ? filterVal : '';
      }}
    }});
    // Clear global search so it doesn't conflict
    state.searchQuery = '';
    document.getElementById('search-input').value = '';
    switchTab(targetTab);
  }}

  // ---- Tab switching ----
  function switchTab(tabId) {{
    state.activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(function(btn) {{
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    }});
    document.querySelectorAll('.tab-panel').forEach(function(panel) {{
      panel.classList.toggle('active', panel.id === 'tab-' + tabId);
    }});
    render(tabId);
  }}

  // ---- Init ----
  function init() {{
    // Stats
    document.getElementById('s-ips').textContent = STATS.total_ips;
    document.getElementById('s-fqdns').textContent = STATS.total_fqdns;
    document.getElementById('s-cve-ips').textContent = STATS.ips_with_cves;
    document.getElementById('s-cves').textContent = STATS.total_unique_cves;

    // Tab buttons
    document.querySelectorAll('.tab-btn').forEach(function(btn) {{
      btn.addEventListener('click', function() {{ switchTab(btn.dataset.tab); }});
    }});

    // Sort on header click
    document.querySelectorAll('#th-by-ip th, #th-by-fqdn th').forEach(function(th) {{
      th.addEventListener('click', function() {{
        var tabId = th.closest('table').closest('.tab-panel').id.replace('tab-', '');
        var col = th.dataset.col;
        var sc = state.sortConfig[tabId];
        if (sc.col === col) {{
          sc.dir = sc.dir === 'asc' ? 'desc' : 'asc';
        }} else {{
          sc.col = col;
          sc.dir = 'asc';
        }}
        render(tabId);
      }});
    }});

    // Column filters
    document.querySelectorAll('.col-filter').forEach(function(input) {{
      input.addEventListener('input', function() {{
        var tabId = input.dataset.tab;
        var col = input.dataset.col;
        state.colFilters[tabId][col] = input.value.toLowerCase();
        applyFilters(tabId);
      }});
    }});

    // Global search
    document.getElementById('search-input').addEventListener('input', function() {{
      state.searchQuery = this.value;
      applyFilters(state.activeTab);
    }});
    document.getElementById('search-clear').addEventListener('click', function() {{
      state.searchQuery = '';
      document.getElementById('search-input').value = '';
      applyFilters(state.activeTab);
    }});

    // Severity filter bar buttons
    document.querySelectorAll('.sev-filter-btn').forEach(function(btn) {{
      btn.addEventListener('click', function() {{
        var tabId = btn.dataset.tab;
        var sev   = btn.dataset.sev;
        state.severityFilter[tabId] = sev;
        document.querySelectorAll('.sev-filter-btn[data-tab="' + tabId + '"]').forEach(function(b) {{
          b.classList.toggle('active', b.dataset.sev === sev);
        }});
        applyFilters(tabId);
      }});
    }});

    // Delegated click handler for nav-link badges
    document.addEventListener('click', function(e) {{
      var link = e.target.closest('.nav-link');
      if (!link) return;
      navigateTo(link.dataset.navTab, link.dataset.navCol, link.dataset.navVal);
    }});

    // Load persisted labels + notes from localStorage
    ['by-ip', 'by-fqdn'].forEach(function(tabId) {{
      var data = tabId === 'by-ip' ? BY_IP_DATA : BY_FQDN_DATA;
      data.forEach(function(record) {{
        var rowId = tabId === 'by-ip' ? record.ip : record.fqdn;
        var lbl  = localStorage.getItem(REPORT_KEY + '_lbl_'  + tabId + '_' + rowId);
        var note = localStorage.getItem(REPORT_KEY + '_note_' + tabId + '_' + rowId);
        if (lbl)  state.labels[tabId + '_' + rowId] = lbl;
        if (note) state.notes[tabId  + '_' + rowId] = note;
      }});
    }});

    // Initial render
    render('by-ip');
  }}

  document.addEventListener('DOMContentLoaded', init);
}})();
</script>
</body>
</html>"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    log(f"\nHTML report generated: {filename}")
    print(filename)  # stdout — can be captured/piped: python d2i.py -f ... | xargs open
    return filename


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Resolves domains/IPs to enriched data and generates a rich self-contained HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-f', '--file',
                        required=True,
                        type=validate_file,
                        help='Input file with one domain/subdomain/URL/IP per line.')
    parser.add_argument('-v6', '--version6',
                        action='store_true',
                        help='Include IPv6 address resolution.')
    parser.add_argument('--ipinfo_token',
                        default=os.getenv("IPINFO_TOKEN"),
                        help='IPinfo.io API token. Can also be set via IPINFO_TOKEN env var.')

    args = parser.parse_args()

    log('======># Starting D2I #<=======')
    log(f"Input file : {args.file}")
    log(f"IPv6       : {'enabled' if args.version6 else 'disabled'}")
    log(f"IPinfo     : {'token provided' if args.ipinfo_token else 'NO TOKEN — IP details will be missing'}")
    log('================================')

    # Read and parse input
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        log(f"Error reading file: {e}")
        sys.exit(1)

    log(f"\nParsing {len(lines)} lines...")
    parsed_entries = []
    for line_num, line in enumerate(lines, 1):
        entry = parse_entry(line)
        if entry is None:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                log(f"  Line {line_num}: Invalid entry '{stripped}' — skipped")
        else:
            parsed_entries.append(entry)

    ip_count = sum(1 for e in parsed_entries if e["type"] == "ip")
    domain_count = sum(1 for e in parsed_entries if e["type"] == "domain")
    log(f"  Valid entries: {ip_count} raw IPs, {domain_count} domains/URLs")

    if not parsed_entries:
        log("No valid entries found. Exiting.")
        sys.exit(0)

    # Build records
    ip_records = build_ip_records(parsed_entries, args.version6, args.ipinfo_token)

    if not ip_records:
        log("No IP records collected. Exiting.")
        sys.exit(0)

    # Build FQDN index and stats
    fqdn_index = build_fqdn_index(ip_records)
    stats = compute_summary_stats(ip_records)

    # Generate report
    log('\n--- Phase 3: Generating report ---')
    output_file = generate_html_report(ip_records, fqdn_index, stats)

    log('\n================================')
    log(f"Total unique IPs   : {stats['total_ips']}")
    log(f"Total unique FQDNs : {stats['total_fqdns']}")
    log(f"IPs with CVEs      : {stats['ips_with_cves']}")
    log(f"Unique CVEs found  : {stats['total_unique_cves']}")
    log(f"Report saved to    : {output_file}")
    log('======># D2I Finished #<=======')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        log(f"\nUnexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
