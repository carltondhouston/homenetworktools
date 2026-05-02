#!/usr/bin/env python3
"""
unifi_export.py — Export UniFi Network Application configuration for review.

Pulls config and stat endpoints from the local UniFi API and writes them
to a timestamped JSON file suitable for offline review / audit.

Usage:
    python unifi_export.py [--out DIR]

Requires:  pip install requests python-dotenv
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

# Suppress SSL warnings for self-signed UDM Pro cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Endpoints to export ────────────────────────────────────────────────────────
# Each entry: (label, path_template)
# {site} is replaced with UNIFI_SITE at runtime.
ENDPOINTS = [
    # ── Network topology ────────────────────────────────────────
    ("networks",            "/proxy/network/api/s/{site}/rest/networkconf"),
    ("port_profiles",       "/proxy/network/api/s/{site}/rest/portconf"),
    ("routing",             "/proxy/network/api/s/{site}/rest/routing"),
    ("dns_records",         "/proxy/network/api/s/{site}/rest/setting/mgmt"),
    # ── Wireless ────────────────────────────────────────────────
    ("wlan_configs",        "/proxy/network/api/s/{site}/rest/wlanconf"),
    ("wlan_groups",         "/proxy/network/api/s/{site}/rest/wlangroup"),
    ("radio_schedule",      "/proxy/network/api/s/{site}/rest/schedule"),
    # ── Firewall ────────────────────────────────────────────────
    ("firewall_rules",      "/proxy/network/api/s/{site}/rest/firewallrule"),
    ("firewall_groups",     "/proxy/network/api/s/{site}/rest/firewallgroup"),
    ("port_forwards",       "/proxy/network/api/s/{site}/rest/portforward"),
    ("traffic_rules",       "/proxy/network/api/s/{site}/rest/trafficrule"),
    ("traffic_routes",      "/proxy/network/api/s/{site}/rest/trafficroute"),
    # ── Devices & clients ───────────────────────────────────────
    ("devices",             "/proxy/network/api/s/{site}/stat/device"),
    ("clients_active",      "/proxy/network/api/s/{site}/stat/sta"),
    ("clients_all",         "/proxy/network/api/s/{site}/stat/alluser"),
    ("client_groups",       "/proxy/network/api/s/{site}/rest/user"),
    # ── Site-wide settings ──────────────────────────────────────
    ("site_settings",       "/proxy/network/api/s/{site}/rest/setting"),
    ("site_info",           "/proxy/network/api/s/{site}/stat/sysinfo"),
    # ── Security / IDS ──────────────────────────────────────────
    ("threat_events",       "/proxy/network/api/s/{site}/stat/ips/event"),
    ("dpi_stats",           "/proxy/network/api/s/{site}/stat/dpi"),
    ("anomaly_events",      "/proxy/network/api/s/{site}/stat/anomalies"),
    # ── VPN ─────────────────────────────────────────────────────
    ("vpn_configs",         "/proxy/network/api/s/{site}/rest/vpnconfig"),
    # ── RADIUS ──────────────────────────────────────────────────
    ("radius_profiles",     "/proxy/network/api/s/{site}/rest/radiusprofile"),
    # ── Dashboard / health ──────────────────────────────────────
    ("health",              "/proxy/network/api/s/{site}/stat/health"),
    ("dashboard",           "/proxy/network/api/s/{site}/stat/dashboard"),
    ("alarms",              "/proxy/network/api/s/{site}/list/alarm"),
    ("events_recent",       "/proxy/network/api/s/{site}/stat/event?_limit=200"),
    # ── Switch port details ─────────────────────────────────────
    ("port_overrides",      "/proxy/network/api/s/{site}/rest/device"),
    ("port_profiles_full",  "/proxy/network/api/s/{site}/rest/portconf"),
]


def load_config() -> dict:
    load_dotenv()
    cfg = {
        "url":     os.getenv("UNIFI_URL", "").rstrip("/"),
        "site":    os.getenv("UNIFI_SITE", "default"),
        "api_key": os.getenv("UNIFI_API_KEY", ""),
    }
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        print(f"[ERROR] Missing env vars: {', '.join('UNIFI_' + k.upper() for k in missing)}")
        sys.exit(1)
    return cfg


def make_session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "X-API-KEY":    api_key,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    })
    return s


def fetch(session: requests.Session, base_url: str, path: str) -> tuple[bool, any]:
    url = base_url + path
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 200:
            return True, r.json()
        return False, {"http_status": r.status_code, "body": r.text[:500]}
    except requests.RequestException as exc:
        return False, {"error": str(exc)}


def sanitize(obj):
    """
    Recursively redact sensitive values so the export is safe to share.

    Catches three categories:
      1. Key-name patterns  — field names that suggest a secret value
      2. Value patterns     — values that look like key material regardless of field name
                              (PEM blocks, long hex/base64 tokens)
      3. Explicit field list — known UniFi fields that weren't caught by the above
    """
    # ── 1. Key-name substrings that always indicate a secret ──────────────────
    SENSITIVE_KEY_FRAGMENTS = (
        "password", "passwd",           # passwords / hashes
        "passphrase",                   # WPA passphrases
        "private_key", "privatekey",    # RSA/EC private keys
        "secret",                       # RADIUS shared secret, mesh PSK, etc.
        "psk",                          # pre-shared keys
        "api_key", "apikey", "api_token", "apitoken",  # API credentials
        "mgmt_key", "mgmtkey",          # controller management key
        "token",                        # generic tokens
        "certificate_key", "cert_key",  # TLS private keys stored alongside certs
        "x_ssh",                        # all UniFi x_ssh_* fields (keys, hashes, passwd)
        "x_mesh",                       # mesh PSK / ESSID
        "x_mgmt",                       # management key
        "community",                    # SNMP community string
    )

    # ── 2. Known full field names that are always sensitive ───────────────────
    SENSITIVE_EXACT_FIELDS = {
        "server_certificate",           # UniFi RADIUS: PEM bundle with embedded private key
        "server_certificate_key",       # UniFi RADIUS: standalone private key
        "ca_certificate",               # CA cert — not a secret but contains PEM material
        "x_api_token",                  # local controller API token
        "x_mgmt_key",                   # controller management key
        "utm_token",                    # IPS/UTM token
    }

    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            kl = k.lower()
            # Check exact match first
            if k in SENSITIVE_EXACT_FIELDS:
                result[k] = "**REDACTED**"
            # Check key-name fragment match
            elif any(frag in kl for frag in SENSITIVE_KEY_FRAGMENTS):
                result[k] = "**REDACTED**"
            # Check if the value itself looks like key material (even if field name is innocent)
            elif isinstance(v, str) and _looks_like_key_material(v):
                result[k] = "**REDACTED**"
            else:
                result[k] = sanitize(v)
        return result

    if isinstance(obj, list):
        return [sanitize(i) for i in obj]

    return obj


def _looks_like_key_material(value: str) -> bool:
    """
    Heuristic: does this string look like a raw cryptographic secret?
    Catches PEM blocks, long hex strings, and long base64 blobs.
    """
    import re
    if "-----BEGIN" in value and "KEY" in value:
        return True  # PEM private key block
    # Long hex string (>= 40 chars, only hex)
    if re.fullmatch(r"[0-9a-fA-F]{40,}", value):
        return True
    # Long base64-ish blob (>= 100 chars) — catches encoded certs/keys
    # but avoids triggering on normal short base64 like MAC addresses
    if len(value) >= 100 and re.fullmatch(r"[A-Za-z0-9+/=\n]+", value):
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Export UniFi config for review")
    parser.add_argument("--out", default=".", help="Output directory (default: current dir)")
    parser.add_argument("--no-redact", action="store_true",
                        help="Skip credential redaction (keep file private!)")
    args = parser.parse_args()

    cfg     = load_config()
    session = make_session(cfg["api_key"])
    site    = cfg["site"]
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file   = out_dir / f"unifi_export_{timestamp}.json"
    results    = {}
    ok_count   = 0
    fail_count = 0

    print(f"Connecting to {cfg['url']}  (site: {site})")
    print(f"Fetching {len(ENDPOINTS)} endpoint(s)...\n")

    for label, path_tmpl in ENDPOINTS:
        path    = path_tmpl.format(site=site)
        success, data = fetch(session, cfg["url"], path)
        status  = "✓" if success else "✗"
        if success:
            ok_count += 1
        else:
            fail_count += 1
        print(f"  {status}  {label:<25}  {path}")
        results[label] = data

    # Optionally redact secrets
    if not args.no_redact:
        results = sanitize(results)
        print("\n  Redaction applied. Fields caught by: key-name patterns, exact-field list,")
        print("  and value heuristics (PEM blocks, hex strings, long base64 blobs).")

    export = {
        "meta": {
            "exported_at":     datetime.now().isoformat(),
            "unifi_url":       cfg["url"],
            "site":            site,
            "endpoints_ok":    ok_count,
            "endpoints_failed": fail_count,
            "redacted":        not args.no_redact,
        },
        "data": results,
    }

    with open(out_file, "w") as fh:
        json.dump(export, fh, indent=2, default=str)

    print(f"\n{'─'*60}")
    print(f"  Exported : {ok_count}/{len(ENDPOINTS)} endpoints")
    print(f"  Failed   : {fail_count} (404s are normal for unused features)")
    print(f"  Output   : {out_file}")
    if not args.no_redact:
        print("  Secrets  : redacted — safe to share with Claude")
    print(f"{'─'*60}")


if __name__ == "__main__":
    main()
