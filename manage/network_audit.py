#!/usr/bin/env python3
"""
network_audit.py
----------------
Two-part network audit tool:

  Report 1 — Container IP Audit
      Queries Portainer for all containers on 'canister' and 'doodoo',
      checks whether each container has a *static* IP assigned, and
      verifies that IP is recorded in phpIPAM.

  Report 2 — UniFi vs phpIPAM Diff
      Compares every device UniFi knows about against phpIPAM's address
      space and flags IPs that are missing from either side, plus
      hostname / MAC mismatches where both sides have a record.

Output: console tables + optional CSV files.

Dependencies:
    pip install requests urllib3 tabulate python-dotenv

Usage:
    cp .env.example .env        # then fill in your values
    python3 network_audit.py [--csv]        # --csv writes CSV files to ./audit_output/
"""

import argparse
import csv
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import requests
import urllib3

# ─────────────────────────────────────────────
# Suppress SSL warnings for self-signed certs
# ─────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit("Missing dependency: pip install requests urllib3 tabulate python-dotenv")

try:
    from tabulate import tabulate
except ImportError:
    sys.exit("Missing dependency: pip install requests urllib3 tabulate python-dotenv")

# Load .env from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION — values come from .env (see .env.example)
# ══════════════════════════════════════════════════════════════════════════════

def _require(key: str) -> str:
    val = os.getenv(key)
    if not val:
        sys.exit(f"Missing required environment variable: {key}  (check your .env file)")
    return val

PORTAINER_URL   = os.getenv("PORTAINER_URL",   "https://canister:9443")
PORTAINER_TOKEN = _require("PORTAINER_TOKEN")

PHPIPAM_URL     = os.getenv("PHPIPAM_URL",  "http://phpipam.chcasa.us")
PHPIPAM_APP     = os.getenv("PHPIPAM_APP",  "audit")
PHPIPAM_TOKEN   = _require("PHPIPAM_TOKEN")   # Administration → API → App token

UNIFI_URL       = os.getenv("UNIFI_URL",  "https://192.168.1.1")
UNIFI_SITE      = os.getenv("UNIFI_SITE", "default")
UNIFI_API_KEY   = _require("UNIFI_API_KEY")   # Network Application → Settings → Integrations → API Keys

# Comma-separated in .env: PORTAINER_HOSTS=canister,doodoo
_hosts_raw      = os.getenv("PORTAINER_HOSTS", "canister,doodoo")
PORTAINER_HOSTS = [h.strip() for h in _hosts_raw.split(",") if h.strip()]

# ══════════════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ContainerRecord:
    host: str
    container_id: str
    name: str
    status: str
    networks: dict          # {network_name: {"ip": ..., "static": bool}}

@dataclass
class PhpIpamRecord:
    ip: str
    hostname: str
    mac: str
    subnet_description: str
    is_gateway: bool
    custom_notes: str

@dataclass
class UnifiClient:
    mac: str
    ip: str
    hostname: str
    is_wired: bool
    last_seen: int          # epoch


# ══════════════════════════════════════════════════════════════════════════════
#  PORTAINER API
# ══════════════════════════════════════════════════════════════════════════════

class PortainerClient:
    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": token})
        self.session.verify = False

    def _get(self, path: str) -> dict | list:
        r = self.session.get(f"{self.base}{path}")
        r.raise_for_status()
        return r.json()

    def get_endpoints(self) -> list[dict]:
        return self._get("/api/endpoints")

    def get_containers(self, endpoint_id: int) -> list[dict]:
        """All containers (running + stopped)."""
        return self._get(f"/api/endpoints/{endpoint_id}/docker/containers/json?all=1")

    def inspect_container(self, endpoint_id: int, container_id: str) -> dict:
        return self._get(
            f"/api/endpoints/{endpoint_id}/docker/containers/{container_id}/json"
        )

    def fetch_all_containers(self, host_names: list[str]) -> list[ContainerRecord]:
        endpoints = self.get_endpoints()
        # Filter to requested hosts (match on Name field, case-insensitive)
        target = {h.lower() for h in host_names}
        matched = [e for e in endpoints if e.get("Name", "").lower() in target]
        if not matched:
            print(f"  [WARN] No Portainer endpoints matched: {host_names}")
            print(f"         Available: {[e.get('Name') for e in endpoints]}")
            matched = endpoints  # fall back to all

        records: list[ContainerRecord] = []
        for ep in matched:
            ep_id   = ep["Id"]
            ep_name = ep["Name"]
            print(f"  Querying Portainer endpoint: {ep_name} (id={ep_id})")
            containers = self.get_containers(ep_id)
            for c in containers:
                cid    = c["Id"]
                name   = c["Names"][0].lstrip("/") if c.get("Names") else cid[:12]
                status = c.get("State", "unknown")

                # Inspect for full network details (static IP detection)
                try:
                    detail = self.inspect_container(ep_id, cid)
                except Exception as e:
                    print(f"    [WARN] inspect failed for {name}: {e}")
                    detail = {}

                nets = {}
                net_settings = (detail.get("NetworkSettings") or {}).get("Networks") or {}
                for net_name, net_info in net_settings.items():
                    ip = net_info.get("IPAddress", "")
                    ipam_cfg = net_info.get("IPAMConfig") or {}
                    static_ip = ipam_cfg.get("IPv4Address", "")
                    is_static = bool(static_ip)
                    nets[net_name] = {
                        "ip": ip or static_ip,
                        "static": is_static,
                        "static_ip": static_ip,
                    }

                records.append(ContainerRecord(
                    host=ep_name,
                    container_id=cid[:12],
                    name=name,
                    status=status,
                    networks=nets,
                ))
        return records


# ══════════════════════════════════════════════════════════════════════════════
#  phpIPAM API
# ══════════════════════════════════════════════════════════════════════════════

class PhpIpamClient:
    def __init__(self, base_url: str, app: str, app_token: str):
        self.base = f"{base_url.rstrip('/')}/api/{app}"
        self.session = requests.Session()
        # Static app token — set "App security" to "SSL with App token" in
        # phpIPAM Administration → API.  The token goes in the Authorization
        # header as a Bearer token; phpIPAM also accepts a plain "token"
        # header, included here as a fallback for older phpIPAM versions.
        self.session.headers.update({
            "Authorization": f"Bearer {app_token}",
            "token": app_token,
        })
        self.session.verify = False

    def _get(self, path: str) -> dict | list | None:
        r = self.session.get(f"{self.base}{path}", verify=False)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        payload = r.json()
        if not payload.get("success"):
            return None
        return payload.get("data")

    def get_subnets(self) -> list[dict]:
        return self._get("/subnets/") or []

    def get_addresses_in_subnet(self, subnet_id: int) -> list[dict]:
        return self._get(f"/subnets/{subnet_id}/addresses/") or []

    def fetch_all_addresses(self) -> dict[str, PhpIpamRecord]:
        """Returns {ip_str: PhpIpamRecord} for every recorded address."""
        subnets = self.get_subnets()
        all_records: dict[str, PhpIpamRecord] = {}
        for subnet in subnets:
            sid   = subnet.get("id")
            sdesc = subnet.get("description") or subnet.get("subnet", "")
            addrs = self.get_addresses_in_subnet(sid)
            for a in addrs:
                ip = a.get("ip", "")
                if not ip:
                    continue
                all_records[ip] = PhpIpamRecord(
                    ip=ip,
                    hostname=a.get("hostname") or "",
                    mac=(a.get("mac") or "").lower(),
                    subnet_description=sdesc,
                    is_gateway=bool(int(a.get("is_gateway") or 0)),
                    custom_notes=a.get("note") or "",
                )
        return all_records


# ══════════════════════════════════════════════════════════════════════════════
#  UniFi API  (UDM Pro / UniFi Network Application)
# ══════════════════════════════════════════════════════════════════════════════

class UnifiClient:
    def __init__(self, base_url: str, api_key: str, site: str = "default"):
        self.base = base_url.rstrip("/")
        self.site = site
        self.session = requests.Session()
        self.session.verify = False
        # Official Network Integration API — stateless, no login/logout needed.
        # Generate the key at: Network Application → Settings → Integrations → API Keys
        self.session.headers.update({"X-API-Key": api_key})
        # Base for the official integration API (UDM Pro / UniFi OS)
        self.api_base = f"{self.base}/proxy/network/integration/v1"
        # Base for the classic internal API (broader endpoint coverage)
        self.classic_base = f"{self.base}/proxy/network/api/s/{site}"

    def _get(self, path: str) -> list:
        r = self.session.get(path)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            return data.get("data", [])
        return data

    def get_active_clients(self) -> list[dict]:
        # Classic path — richer per-client data, still works with API key auth
        return self._get(f"{self.classic_base}/stat/sta")

    def get_all_known_clients(self) -> list[dict]:
        """All clients UniFi has ever seen (includes inactive)."""
        return self._get(f"{self.classic_base}/rest/user")

    def fetch_clients(self) -> dict[str, UnifiClient]:
        """Returns {ip: UnifiClient}. Uses known clients; active ones overwrite."""
        clients: dict[str, "UnifiClient"] = {}

        for c in self.get_all_known_clients():
            ip = (c.get("use_fixedip") and c.get("fixed_ip")) or ""
            if not ip:
                continue  # skip clients with no known IP
            mac  = (c.get("mac") or "").lower()
            host = c.get("hostname") or c.get("name") or mac
            clients[ip] = UnifiClient(
                mac=mac,
                ip=ip,
                hostname=host,
                is_wired=not c.get("is_wl", False),
                last_seen=c.get("last_seen", 0),
            )

        # Overlay with currently active clients (they have current IPs)
        for c in self.get_active_clients():
            ip   = c.get("ip", "")
            if not ip:
                continue
            mac  = (c.get("mac") or "").lower()
            host = c.get("hostname") or c.get("name") or mac
            clients[ip] = UnifiClient(
                mac=mac,
                ip=ip,
                hostname=host,
                is_wired=c.get("is_wired", False),
                last_seen=c.get("last_seen", 0),
            )

        return clients


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT 1 — Container IP Audit
# ══════════════════════════════════════════════════════════════════════════════

def report_container_audit(
    containers: list[ContainerRecord],
    phpipam_addresses: dict[str, PhpIpamRecord],
    write_csv: bool = False,
):
    print("\n" + "═" * 90)
    print("  REPORT 1 — CONTAINER IP AUDIT  (Portainer → phpIPAM)")
    print("═" * 90)

    rows = []
    for c in sorted(containers, key=lambda x: (x.host, x.name)):
        if not c.networks:
            rows.append([
                c.host, c.name, c.status, "—", "—", "—", "⚠ no networks",
            ])
            continue

        for net_name, net in c.networks.items():
            ip = net["ip"]
            if not ip:
                rows.append([
                    c.host, c.name, c.status, net_name, "—",
                    "❌ dynamic / no IP", "—",
                ])
                continue

            static_flag = "✅ static" if net["static"] else "⚠ dynamic"
            if ip in phpipam_addresses:
                rec = phpipam_addresses[ip]
                ipam_status = f"✅ in phpIPAM ({rec.hostname or 'no hostname'})"
            else:
                ipam_status = "❌ NOT in phpIPAM"

            rows.append([
                c.host, c.name, c.status, net_name, ip, static_flag, ipam_status,
            ])

    headers = ["Host", "Container", "State", "Network", "IP", "Static?", "phpIPAM"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))

    # Summary counts
    total      = sum(1 for r in rows if r[4] and r[4] != "—")
    missing    = sum(1 for r in rows if "NOT in phpIPAM" in r[-1])
    dynamic    = sum(1 for r in rows if "dynamic" in r[5])
    print(f"\n  Total IPs: {total}  |  Missing from phpIPAM: {missing}  |  Dynamic IPs: {dynamic}")

    if write_csv:
        _write_csv("audit_output/container_audit.csv", headers, rows)


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT 2 — UniFi vs phpIPAM Diff
# ══════════════════════════════════════════════════════════════════════════════

def report_unifi_vs_phpipam(
    unifi_clients: dict[str, "UnifiClient"],
    phpipam_addresses: dict[str, PhpIpamRecord],
    write_csv: bool = False,
):
    print("\n" + "═" * 90)
    print("  REPORT 2 — UNIFI vs phpIPAM DIFF")
    print("═" * 90)

    all_ips = sorted(
        set(unifi_clients.keys()) | set(phpipam_addresses.keys()),
        key=lambda ip: tuple(int(p) for p in ip.split(".") if p.isdigit())
    )

    rows = []
    counts = {"match": 0, "only_unifi": 0, "only_phpipam": 0, "mismatch": 0}

    for ip in all_ips:
        in_unifi  = ip in unifi_clients
        in_phpipam = ip in phpipam_addresses

        u = unifi_clients.get(ip)
        p = phpipam_addresses.get(ip)

        if in_unifi and in_phpipam:
            # Both have it — check for hostname / MAC mismatch
            mac_match  = (u.mac == p.mac) if p.mac else True
            host_match = (
                u.hostname.lower() == p.hostname.lower()
                if u.hostname and p.hostname else True
            )
            if mac_match and host_match:
                status = "✅ match"
                counts["match"] += 1
            else:
                parts = []
                if not mac_match:
                    parts.append(f"MAC: UniFi={u.mac} phpIPAM={p.mac}")
                if not host_match:
                    parts.append(f"host: UniFi={u.hostname} phpIPAM={p.hostname}")
                status = "⚠ mismatch — " + " | ".join(parts)
                counts["mismatch"] += 1
            rows.append([
                ip,
                u.hostname or "—",
                p.hostname or "—",
                u.mac or "—",
                p.mac or "—",
                p.subnet_description or "—",
                status,
            ])

        elif in_unifi:
            counts["only_unifi"] += 1
            rows.append([
                ip,
                u.hostname or "—",
                "—",
                u.mac or "—",
                "—",
                "—",
                "⚠ UniFi only — not in phpIPAM",
            ])

        else:  # only in phpIPAM
            counts["only_phpipam"] += 1
            rows.append([
                ip,
                "—",
                p.hostname or "—",
                "—",
                p.mac or "—",
                p.subnet_description or "—",
                "ℹ phpIPAM only — not seen by UniFi",
            ])

    headers = ["IP", "UniFi Host", "phpIPAM Host", "UniFi MAC", "phpIPAM MAC", "Subnet", "Status"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))

    print(f"\n  ✅ Matched: {counts['match']}  |  ⚠ Mismatch: {counts['mismatch']}  "
          f"|  UniFi only: {counts['only_unifi']}  |  phpIPAM only: {counts['only_phpipam']}")

    if write_csv:
        _write_csv("audit_output/unifi_phpipam_diff.csv", headers, rows)


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _write_csv(path: str, headers: list[str], rows: list[list]):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)
    print(f"  → CSV written: {path}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Network audit: Portainer / phpIPAM / UniFi")
    parser.add_argument("--csv", action="store_true", help="Also write CSV output files")
    parser.add_argument("--report", choices=["1", "2", "both"], default="both",
                        help="Which report to run (default: both)")
    args = parser.parse_args()

    run1 = args.report in ("1", "both")
    run2 = args.report in ("2", "both")

    print("\n[ phpIPAM ] Authenticating and fetching addresses...")
    phpipam = PhpIpamClient(PHPIPAM_URL, PHPIPAM_APP, PHPIPAM_TOKEN)
    phpipam_addresses = phpipam.fetch_all_addresses()
    print(f"  Found {len(phpipam_addresses)} addresses in phpIPAM")

    if run1:
        print("\n[ Portainer ] Fetching containers...")
        portainer = PortainerClient(PORTAINER_URL, PORTAINER_TOKEN)
        containers = portainer.fetch_all_containers(PORTAINER_HOSTS)
        print(f"  Found {len(containers)} containers across {PORTAINER_HOSTS}")
        report_container_audit(containers, phpipam_addresses, write_csv=args.csv)

    if run2:
        print("\n[ UniFi ] Fetching client list...")
        unifi = UnifiClient(UNIFI_URL, UNIFI_API_KEY, UNIFI_SITE)
        unifi_clients = unifi.fetch_clients()
        print(f"  Found {len(unifi_clients)} clients with known IPs in UniFi")
        report_unifi_vs_phpipam(unifi_clients, phpipam_addresses, write_csv=args.csv)

    print()


if __name__ == "__main__":
    main()
