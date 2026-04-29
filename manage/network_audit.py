#!/usr/bin/env python3
"""
network_audit.py
----------------
Three-part network audit tool:

  Report 1 — Container IP Audit
      Queries Portainer for all containers on 'canister' and 'doodoo',
      checks whether each container has a *static* IP assigned, and
      verifies that IP is recorded in phpIPAM.

  Report 2 — UniFi vs phpIPAM Diff
      Compares every device UniFi knows about against phpIPAM's address
      space and flags IPs that are missing from either side, plus
      hostname / MAC mismatches where both sides have a record.

  Report 3 — NPM Proxy Host Consistency
      For each proxy host in Nginx Proxy Manager, resolves the forward
      destination to an IP, looks it up in phpIPAM and Portainer, and
      assesses whether the destination name is consistent with the
      proxy domain name.

Output: console tables + optional CSV files.

Dependencies:
    pip install requests urllib3 tabulate python-dotenv

Usage:
    cp .env.example .env        # then fill in your values
    python3 network_audit.py [--csv]        # --csv writes CSV files to ./audit_output/
"""

import argparse
import csv
import ipaddress
import os
import socket
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

NPM_URL         = os.getenv("NPM_URL",  "http://npm.chcasa.us:81")
NPM_USER        = _require("NPM_USER")    # NPM admin email address
NPM_PASS        = _require("NPM_PASS")

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
class UnifiClientRecord:
    mac: str
    ip: str
    hostname: str
    is_wired: bool
    last_seen: int          # epoch


@dataclass
class NpmProxyRecord:
    domain: str           # e.g. ipam.chcasa.us
    forward_host: str     # as configured in NPM (IP, hostname, or FQDN)
    forward_port: int
    forward_scheme: str   # http / https
    enabled: bool


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
    def __init__(self, base_url: str, app: str, app_token: str, debug: bool = False):
        self.base = f"{base_url.rstrip('/')}/api/{app}"
        self._debug = debug
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

    def _get(self, path: str, timeout: int = 10) -> dict | list | None:
        url = f"{self.base}{path}"
        if self._debug:
            import time
            print(f"  [phpIPAM] GET {url}", flush=True)
            t0 = time.monotonic()
        try:
            r = self.session.get(url, verify=False, timeout=timeout)
        except requests.exceptions.Timeout:
            print(f"  [phpIPAM] *** TIMEOUT after {timeout}s: {url}", flush=True)
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"  [phpIPAM] *** CONNECTION ERROR: {e}", flush=True)
            return None
        if self._debug:
            elapsed = time.monotonic() - t0
            print(f"  [phpIPAM]  -> {r.status_code} in {elapsed:.2f}s", flush=True)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        payload = r.json()
        if not payload.get("success"):
            if self._debug:
                print(f"  [phpIPAM]  -> success=false  message={payload.get('message')}", flush=True)
            return None
        return payload.get("data")

    def get_subnets(self) -> list[dict]:
        return self._get("/subnets/") or []

    def get_addresses_in_subnet(self, subnet_id: int) -> list[dict]:
        return self._get(f"/subnets/{subnet_id}/addresses/") or []

    def fetch_known_networks(self) -> list[ipaddress.IPv4Network]:
        """Return every subnet defined in phpIPAM as an IPv4Network object."""
        networks = []
        for s in self.get_subnets():
            subnet = s.get("subnet", "")
            mask   = s.get("mask", "")
            if subnet and mask:
                try:
                    networks.append(ipaddress.IPv4Network(f"{subnet}/{mask}", strict=False))
                except ValueError:
                    pass
        return networks

    def fetch_all_addresses(self) -> dict[str, PhpIpamRecord]:
        """Returns {ip_str: PhpIpamRecord} for every recorded address."""
        subnets = self.get_subnets()
        if self._debug:
            print(f"  [phpIPAM] Found {len(subnets)} subnets", flush=True)
        all_records: dict[str, PhpIpamRecord] = {}
        for subnet in subnets:
            sid   = subnet.get("id")
            sdesc = subnet.get("description") or subnet.get("subnet", "")
            snet  = subnet.get("subnet", "")
            smask = subnet.get("mask", "")
            if self._debug:
                print(f"  [phpIPAM] Fetching addresses for subnet {snet}/{smask} (id={sid}, '{sdesc}')", flush=True)
            addrs = self.get_addresses_in_subnet(sid)
            if self._debug:
                print(f"  [phpIPAM]  -> {len(addrs)} addresses", flush=True)
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
    def __init__(self, base_url: str, api_key: str, site: str = "default", debug: bool = False):
        self.base = base_url.rstrip("/")
        self.site = site
        self._debug = debug
        self.session = requests.Session()
        self.session.verify = False
        # Local Network Integration API key — generate this from within the
        # Network Application at: Settings → Control Plane → Integrations → API Keys
        # This is NOT the same as the Site Manager key from unifi.ui.com.
        # The Site Manager key is a cloud API that does not expose client/station data.
        self.session.headers.update({"X-API-Key": api_key})
        # The integration v1 path for site discovery
        self.api_base = f"{self.base}/proxy/network/integration/v1"
        # Classic internal path — richer client data than integration/v1
        self.classic_base = f"{self.base}/proxy/network/api/s/{site}"

    def _get(self, path: str, timeout: int = 10) -> list:
        if self._debug:
            import time
            print(f"  [UniFi] GET {path}", flush=True)
            t0 = time.monotonic()
        try:
            r = self.session.get(path, timeout=timeout)
        except requests.exceptions.Timeout:
            print(f"  [UniFi] *** TIMEOUT after {timeout}s: {path}", flush=True)
            return []
        except requests.exceptions.ConnectionError as e:
            print(f"  [UniFi] *** CONNECTION ERROR: {e}", flush=True)
            return []
        if self._debug:
            elapsed = time.monotonic() - t0
            print(f"  [UniFi]  -> {r.status_code} in {elapsed:.2f}s", flush=True)
        if r.status_code == 401:
            print(f"  [UniFi] *** 401 Unauthorized — wrong key, or key is a Site Manager", flush=True)
            print(f"           key from unifi.ui.com instead of a local Network Application key.", flush=True)
            return []
        if r.status_code == 403:
            print(f"  [UniFi] *** 403 Forbidden — key may lack permissions or site '{self.site}' is wrong.", flush=True)
            return []
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            # Classic API wraps in {"data": [...], "meta": {...}}
            if data.get("meta", {}).get("rc") == "error":
                msg = data.get("meta", {}).get("msg", "unknown")
                print(f"  [UniFi] *** API error: {msg}", flush=True)
                return []
            return data.get("data", [])
        return data

    def get_active_clients(self) -> list[dict]:
        """Currently connected clients."""
        return self._get(f"{self.classic_base}/stat/sta")

    def get_all_known_clients(self) -> list[dict]:
        """All clients UniFi has ever seen, including inactive."""
        return self._get(f"{self.classic_base}/rest/user")

    def fetch_clients(self) -> dict[str, UnifiClientRecord]:
        """Returns {ip: UnifiClient}. Uses known clients; active ones overwrite."""
        clients: dict[str, UnifiClientRecord] = {}

        for c in self.get_all_known_clients():
            ip = (c.get("use_fixedip") and c.get("fixed_ip")) or ""
            if not ip:
                continue  # skip clients with no known IP
            mac  = (c.get("mac") or "").lower()
            host = c.get("hostname") or c.get("name") or mac
            clients[ip] = UnifiClientRecord(
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
            clients[ip] = UnifiClientRecord(
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
    subnet_filter=None,
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
            if subnet_filter and not subnet_filter(ip):
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
    unifi_clients: dict[str, UnifiClientRecord],
    phpipam_addresses: dict[str, PhpIpamRecord],
    subnet_filter=None,
    write_csv: bool = False,
):
    print("\n" + "═" * 90)
    print("  REPORT 2 — UNIFI vs phpIPAM DIFF")
    print("═" * 90)

    all_ips = sorted(
        {ip for ip in (set(unifi_clients.keys()) | set(phpipam_addresses.keys()))
         if not subnet_filter or subnet_filter(ip)},
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
#  NPM API
# ══════════════════════════════════════════════════════════════════════════════

class NpmClient:
    def __init__(self, base_url: str, email: str, password: str, debug: bool = False):
        self.base    = base_url.rstrip("/")
        self._debug  = debug
        self.session = requests.Session()
        self.session.verify = False
        self._authenticate(email, password)

    def _authenticate(self, email: str, password: str):
        r = self.session.post(
            f"{self.base}/api/tokens",
            json={"identity": email, "secret": password},
            timeout=10,
        )
        r.raise_for_status()
        token = r.json().get("token")
        if not token:
            sys.exit("NPM auth failed: no token in response")
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def _get(self, path: str, timeout: int = 10) -> list | dict:
        url = f"{self.base}{path}"
        if self._debug:
            import time
            print(f"  [NPM] GET {url}", flush=True)
            t0 = time.monotonic()
        try:
            r = self.session.get(url, timeout=timeout)
        except requests.exceptions.Timeout:
            print(f"  [NPM] *** TIMEOUT after {timeout}s: {url}", flush=True)
            return []
        except requests.exceptions.ConnectionError as e:
            print(f"  [NPM] *** CONNECTION ERROR: {e}", flush=True)
            return []
        if self._debug:
            elapsed = time.monotonic() - t0
            print(f"  [NPM]  -> {r.status_code} in {elapsed:.2f}s", flush=True)
        r.raise_for_status()
        return r.json()

    def fetch_proxy_hosts(self) -> list[NpmProxyRecord]:
        hosts = self._get("/api/nginx/proxy-hosts?expand=certificate")
        if not isinstance(hosts, list):
            print("  [NPM] Unexpected response shape for proxy hosts", flush=True)
            return []
        records = []
        for h in hosts:
            # NPM supports multiple domain names per host; expand each one
            domains = h.get("domain_names") or []
            fwd_host   = h.get("forward_host", "")
            fwd_port   = int(h.get("forward_port", 80))
            fwd_scheme = h.get("forward_scheme", "http")
            enabled    = not h.get("disabled", False)
            for domain in domains:
                records.append(NpmProxyRecord(
                    domain=domain,
                    forward_host=fwd_host,
                    forward_port=fwd_port,
                    forward_scheme=fwd_scheme,
                    enabled=enabled,
                ))
        return records


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
#  REPORT 3 — NPM PROXY HOST CONSISTENCY
# ══════════════════════════════════════════════════════════════════════════════

def report_npm_consistency(
    proxy_hosts: list[NpmProxyRecord],
    phpipam_addresses: dict[str, PhpIpamRecord],
    containers: list[ContainerRecord] | None,
    write_csv: bool = False,
    debug: bool = False,
):
    print("\n" + "═" * 110)
    print("  REPORT 3 — NPM PROXY HOST CONSISTENCY")
    print("═" * 110)

    # Build a flat IP → container_name lookup from Portainer data
    ip_to_container: dict[str, str] = {}
    if containers:
        for c in containers:
            for net in c.networks.values():
                ip = net.get("ip", "")
                if ip:
                    ip_to_container[ip] = c.name

    rows = []
    for h in sorted(proxy_hosts, key=lambda x: x.domain):
        status_prefix = "" if h.enabled else "⏸ disabled — "

        # Resolve forward_host to an IP
        resolved_ip = _resolve_host(h.forward_host)
        if debug and h.forward_host != resolved_ip:
            print(f"  [NPM] {h.forward_host} → {resolved_ip or 'unresolvable'}", flush=True)

        if not resolved_ip:
            rows.append([
                h.domain,
                f"{h.forward_host}:{h.forward_port}",
                "—",
                "—",
                "—",
                f"{status_prefix}❌ cannot resolve forward host",
            ])
            continue

        phpipam_rec   = phpipam_addresses.get(resolved_ip)
        phpipam_host  = phpipam_rec.hostname if phpipam_rec else ""
        container_name = ip_to_container.get(resolved_ip, "")

        if not phpipam_rec:
            ipam_display = "❌ not in phpIPAM"
        else:
            ipam_display = phpipam_host or "(no hostname)"

        assessment = _assess_consistency(
            h.domain, h.forward_host, phpipam_host, container_name
        )
        if status_prefix:
            assessment = status_prefix + assessment

        rows.append([
            h.domain,
            f"{h.forward_scheme}://{h.forward_host}:{h.forward_port}",
            resolved_ip,
            ipam_display,
            container_name or "—",
            assessment,
        ])

    headers = ["Domain", "Forward", "Resolved IP", "phpIPAM Host", "Container", "Assessment"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))

    total     = len(rows)
    warnings  = sum(1 for r in rows if "⚠" in r[-1])
    errors    = sum(1 for r in rows if "❌" in r[-1])
    disabled  = sum(1 for r in rows if "⏸" in r[-1])
    print(f"\n  Total: {total}  |  ✅ Consistent: {total - warnings - errors}  "
          f"|  ⚠ Verify: {warnings}  |  ❌ Errors: {errors}  |  ⏸ Disabled: {disabled}")

    if write_csv:
        _write_csv("audit_output/npm_consistency.csv", headers, rows)


_dns_cache: dict[str, str] = {}

def _resolve_host(host: str) -> str:
    """Resolve a hostname to an IP string. Returns the original string on
    failure so callers can still display it.  Results are cached."""
    if not host:
        return ""
    # Already an IP?
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
        _dns_cache[host] = ip
        return ip
    except socket.gaierror:
        _dns_cache[host] = ""
        return ""


def _assess_consistency(domain: str, forward_host: str,
                         phpipam_hostname: str, container_name: str) -> str:
    """Heuristic: does the proxy domain *look like* it belongs to the
    destination?  We tokenise both sides on common separators and check for
    any shared token of length >= 3.  This catches ipam↔phpipam-web,
    portainer↔portainer, wiki↔wiki, etc. while not claiming certainty."""

    def tokens(s: str) -> set[str]:
        import re
        parts = re.split(r"[-_. /:]", s.lower())
        return {p for p in parts if len(p) >= 3}

    # Pull just the subdomain from the proxy domain (drop the base domain)
    subdomain = domain.split(".")[0] if "." in domain else domain
    left = tokens(subdomain)

    # Gather all name tokens from the destination side
    right: set[str] = set()
    for name in (forward_host, phpipam_hostname, container_name):
        right |= tokens(name)

    if not right:
        return "ℹ no destination name to compare"

    overlap = left & right
    if overlap:
        return f"✅ consistent  ({', '.join(sorted(overlap))})"
    else:
        return f"⚠ verify — '{subdomain}' shares no tokens with destination"


def _make_subnet_filter(
    networks: list[ipaddress.IPv4Network],
) -> "Callable[[str], bool]":
    """Return a predicate that is True when an IP string falls inside any of
    the given networks.  When *networks* is empty the filter accepts everything
    (i.e. --known-subnets-only has no effect if phpIPAM has no subnets)."""
    if not networks:
        return lambda _ip: True
    def _in_subnet(ip_str: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip_str)
            return any(addr in net for net in networks)
        except ValueError:
            return False
    return _in_subnet


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Network audit: Portainer / phpIPAM / UniFi")
    parser.add_argument("--csv", action="store_true", help="Also write CSV output files")
    parser.add_argument("--report", choices=["1", "2", "3", "both", "all"], default="all",
                        help="Which report(s) to run: 1, 2, 3, both (1+2), or all (default: all)")
    parser.add_argument("--debug", action="store_true",
                        help="Print each HTTP request with URL, status, and elapsed time")
    parser.add_argument("--known-subnets-only", action="store_true",
                        help="Exclude IPs from Portainer and UniFi that do not fall "
                             "within any subnet defined in phpIPAM")
    args = parser.parse_args()

    run1 = args.report in ("1", "both", "all")
    run2 = args.report in ("2", "both", "all")
    run3 = args.report in ("3", "all")

    print("\n[ phpIPAM ] Authenticating and fetching addresses...")
    phpipam = PhpIpamClient(PHPIPAM_URL, PHPIPAM_APP, PHPIPAM_TOKEN, debug=args.debug)
    phpipam_addresses = phpipam.fetch_all_addresses()
    print(f"  Found {len(phpipam_addresses)} addresses in phpIPAM")

    subnet_filter = None
    if args.known_subnets_only:
        known_networks = phpipam.fetch_known_networks()
        subnet_filter  = _make_subnet_filter(known_networks)
        print(f"  Subnet filter active: {len(known_networks)} phpIPAM subnet(s) — "
              f"IPs outside these will be excluded from reports")

    containers = None
    if run1 or run3:
        print("\n[ Portainer ] Fetching containers...")
        portainer  = PortainerClient(PORTAINER_URL, PORTAINER_TOKEN)
        containers = portainer.fetch_all_containers(PORTAINER_HOSTS)
        print(f"  Found {len(containers)} containers across {PORTAINER_HOSTS}")

    if run1:
        report_container_audit(containers, phpipam_addresses,
                               subnet_filter=subnet_filter, write_csv=args.csv)

    if run2:
        print("\n[ UniFi ] Fetching client list...")
        unifi = UnifiClient(UNIFI_URL, UNIFI_API_KEY, UNIFI_SITE, debug=args.debug)
        unifi_clients = unifi.fetch_clients()
        print(f"  Found {len(unifi_clients)} clients with known IPs in UniFi")
        report_unifi_vs_phpipam(unifi_clients, phpipam_addresses,
                                subnet_filter=subnet_filter, write_csv=args.csv)

    if run3:
        print("\n[ NPM ] Fetching proxy hosts...")
        npm = NpmClient(NPM_URL, NPM_USER, NPM_PASS, debug=args.debug)
        proxy_hosts = npm.fetch_proxy_hosts()
        print(f"  Found {len(proxy_hosts)} proxy host entries in NPM")
        report_npm_consistency(proxy_hosts, phpipam_addresses, containers,
                               write_csv=args.csv, debug=args.debug)

    print()


if __name__ == "__main__":
    main()
