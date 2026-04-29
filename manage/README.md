# network_audit.py

A three-report audit tool for home/small-office networks running **Portainer**, **phpIPAM**, **UniFi (UDM Pro)**, and **Nginx Proxy Manager**. Designed to keep Docker container IPs and network client IPs honest — statically assigned, documented in phpIPAM, consistent with what UniFi sees, and proxied to the right destinations in NPM.

---

## Reports

### Report 1 — Container IP Audit (Portainer → phpIPAM)

Queries Portainer for every container across all configured hosts, inspects each container's network configuration, and cross-references against phpIPAM.

For each container it shows:

- Which Docker network it's on and what IP it has
- Whether the IP is **statically assigned** (set via `ipv4_address` in the compose file) or dynamically assigned by Docker's IPAM
- Whether that IP is **recorded in phpIPAM**, and if so, what hostname phpIPAM has for it

Static IP detection works by checking `NetworkSettings.Networks[name].IPAMConfig.IPv4Address` in the Docker inspect response. This field is only populated when an explicit static IP was set — an empty field means the IP is dynamic.

> **Note:** Containers running in `host` network mode inherit the host's IP and will appear with no Docker network. This is expected behavior.

---

### Report 2 — UniFi vs phpIPAM Diff

Pulls the full client list from UniFi (both active and all known clients) and compares it against every address recorded in phpIPAM. Flags:

- IPs **only in UniFi** — device on the network with no phpIPAM record
- IPs **only in phpIPAM** — documented address not currently seen by UniFi
- IPs in both but with **hostname or MAC mismatches** between the two systems

---

### Report 3 — NPM Proxy Host Consistency

For each proxy host in Nginx Proxy Manager, resolves the `forward_host` to an IP address, then cross-references that IP against phpIPAM (for its recorded hostname) and Portainer (for a matching container name). Produces an assessment for each entry:

- **✅ consistent** — the proxy domain name shares tokens with the destination name (e.g. `ipam.chcasa.us` → `phpipam-web` → match on `ipam`)
- **⚠ verify** — no name overlap detected; worth a manual check
- **❌ cannot resolve** — the forward host couldn't be resolved to an IP
- **⏸ disabled** — the proxy rule is present but disabled in NPM

The consistency check is a heuristic, not authoritative. It tokenises the subdomain of the proxy domain and the destination names on common separators (`-`, `_`, `.`) and looks for any shared token of three or more characters. This catches obvious mismatches (e.g. `wiki.chcasa.us` pointing to `phpipam-web`) while being lenient enough to handle naming variations.

Disabled proxy hosts are included in the report but prefixed so they stand out.

---

## Requirements

- Python 3.10+
- Portainer with API access
- phpIPAM with API enabled
- UniFi Network Application on a UniFi OS console (UDM Pro, UDR, UCG, etc.)
- Nginx Proxy Manager with admin credentials

```bash
pip install requests urllib3 tabulate python-dotenv
```

---

## Setup

### 1. Clone and configure

```bash
git clone <your-repo-url>
cd <repo-dir>
cp .env.example .env
```

Edit `.env` with your credentials. See [Environment Variables](#environment-variables) below.

### 2. Configure Portainer

Generate an API token in Portainer: **Settings → My Account → API tokens**

The token only needs read access. Set `PORTAINER_TOKEN` in `.env`.

### 3. Configure phpIPAM

In phpIPAM, go to **Administration → API** and create an API application:

- **App security** must be set to **SSL with App token** (not "User token")
- Read access is sufficient

The static app token is displayed on that page. Set `PHPIPAM_TOKEN` in `.env`.

> The app ID (e.g. `audit`) goes in `PHPIPAM_APP`. The script uses token-based auth — no username or password is needed.

### 4. Configure UniFi

Generate a **local** Network Application API key — this is **not** the same as the Site Manager key from `unifi.ui.com`.

In your Network Application: **Settings → Control Plane → Integrations → API Keys → Create**

Set `UNIFI_API_KEY` in `.env`.

> The Site Manager API (from `unifi.ui.com`) is a cloud API scoped to infrastructure devices. It does not expose the client/station list this script needs. You must use a local key generated from within the Network Application.

For `UNIFI_SITE`, use the internal site ID, not the display name. On most single-site UDM Pro setups this is `default`. To confirm yours:

```bash
curl -sk https://10.0.0.1/proxy/network/integration/v1/sites \
  -H "X-API-Key: YOUR_KEY" | python3 -m json.tool
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values. The `.env` file is excluded from version control by `.gitignore`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORTAINER_URL` | No | `https://canister:9443` | Base URL of your Portainer instance |
| `PORTAINER_TOKEN` | **Yes** | — | Portainer API token |
| `PORTAINER_HOSTS` | No | `canister,doodoo` | Comma-separated Portainer environment names to audit |
| `PHPIPAM_URL` | No | `http://phpipam.chcasa.us` | Base URL of your phpIPAM instance |
| `PHPIPAM_APP` | No | `audit` | phpIPAM API app ID |
| `PHPIPAM_TOKEN` | **Yes** | — | phpIPAM static app token |
| `UNIFI_URL` | No | `https://192.168.1.1` | UDM Pro address |
| `UNIFI_SITE` | No | `default` | UniFi internal site ID |
| `UNIFI_API_KEY` | **Yes** | — | Local Network Application API key |
| `NPM_URL` | No | `http://npm.chcasa.us:81` | Base URL of your NPM instance including port |
| `NPM_USER` | **Yes** | — | NPM admin email address |
| `NPM_PASS` | **Yes** | — | NPM admin password |

---

## Usage

```bash
# Run all three reports, console output only
python3 network_audit.py

# Run all reports and write CSV files to ./audit_output/
python3 network_audit.py --csv

# Run only the container audit (Report 1)
python3 network_audit.py --report 1

# Run only the UniFi/phpIPAM diff (Report 2)
python3 network_audit.py --report 2

# Run only the NPM proxy consistency check (Report 3)
python3 network_audit.py --report 3

# Reports 1 and 2 only (original "both" behaviour)
python3 network_audit.py --report both

# Exclude IPs that don't fall within any subnet defined in phpIPAM
python3 network_audit.py --known-subnets-only

# Show each HTTP request with URL, status code, and elapsed time
python3 network_audit.py --debug

# Combine flags
python3 network_audit.py --report 3 --csv --debug
```

### `--known-subnets-only`

When this flag is set, the script fetches the subnet list from phpIPAM and builds an IP filter from it. Any IP from Portainer or UniFi that doesn't fall within one of those subnets is silently excluded from both reports.

This is useful for filtering out Docker-internal addresses (e.g. `172.17.0.0/16` bridge networks) that you haven't and don't intend to document in phpIPAM.

If phpIPAM returns no subnets, the filter is a no-op and all IPs are included.

### `--debug`

Prints every HTTP request made to phpIPAM and UniFi, including the full URL, response status code, and time elapsed. Useful for diagnosing connectivity issues or slow responses.

Example output:

```
[ phpIPAM ] Authenticating and fetching addresses...
  [phpIPAM] GET http://phpipam.local/api/audit/subnets/
  [phpIPAM]  -> 200 in 0.04s
  [phpIPAM] Found 6 subnets
  [phpIPAM] Fetching addresses for subnet 10.0.0.0/24 (id=1, 'LAN')
  [phpIPAM]  -> 200 in 0.03s
  [phpIPAM]  -> 12 addresses
```

---

## Output

### Console

Both reports print formatted tables to stdout. Report 1 example:

```
Host       Container        State    Network    IP            Static?     phpIPAM
---------  ---------------  -------  ---------  ------------  ----------  ---------------------------
canister   jellyfin         running  macvlan    10.0.0.42     ✅ static   ✅ in phpIPAM (jellyfin)
canister   sonarr           running  macvlan    10.0.0.43     ✅ static   ❌ NOT in phpIPAM
doodoo     uptime-kuma      running  bridge     172.18.0.3    ⚠ dynamic  ❌ NOT in phpIPAM
```

### CSV

When `--csv` is passed, up to three files are written to `./audit_output/`:

- `container_audit.csv` — Report 1 data
- `unifi_phpipam_diff.csv` — Report 2 data
- `npm_consistency.csv` — Report 3 data

The `audit_output/` directory is excluded from version control by `.gitignore`.

---

### 5. Configure Nginx Proxy Manager

NPM uses email/password authentication to issue a JWT — there is no API key option. Set `NPM_USER` and `NPM_PASS` in `.env` to your NPM admin credentials.

`NPM_URL` should include the port (default is `81`):

```
NPM_URL=http://npm.chcasa.us:81
```

---

## Project Structure

```
.
├── network_audit.py    # Main script  (Reports 1, 2, 3)
├── .env.example        # Environment variable template
├── .env                # Your local credentials (git-ignored)
├── .gitignore
├── README.md
└── audit_output/       # CSV output directory (git-ignored, created on demand)
```

---

## Notes

- SSL certificate warnings for self-signed certs are suppressed. If your Portainer or phpIPAM instance uses a valid certificate, you can remove the `urllib3.disable_warnings()` call near the top of the script.
- All HTTP requests to phpIPAM and UniFi have a 10-second timeout. Connection errors and timeouts are caught and reported rather than crashing the script.
- UniFi client data is sourced from both the active client list (`stat/sta`) and the full known client list (`rest/user`). Active clients take precedence, so a device's current IP is used when available.
