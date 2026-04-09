# Local Network Troubleshooter

A lightweight Python monitor that continuously checks key points in your home network and logs results for troubleshooting intermittent slowdowns.

## What it measures

- **ICMP ping latency** to local and internet targets (router, HA box, DNS resolvers, etc.)
- **TCP connect time** to services like DNS/HTTPS
- **Direct DNS query latency** against each DNS server (example: AdGuard vs public DNS)
- **Multiple DNS probe hostnames** so one blocked/broken domain does not create a false alarm

This helps isolate whether slowness is:

- local LAN / Wi-Fi issues (router/AP)
- your Home Assistant / AdGuard host
- DNS resolution path
- or WAN/ISP path

## Quick start

```bash
python3 network_monitor.py init-config --output config.json
# edit config.json for your IPs and targets
python3 network_monitor.py run
```

By default, probes run every `30` seconds (`interval_seconds`). If outages are very brief, increase sampling frequency (for example `5`-`10` seconds), but note that this increases probe traffic and log volume.

### Simplest startup commands

If you want minimal commands:

```bash
# terminal 1: collect probes
python3 network_monitor.py run

# terminal 2: keep HTML refreshed
python3 network_monitor.py watch-report
```

Or use a single command that launches both:

```bash
python3 network_monitor.py start
```

Logs are written to:

- `logs/network_log.csv`
- `logs/network_log.jsonl`

Generate a quick HTML summary:

```bash
python3 network_monitor.py report --csv logs/network_log.csv --output logs/network_report.html --since-hours 24
```

The report now includes a **Plain-English diagnosis** section that highlights likely issue domains (local DNS/AdGuard, LAN path, or WAN/ISP) based on comparative success rates and P95 latency across target groups.
By default, report timestamps are displayed in your browser's local timezone (`--display-timezone browser`). You can override with `--display-timezone UTC` or an IANA timezone like `--display-timezone America/New_York`.
The report tables (including **Target**) are sortable by clicking column headers, and include a legend explaining `Dominant area` values and hint interpretation.
It also includes:
- severity labels on incident windows
- incident count-by-hour rollups (displayed in browser local time when using `--display-timezone browser`)
- confidence-scored hypotheses
- actionable playbooks ("if this, then do this")

You can also include a router log bundle (tar/tar.gz) in the report generation step:

```bash
python3 network_monitor.py report \
  --csv logs/network_log.csv \
  --output logs/network_report.html \
  --since-hours 24 \
  --router-bundle /path/to/router_logs.tar
```

When provided, the report adds:
- an **Automated correlation checklist** of incident windows from monitor data
- a **best-effort router bundle scan** for suspicious WAN/DNS/disconnect log lines

If you want to inspect a router bundle **without mixing it into monitor report output**, use:

```bash
python3 network_monitor.py inspect-router-bundle \
  --bundle /path/to/router_logs.tar \
  --output logs/router_bundle_inspection.txt
```

To auto-refresh the HTML report on a schedule (no manual regeneration):

```bash
python3 network_monitor.py watch-report \
  --csv logs/network_log.csv \
  --output logs/network_report.html \
  --since-hours 24 \
  --display-timezone browser \
  --interval-seconds 60
```

## Running on a MacBook Pro (for mesh-hop testing)

Yes — this tool works well for that use case:
- run it on your Mac in different physical locations (near router vs mesh hop areas)
- compare generated reports from each location to isolate Wi-Fi/mesh backhaul effects

macOS quick notes:
- verify Python 3: `python3 --version`
- if needed, create config once: `python3 network_monitor.py init-config --output config.json`
- then run with defaults: `python3 network_monitor.py start`

## DNS probe hostnames (`dns_probe_hosts`)

Use 2+ stable hostnames (for example `cloudflare.com`, `google.com`) rather than only one domain. This makes the monitor more resilient if one name is blocked by policy, filtered, or temporarily not resolvable in your environment.

If you see browser errors like `ERR_NAME_NOT_RESOLVED`, that is exactly the type of DNS failure this monitor should log. Compare results across your local resolver (AdGuard) and a public resolver to isolate whether the issue is local DNS policy/service or upstream connectivity.

## Suggested config for your setup

Use your real internal IPs:

- router (often `192.168.1.1`)
- HA/AdGuard host (your Beelink/Proxmox VM IP)
- AdGuard DNS IP

Then keep one or two public references (`1.1.1.1`, `8.8.8.8`) so you can compare LAN vs WAN behavior.

## Running continuously

### Option A: Home Assistant / Linux box (recommended)

Run as a systemd service or inside a small container/VM on the same network segment as HA.

### Option B: Windows 11 desktop

Run with Task Scheduler at login/startup:

```powershell
python C:\path\to\network_monitor.py run --config C:\path\to\config.json
```

## Interpreting patterns

- **Only router + local targets degrade:** likely Wi-Fi/router/LAN
- **LAN is fine, public targets degrade:** likely ISP/WAN path
- **Only DNS probes degrade/fail:** DNS resolver issue (AdGuard host load, upstream DNS, etc.)
- **HA/AdGuard target degrades while others are fine:** host saturation/resource contention

## Notes

- Ping timing uses host OS `ping` command for portability.
- DNS probes use direct UDP queries to specific resolvers (not system DNS cache path).
- For deeper root cause, combine this with router logs + modem signal/event logs + ISP outage windows.
