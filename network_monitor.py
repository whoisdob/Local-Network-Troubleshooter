#!/usr/bin/env python3
"""Lightweight local network monitor for home labs.

Collects latency / DNS / TCP-connect metrics and writes CSV + JSONL logs.
Can also generate a quick HTML report from collected CSV data.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import tarfile
import time
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class ProbeResult:
    timestamp: str
    target: str
    probe_type: str
    success: bool
    latency_ms: Optional[float]
    value: Optional[str]
    error: Optional[str]


DEFAULT_CONFIG = {
    "interval_seconds": 30,
    "dns_timeout_seconds": 2.0,
    "tcp_timeout_seconds": 2.0,
    "ping_count": 1,
    "ping_timeout_seconds": 2,
    "dns_servers": ["192.168.1.2", "8.8.8.8"],
    "dns_probe_hosts": ["cloudflare.com", "google.com"],
    "latency_targets": [
        {"name": "router", "host": "192.168.1.1"},
        {"name": "ha_box", "host": "192.168.1.10"},
        {"name": "internet_google", "host": "8.8.8.8"},
        {"name": "internet_cloudflare", "host": "1.1.1.1"},
    ],
    "tcp_targets": [
        {"name": "router_dns", "host": "192.168.1.1", "port": 53},
        {"name": "adguard_dns", "host": "192.168.1.2", "port": 53},
        {"name": "cloudflare_https", "host": "1.1.1.1", "port": 443},
    ],
}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config(path: Path) -> dict:
    if not path.exists():
        return DEFAULT_CONFIG
    with path.open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    merged = dict(DEFAULT_CONFIG)
    merged.update(loaded)
    return merged


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def ping_latency_ms(host: str, timeout_seconds: int, count: int) -> tuple[bool, Optional[float], Optional[str]]:
    # Cross-platform ping flags: Linux/macOS use -c/-W, Windows use -n/-w(ms).
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", str(count), "-w", str(timeout_seconds * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), host]

    started = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds + 2)
    except Exception as exc:  # noqa: BLE001
        return False, None, str(exc)

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode == 0:
        return True, elapsed_ms, None
    return False, None, proc.stderr.strip() or proc.stdout.strip() or "ping_failed"


def tcp_connect_ms(host: str, port: int, timeout_seconds: float) -> tuple[bool, Optional[float], Optional[str]]:
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        sock.connect((host, port))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return True, elapsed_ms, None
    except Exception as exc:  # noqa: BLE001
        return False, None, str(exc)
    finally:
        sock.close()


def _build_dns_query(qname: str, qtype: int = 1) -> tuple[int, bytes]:
    txid = int(time.time() * 1000) & 0xFFFF
    flags = 0x0100
    qdcount = 1
    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    parts = qname.split(".")
    qname_wire = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts) + b"\x00"
    question = qname_wire + struct.pack("!HH", qtype, 1)
    return txid, header + question


def _parse_dns_a_answer(txid: int, data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    r_txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if r_txid != txid or (flags & 0x8000) == 0:
        return []
    idx = 12
    for _ in range(qdcount):
        while idx < len(data) and data[idx] != 0:
            idx += 1 + data[idx]
        idx += 1 + 4
    ips = []
    for _ in range(ancount):
        if idx + 12 > len(data):
            break
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += 1 + data[idx]
            idx += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[idx: idx + 10])
        idx += 10
        rdata = data[idx: idx + rdlen]
        idx += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips


def dns_query_ms(server: str, hostname: str, timeout_seconds: float) -> tuple[bool, Optional[float], Optional[str], Optional[str]]:
    txid, payload = _build_dns_query(hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_seconds)
    started = time.perf_counter()
    try:
        sock.sendto(payload, (server, 53))
        data, _ = sock.recvfrom(512)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        answers = _parse_dns_a_answer(txid, data)
        if answers:
            return True, elapsed_ms, ",".join(answers), None
        return False, None, None, "no_a_record"
    except Exception as exc:  # noqa: BLE001
        return False, None, None, str(exc)
    finally:
        sock.close()


def append_results(csv_path: Path, jsonl_path: Path, rows: Iterable[ProbeResult]) -> None:
    ensure_parent(csv_path)
    ensure_parent(jsonl_path)

    csv_exists = csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as cf, jsonl_path.open("a", encoding="utf-8") as jf:
        writer = csv.DictWriter(cf, fieldnames=list(asdict(next(iter([ProbeResult('', '', '', False, None, None, None)]))).keys()))
        if not csv_exists:
            writer.writeheader()
        for row in rows:
            record = asdict(row)
            writer.writerow(record)
            jf.write(json.dumps(record) + "\n")


def run_monitor(config: dict, csv_path: Path, jsonl_path: Path, loops: Optional[int]) -> None:
    interval = float(config["interval_seconds"])
    ping_timeout = int(config["ping_timeout_seconds"])
    ping_count = int(config["ping_count"])
    tcp_timeout = float(config["tcp_timeout_seconds"])
    dns_timeout = float(config["dns_timeout_seconds"])

    i = 0
    dns_probe_hosts = config.get("dns_probe_hosts")
    if not dns_probe_hosts:
        # Backward compatibility with earlier single-host key.
        fallback_host = config.get("dns_probe_host", "cloudflare.com")
        dns_probe_hosts = [fallback_host]

    while loops is None or i < loops:
        ts = iso_now()
        rows: list[ProbeResult] = []

        for target in config["latency_targets"]:
            ok, ms, err = ping_latency_ms(target["host"], ping_timeout, ping_count)
            rows.append(ProbeResult(ts, target["name"], "ping", ok, round(ms, 2) if ms else None, target["host"], err))

        for target in config["tcp_targets"]:
            ok, ms, err = tcp_connect_ms(target["host"], int(target["port"]), tcp_timeout)
            rows.append(
                ProbeResult(
                    ts,
                    target["name"],
                    "tcp_connect",
                    ok,
                    round(ms, 2) if ms else None,
                    f"{target['host']}:{target['port']}",
                    err,
                )
            )

        for server in config["dns_servers"]:
            for host in dns_probe_hosts:
                ok, ms, value, err = dns_query_ms(server, host, dns_timeout)
                rows.append(
                    ProbeResult(
                        ts,
                        f"dns_{server}_{host}",
                        "dns_query",
                        ok,
                        round(ms, 2) if ms else None,
                        value,
                        err,
                    )
                )

        append_results(csv_path, jsonl_path, rows)

        failures = sum(1 for r in rows if not r.success)
        latencies = [r.latency_ms for r in rows if r.latency_ms is not None]
        avg = round(statistics.mean(latencies), 2) if latencies else None
        print(f"[{ts}] wrote {len(rows)} probes, failures={failures}, avg_latency_ms={avg}")

        i += 1
        if loops is None or i < loops:
            time.sleep(interval)


def _target_domain(target: str) -> str:
    t = target.lower()
    if t.startswith("dns_") and ("192.168." in t or "10." in t or "172." in t):
        return "local_dns"
    if t.startswith("dns_"):
        return "public_dns"
    if "internet_" in t or "cloudflare_https" in t:
        return "wan"
    if "router" in t:
        return "router_lan"
    if "ha_" in t or "adguard" in t:
        return "ha_adguard_host"
    return "other"


def _scan_router_bundle(router_bundle: Path) -> tuple[list[str], list[str]]:
    """Best-effort scan of a router tar bundle for suspicious log lines."""
    if not router_bundle.exists():
        return [], [f"Router bundle not found: {router_bundle}"]

    keywords = [
        "wan",
        "disconnect",
        "pppoe",
        "dhcp",
        "dns",
        "timeout",
        "link down",
        "loss",
        "renew",
        "upstream",
    ]
    matched_lines: list[str] = []
    notes: list[str] = []
    try:
        with tarfile.open(router_bundle, "r:*") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            for member in members[:100]:
                name = member.name.lower()
                if not any(name.endswith(ext) for ext in (".log", ".txt", ".csv", ".json")):
                    continue
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                raw = extracted.read().decode("utf-8", errors="replace")
                for line in raw.splitlines()[:5000]:
                    low = line.lower()
                    if any(k in low for k in keywords):
                        cleaned = re.sub(r"\s+", " ", line.strip())
                        if cleaned:
                            matched_lines.append(f"{member.name}: {cleaned}")
                    if len(matched_lines) >= 40:
                        break
                if len(matched_lines) >= 40:
                    break
    except Exception as exc:  # noqa: BLE001
        notes.append(f"Could not parse router bundle: {exc}")
        return [], notes

    if not matched_lines:
        notes.append("No obvious WAN/DNS/disconnect keywords found in first-pass scan.")
    return matched_lines, notes


def inspect_router_bundle(bundle: Path, output: Optional[Path], max_matches: int) -> int:
    """Standalone router bundle inspection (independent of network probe logs)."""
    matches, notes = _scan_router_bundle(bundle)
    lines = [
        f"Router bundle inspection: {bundle}",
        f"Generated: {iso_now()}",
        f"Matches found: {len(matches)}",
        "",
    ]
    if notes:
        lines.append("Notes:")
        lines.extend(f"- {n}" for n in notes)
        lines.append("")
    if matches:
        lines.append(f"Top suspicious lines (max {max_matches}):")
        for m in matches[:max_matches]:
            lines.append(f"- {m}")
    else:
        lines.append("No suspicious lines found with current keyword scanner.")

    report_text = "\n".join(lines) + "\n"
    if output is None:
        print(report_text)
    else:
        ensure_parent(output)
        output.write_text(report_text, encoding="utf-8")
        print(f"Wrote router bundle report to {output}")
    return 0


def html_report(csv_path: Path, output_path: Path, since_hours: int, router_bundle: Optional[Path] = None) -> None:
    if not csv_path.exists():
        raise FileNotFoundError(f"No log file: {csv_path}")

    cutoff = time.time() - since_hours * 3600
    rows = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ts = datetime.fromisoformat(r["timestamp"]).timestamp()
            if ts >= cutoff:
                rows.append(r)

    # Build per-timestamp snapshots for automated incident correlation.
    snapshots: dict[str, list[dict]] = {}
    for r in rows:
        snapshots.setdefault(r["timestamp"], []).append(r)

    by_target: dict[str, list[dict]] = {}
    for r in rows:
        by_target.setdefault(r["target"], []).append(r)

    summary_rows = []
    for target, items in sorted(by_target.items()):
        total = len(items)
        ok_count = sum(1 for x in items if str(x["success"]).lower() == "true")
        lat = [float(x["latency_ms"]) for x in items if x["latency_ms"] not in ("", "None", None)]
        p95 = round(sorted(lat)[int(len(lat) * 0.95) - 1], 2) if lat else None
        avg = round(statistics.mean(lat), 2) if lat else None
        success_pct = round((ok_count / total) * 100.0, 1)
        failures = total - ok_count
        if success_pct < 98.5 or (p95 is not None and p95 > 120):
            health = "Needs attention"
        elif success_pct < 99.5 or (p95 is not None and p95 > 80):
            health = "Watch"
        else:
            health = "Healthy"
        summary_rows.append(
            {
                "target": target,
                "target_label": target.replace("_", " "),
                "samples": total,
                "success": ok_count,
                "failures": failures,
                "success_pct": success_pct,
                "avg_ms": avg,
                "p95_ms": p95,
                "health": health,
            }
        )

    # Worst-first ordering makes the report easier to read quickly.
    summary_rows.sort(key=lambda r: (r["success_pct"], -(r["p95_ms"] or 0.0)))

    # Infer observed polling cadence from timestamps (best effort).
    cadence_seconds = None
    if rows:
        ts_values = sorted(
            {
                datetime.fromisoformat(r["timestamp"]).timestamp()
                for r in rows
                if r.get("timestamp")
            }
        )
        if len(ts_values) >= 2:
            deltas = [b - a for a, b in zip(ts_values, ts_values[1:]) if (b - a) > 0]
            if deltas:
                cadence_seconds = round(statistics.median(deltas), 2)

    avg_success = round(statistics.mean([r["success_pct"] for r in summary_rows]), 2) if summary_rows else None
    total_failures = sum(r["failures"] for r in summary_rows)

    def _is_private_ip_in_target(target: str) -> bool:
        for token in target.replace("-", "_").split("_"):
            candidate = token.replace("-", ".")
            try:
                if ipaddress.ip_address(candidate).is_private:
                    return True
            except ValueError:
                continue
        return False

    def _group(rows_: list[dict], predicate) -> list[dict]:
        return [r for r in rows_ if predicate(r)]

    def _mean(items: list[dict], field: str) -> Optional[float]:
        values = [float(i[field]) for i in items if i.get(field) is not None]
        return round(statistics.mean(values), 2) if values else None

    dns_rows = _group(summary_rows, lambda r: str(r["target"]).startswith("dns_"))
    local_dns_rows = _group(dns_rows, lambda r: _is_private_ip_in_target(str(r["target"])))
    public_dns_rows = _group(dns_rows, lambda r: not _is_private_ip_in_target(str(r["target"])))
    internet_rows = _group(summary_rows, lambda r: "internet_" in str(r["target"]))
    lan_rows = _group(
        summary_rows,
        lambda r: ("router" in str(r["target"])) or ("ha_" in str(r["target"])) or ("adguard" in str(r["target"])),
    )

    diagnosis: list[str] = []
    next_steps: list[str] = []

    local_dns_success = _mean(local_dns_rows, "success_pct")
    public_dns_success = _mean(public_dns_rows, "success_pct")
    local_dns_p95 = _mean(local_dns_rows, "p95_ms")
    public_dns_p95 = _mean(public_dns_rows, "p95_ms")
    internet_success = _mean(internet_rows, "success_pct")
    lan_success = _mean(lan_rows, "success_pct")
    internet_p95 = _mean(internet_rows, "p95_ms")
    lan_p95 = _mean(lan_rows, "p95_ms")

    if local_dns_success is not None and public_dns_success is not None:
        if (public_dns_success - local_dns_success) >= 0.8:
            diagnosis.append(
                f"Local DNS path looks less reliable than public DNS ({local_dns_success}% vs {public_dns_success}% success)."
            )
            next_steps.append(
                "Inspect AdGuard/HA CPU, memory, and DNS upstream settings; check whether packet loss exists between clients and the DNS host."
            )
        elif (local_dns_success - public_dns_success) >= 0.8:
            diagnosis.append(
                f"Public DNS path looks less reliable than local DNS ({public_dns_success}% vs {local_dns_success}% success), suggesting WAN/upstream DNS instability."
            )
            next_steps.append("Check ISP path quality and test alternate upstream resolvers in AdGuard.")

    if local_dns_p95 is not None and public_dns_p95 is not None:
        if local_dns_p95 > (public_dns_p95 * 1.5):
            diagnosis.append(
                f"Local DNS latency spikes are higher than public DNS (P95 {local_dns_p95}ms vs {public_dns_p95}ms)."
            )
            next_steps.append("Review AdGuard host load and query logs during spike windows.")

    if internet_success is not None and lan_success is not None and internet_success < (lan_success - 0.5):
        diagnosis.append(
            f"WAN/ISP path likely contributes to drops (internet success {internet_success}% vs LAN-related {lan_success}%)."
        )
        next_steps.append("Capture modem signal/event logs and compare timestamps with monitor failures.")

    if internet_p95 is not None and lan_p95 is not None and internet_p95 > (lan_p95 * 1.4):
        diagnosis.append(
            f"WAN jitter appears higher than LAN jitter (internet P95 {internet_p95}ms vs LAN P95 {lan_p95}ms)."
        )
        next_steps.append("Look for ISP congestion windows and bufferbloat under upload/download load.")

    worst = summary_rows[0] if summary_rows else None
    if worst is not None and worst["success_pct"] < 99.0:
        diagnosis.append(
            f"Most problematic target in this window: '{worst['target_label']}' ({worst['success_pct']}% success, P95 {worst['p95_ms']}ms)."
        )

    if not diagnosis:
        diagnosis.append(
            "No single dominant root cause stood out in this window; failures/latency are relatively distributed across targets."
        )
        next_steps.append("Run longer (24-72h) and correlate failures to exact time windows, then compare with ISP/router logs.")

    incident_rows = []
    for ts, items in sorted(snapshots.items()):
        total = len(items)
        failures = [x for x in items if str(x.get("success", "")).lower() != "true"]
        fail_rate = (len(failures) / total) * 100.0 if total else 0.0
        lat_vals = [
            float(x["latency_ms"])
            for x in items
            if x.get("latency_ms") not in ("", "None", None)
        ]
        median_latency = statistics.median(lat_vals) if lat_vals else None
        if fail_rate >= 20.0 or (median_latency is not None and median_latency >= 80.0):
            by_domain: dict[str, int] = {}
            for f in failures:
                d = _target_domain(str(f.get("target", "")))
                by_domain[d] = by_domain.get(d, 0) + 1
            dominant = max(by_domain.items(), key=lambda kv: kv[1])[0] if by_domain else "latency_spike"
            if dominant == "local_dns":
                hint = "Likely local DNS/AdGuard path issue during this window."
            elif dominant == "wan":
                hint = "Likely WAN/ISP path issue during this window."
            elif dominant in ("router_lan", "ha_adguard_host"):
                hint = "Likely LAN or local host segment issue during this window."
            else:
                hint = "Mixed/unclear failure pattern."
            incident_rows.append(
                {
                    "timestamp": ts,
                    "fail_rate": round(fail_rate, 1),
                    "median_latency": round(median_latency, 2) if median_latency is not None else None,
                    "dominant": dominant,
                    "hint": hint,
                }
            )

    router_lines: list[str] = []
    router_notes: list[str] = []
    if router_bundle is not None:
        router_lines, router_notes = _scan_router_bundle(router_bundle)

    html = [
        "<html><head><meta charset='utf-8'><title>Network Report</title>",
        (
            "<style>"
            "body{font-family:Arial;margin:20px;}"
            "table{border-collapse:collapse;}"
            "th,td{border:1px solid #ccc;padding:6px;}"
            "th{background:#eee;}"
            ".card{border:1px solid #ddd;background:#fafafa;padding:10px;margin:10px 0;}"
            ".healthy{background:#eef9f0;}"
            ".watch{background:#fff8e8;}"
            ".needs-attention{background:#ffecec;}"
            "</style>"
        ),
        "</head><body>",
        f"<h1>Network monitor report (last {since_hours}h)</h1>",
        f"<p>Generated: {iso_now()}</p>",
        "<div class='card'>"
        f"<strong>Quick summary:</strong> Targets={len(summary_rows)} | "
        f"Total failures={total_failures} | "
        f"Average success across targets={avg_success}%"
        "</div>",
    ]
    if cadence_seconds is not None:
        html.append(
            "<div class='card'>"
            f"<strong>Observed polling cadence:</strong> about every {cadence_seconds} seconds."
            " Outages shorter than this can be missed between checks."
            "</div>"
        )
    html.append("<div class='card'><h3>Plain-English diagnosis</h3><ul>")
    for d in diagnosis:
        html.append(f"<li>{d}</li>")
    html.append("</ul><h4>Suggested next checks</h4><ul>")
    for step in next_steps:
        html.append(f"<li>{step}</li>")
    html.append("</ul></div>")
    html.append("<div class='card'><h3>Automated correlation checklist</h3>")
    if incident_rows:
        html.append(
            "<p>Potential incident windows are listed below (triggered when per-snapshot failure rate >= 20% "
            "or median latency >= 80ms).</p>"
        )
        html.append(
            "<table><tr><th>Timestamp (UTC)</th><th>Fail rate %</th><th>Median latency ms</th><th>Dominant area</th><th>Hint</th></tr>"
        )
        for inc in incident_rows[:50]:
            html.append(
                "<tr><td>{timestamp}</td><td>{fail_rate}</td><td>{median_latency}</td><td>{dominant}</td><td>{hint}</td></tr>".format(
                    **inc
                )
            )
        html.append("</table>")
    else:
        html.append("<p>No high-severity incident windows were detected using current thresholds.</p>")

    if router_bundle is not None:
        html.append("<h4>Router bundle scan (best effort)</h4>")
        html.append(f"<p>Bundle: <code>{router_bundle}</code></p>")
        if router_notes:
            html.append("<ul>")
            for note in router_notes:
                html.append(f"<li>{note}</li>")
            html.append("</ul>")
        if router_lines:
            html.append("<p>Suspicious keyword matches (first 40):</p><ul>")
            for line in router_lines[:40]:
                html.append(f"<li><code>{line}</code></li>")
            html.append("</ul>")
    html.append("</div>")
    html.append(
        "<table><tr><th>Health</th><th>Target</th><th>Samples</th><th>Success</th><th>Failures</th><th>Success %</th><th>Avg ms</th><th>P95 ms</th></tr>"
    )
    for row in summary_rows:
        row_class = row["health"].lower().replace(" ", "-")
        html.append(
            "<tr class='{row_class}'><td>{health}</td><td>{target}</td><td>{samples}</td><td>{success}</td>"
            "<td>{failures}</td><td>{success_pct}</td><td>{avg_ms}</td><td>{p95_ms}</td></tr>".format(
                row_class=row_class,
                health=row["health"],
                target=row["target_label"],
                samples=row["samples"],
                success=row["success"],
                failures=row["failures"],
                success_pct=row["success_pct"],
                avg_ms=row["avg_ms"],
                p95_ms=row["p95_ms"],
            )
        )
    html.append("</table></body></html>")

    ensure_parent(output_path)
    output_path.write_text("\n".join(html), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor local/home network health.")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run continuous monitoring")
    run_p.add_argument("--config", default="config.json", type=Path)
    run_p.add_argument("--csv", default="logs/network_log.csv", type=Path)
    run_p.add_argument("--jsonl", default="logs/network_log.jsonl", type=Path)
    run_p.add_argument("--loops", type=int, default=None, help="Number of loops for testing; default endless")

    rep_p = sub.add_parser("report", help="Generate HTML summary report")
    rep_p.add_argument("--csv", default="logs/network_log.csv", type=Path)
    rep_p.add_argument("--output", default="logs/network_report.html", type=Path)
    rep_p.add_argument("--since-hours", type=int, default=24)
    rep_p.add_argument("--router-bundle", type=Path, default=None, help="Optional router tar/tar.gz log bundle")

    rb_p = sub.add_parser("inspect-router-bundle", help="Inspect router tar/tar.gz logs standalone")
    rb_p.add_argument("--bundle", type=Path, required=True, help="Path to router tar/tar.gz bundle")
    rb_p.add_argument("--output", type=Path, default=None, help="Optional text report output path")
    rb_p.add_argument("--max-matches", type=int, default=80, help="Max suspicious lines to include")

    cfg_p = sub.add_parser("init-config", help="Write a starter config file")
    cfg_p.add_argument("--output", default="config.json", type=Path)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "init-config":
        if args.output.exists():
            print(f"Config already exists: {args.output}")
            return 1
        ensure_parent(args.output)
        args.output.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        print(f"Wrote {args.output}")
        return 0

    if args.command == "run":
        cfg = load_config(args.config)
        run_monitor(cfg, args.csv, args.jsonl, args.loops)
        return 0

    if args.command == "report":
        html_report(args.csv, args.output, args.since_hours, args.router_bundle)
        print(f"Wrote report to {args.output}")
        return 0

    if args.command == "inspect-router-bundle":
        return inspect_router_bundle(args.bundle, args.output, args.max_matches)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
