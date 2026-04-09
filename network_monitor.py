#!/usr/bin/env python3
"""Lightweight local network monitor for home labs.

Collects latency / DNS / TCP-connect metrics and writes CSV + JSONL logs.
Can also generate a quick HTML report from collected CSV data.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import time
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


def html_report(csv_path: Path, output_path: Path, since_hours: int) -> None:
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
        summary_rows.append((target, total, ok_count, round((ok_count / total) * 100.0, 1), avg, p95))

    html = [
        "<html><head><meta charset='utf-8'><title>Network Report</title>",
        "<style>body{font-family:Arial;margin:20px;}table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:6px;}th{background:#eee;}</style>",
        "</head><body>",
        f"<h1>Network monitor report (last {since_hours}h)</h1>",
        f"<p>Generated: {iso_now()}</p>",
        "<table><tr><th>Target</th><th>Samples</th><th>Success</th><th>Success %</th><th>Avg ms</th><th>P95 ms</th></tr>",
    ]
    for row in summary_rows:
        html.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
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
        html_report(args.csv, args.output, args.since_hours)
        print(f"Wrote report to {args.output}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
