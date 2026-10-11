#!/usr/bin/env python3
"""
Network Scanner & Report
==========================
A network reconnaissance tool that uses Nmap to:
  - Discover live hosts on a network
  - Detect open ports and running services
  - Identify operating systems (best-effort)
  - Generate a professional HTML/JSON/CSV report

Author: batool jameel
License: MIT
"""

import os
import sys
import csv
import json
import argparse
import nmap
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def banner(text):
    """Print a section banner."""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def write_json(path, data):
    """Write data as pretty JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path, rows, fieldnames=None):
    """Write list of dicts to CSV."""
    if not rows:
        return
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


# --------------------------------------------------------------------
# Nmap Scanning Functions
# --------------------------------------------------------------------

def scan_hosts(target, arguments="-sn"):
    """
    Discover live hosts on a network.
    Default: ping scan (-sn) - no port scan.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=arguments)

    hosts = []
    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "N/A",
            "state": nm[host].state(),
            "mac": "N/A",
            "vendor": "N/A",
        }
        # MAC address if available (requires admin/root)
        if "addresses" in nm[host] and "mac" in nm[host]["addresses"]:
            host_data["mac"] = nm[host]["addresses"]["mac"]
            host_data["vendor"] = nm[host].get("vendor", {}).get(
                host_data["mac"], "N/A"
            )
        hosts.append(host_data)

    return hosts


def scan_ports(target, ports="1-1000", arguments="-sV"):
    """
    Scan open ports and services on target(s).
    Default: TCP SYN scan with version detection on ports 1-1000.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=ports, arguments=arguments)

    results = []
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        host_result = {
            "ip": host,
            "hostname": nm[host].hostname() or "N/A",
            "state": nm[host].state(),
            "os_match": "N/A",
            "ports": [],
        }

        # OS detection (only if -O was used)
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            host_result["os_match"] = nm[host]["osmatch"][0].get("name", "N/A")

        # Ports & services
        for proto in nm[host].all_protocols():
            ports_list = nm[host][proto].keys()
            for port in ports_list:
                port_info = nm[host][proto][port]
                host_result["ports"].append({
                    "protocol": proto,
                    "port": port,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                })

        results.append(host_result)

    return results


def build_summary(hosts, port_results):
    """Build a summary of the scan."""
    total_open = sum(
        1 for h in port_results
        for p in h["ports"] if p["state"] == "open"
    )
    return {
        "total_hosts_alive": len(hosts),
        "total_hosts_scanned": len(port_results),
        "total_open_ports": total_open,
    }


# --------------------------------------------------------------------
# Report Generation
# --------------------------------------------------------------------

def save_report(data, output_dir):
    """Save JSON, CSV, and HTML report."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    write_json(output_dir / "scan_results.json", data)

    # CSV: hosts
    if data["hosts"]:
        write_csv(output_dir / "hosts.csv", data["hosts"])

    # CSV: open ports (flatten)
    port_rows = []
    for host in data["port_scan"]:
        for p in host["ports"]:
            if p["state"] == "open":
                port_rows.append({
                    "ip": host["ip"],
                    "hostname": host["hostname"],
                    "protocol": p["protocol"],
                    "port": p["port"],
                    "service": p["service"],
                    "product": p["product"],
                    "version": p["version"],
                })

    if port_rows:
        write_csv(output_dir / "open_ports.csv", port_rows)

    # HTML
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    html_content = template.render(
        data=data,
        scanned_at=data["metadata"]["scanned_at"],
        target=data["metadata"]["target"],
        scan_type=data["metadata"]["scan_type"],
    )

    with open(output_dir / "report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_dir


# --------------------------------------------------------------------
# Entry Point
# --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner & Report - Nmap-based tool"
    )
    parser.add_argument(
        "target",
        help="Target to scan (IP, hostname, or CIDR like 192.168.1.0/24)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="Port range to scan (default: 1-1000)",
    )
    parser.add_argument(
        "-t", "--type",
        choices=["discovery", "full"],
        default="full",
        help="Scan type: 'discovery' (hosts only) or 'full' (hosts + ports)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output directory (default: output/scan_YYYYMMDD_HHMMSS)",
    )
    args = parser.parse_args()

    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"output/scan_{timestamp}"
    else:
        output_dir = args.output

    print("\n" + "=" * 60)
    print("  NETWORK SCANNER & REPORT")
    print("=" * 60)
    print(f"  Target: {args.target}")
    print(f"  Scan type: {args.type}")
    print(f"  Output: {output_dir}")
    print(f"  Started: {datetime.now().isoformat(timespec='seconds')}")

    data = {
        "metadata": {
            "target": args.target,
            "scan_type": args.type,
            "ports": args.ports,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        },
        "hosts": [],
        "port_scan": [],
        "summary": {},
    }

    # ----------------------------------------------------------------
    # Step 1: Host Discovery
    # ----------------------------------------------------------------
    banner("[1/3] Host Discovery")
    try:
        data["hosts"] = scan_hosts(args.target)
        print(f"  [+] Live hosts found: {len(data['hosts'])}")
        for h in data["hosts"]:
            print(f"      - {h['ip']} ({h['hostname']})")
    except Exception as e:
        print(f"  [!] Host discovery failed: {e}")
        sys.exit(1)

    if not data["hosts"]:
        print("\n[!] No live hosts found. Exiting.")
        sys.exit(0)

    # ----------------------------------------------------------------
    # Step 2: Port Scan (only if 'full')
    # ----------------------------------------------------------------
    if args.type == "full":
        banner("[2/3] Port & Service Scan")
        try:
            data["port_scan"] = scan_ports(args.target, args.ports)
            total_open = sum(
                len([p for p in h["ports"] if p["state"] == "open"])
                for h in data["port_scan"]
            )
            print(f"  [+] Hosts scanned: {len(data['port_scan'])}")
            print(f"  [+] Open ports found: {total_open}")
        except Exception as e:
            print(f"  [!] Port scan failed: {e}")
    else:
        banner("[2/3] Port Scan - SKIPPED (discovery mode)")

    # ----------------------------------------------------------------
    # Step 3: Generate Report
    # ----------------------------------------------------------------
    banner("[3/3] Generating Report")
    data["summary"] = build_summary(data["hosts"], data["port_scan"])
    out = save_report(data, output_dir)
    print(f"  [+] Report: {out}/report.html")
    print(f"  [+] JSON: {out}/scan_results.json")
    print(f"  [+] CSV files saved")

    banner("DONE")
    print(f"  Scan completed at {datetime.now().isoformat(timespec='seconds')}")
    print(f"  Open the report: {out}\\report.html\n")


if __name__ == "__main__":
    main()