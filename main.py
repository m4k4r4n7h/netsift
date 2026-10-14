import os
import sys
import json
import argparse
import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from parser import parse_capture
from heuristics import find_weird_traffic

console = Console()

def run_c_preloader(pcap_path):
    binary = "./fast_scan.exe" if os.name == "nt" else "./fast_scan"
    if not os.path.exists(binary):
        return None
    try:
        res = subprocess.run([binary, pcap_path], capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return None
        info = {}
        for line in res.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v
        return info
    except Exception:
        return None

def render_summary(pcap_path, c_stats, data, alerts, top_n):
    console.print(Panel.fit(f"[bold cyan]NetSift PCAP Analyzer[/bold cyan]\nTarget File: [yellow]{pcap_path}[/yellow]"))

    if c_stats:
        console.print(
            f"[dim]C Engine Quick-Scan:[/dim] v{c_stats.get('PCAP_VERSION')} | "
            f"Packets: [bold]{c_stats.get('TOTAL_PKTS')}[/bold] | "
            f"Bytes: [bold]{c_stats.get('TOTAL_BYTES')}[/bold] | "
            f"Duration: [bold]{c_stats.get('DURATION_SEC')}s[/bold] | "
            f"Avg Pkt: [bold]{c_stats.get('AVG_PKT_SIZE')} B[/bold]\n"
        )
    else:
        console.print(
            f"Total Packets Parsed: [bold]{data['total_packets']}[/bold] | "
            f"Total Bytes: [bold]{data['total_volume']}[/bold]\n"
        )

    proto_table = Table(title="Protocol Breakdown")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Packets", justify="right", style="green")
    proto_table.add_column("Share", justify="right", style="magenta")

    total_p = max(data["total_packets"], 1)
    for proto, count in data["protocols"].most_common(top_n):
        pct = (count / total_p) * 100
        proto_table.add_row(proto, str(count), f"{pct:.1f}%")
    console.print(proto_table)

    ip_table = Table(title=f"Top {top_n} Talkers (Source IPs)")
    ip_table.add_column("Source IP", style="yellow")
    ip_table.add_column("Packets Sent", justify="right", style="green")
    for ip, count in data["src_ips"].most_common(top_n):
        ip_table.add_row(ip, str(count))
    console.print(ip_table)

    conv_table = Table(title=f"Top {top_n} Conversations")
    conv_table.add_column("Flow", style="white")
    conv_table.add_column("Packets", justify="right", style="green")
    for flow, count in data["conversations"].most_common(top_n):
        conv_table.add_row(flow, str(count))
    console.print(conv_table)

    if data["dns_queries"]:
        dns_table = Table(title=f"Top {top_n} DNS Queries")
        dns_table.add_column("Queried Domain", style="blue")
        dns_table.add_column("Requests", justify="right", style="green")
        for dom, count in data["dns_queries"].most_common(top_n):
            dns_table.add_row(dom, str(count))
        console.print(dns_table)
    else:
        console.print("[dim]No DNS queries found in this capture.[/dim]\n")

    if alerts:
        alert_table = Table(title="Unusual Traffic Patterns Flagged")
        alert_table.add_column("Severity", style="bold")
        alert_table.add_column("Type", style="red")
        alert_table.add_column("Source / Indicator", style="yellow")
        alert_table.add_column("Details", style="white")

        for a in alerts:
            sev_color = "red" if a["severity"] == "HIGH" else ("yellow" if a["severity"] == "MEDIUM" else "cyan")
            alert_table.add_row(
                f"[{sev_color}]{a['severity']}[/{sev_color}]",
                a["type"],
                a["source"],
                a["detail"]
            )
        console.print(alert_table)
    else:
        console.print(Panel("[bold green]No obvious traffic anomalies triggered heuristics.[/bold green]"))

def export_json(out_path, pcap_path, c_stats, data, alerts):
    payload = {
        "file": pcap_path,
        "c_header_stats": c_stats,
        "total_packets": data["total_packets"],
        "total_bytes": data["total_volume"],
        "protocols": dict(data["protocols"].most_common()),
        "top_sources": dict(data["src_ips"].most_common(25)),
        "top_destinations": dict(data["dst_ips"].most_common(25)),
        "dns_queries": dict(data["dns_queries"].most_common(50)),
        "alerts": alerts
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    console.print(f"\n[bold green]Saved JSON report to {out_path}[/bold green]")

def main():
    argp = argparse.ArgumentParser(description="NetSift - Hybrid C/Python PCAP Summarizer")
    argp.add_argument("pcap", help="Path to the .pcap file")
    argp.add_argument("-t", "--top", type=int, default=10, help="Number of top rows to display")
    argp.add_argument("-o", "--out", help="Export results to a JSON file")
    args = argp.parse_args()

    if not os.path.isfile(args.pcap):
        console.print(f"[bold red]Error:[/bold red] File '{args.pcap}' does not exist.")
        sys.exit(1)

    c_stats = run_c_preloader(args.pcap)
    data = parse_capture(args.pcap)
    alerts = find_weird_traffic(data)

    render_summary(args.pcap, c_stats, data, alerts, args.top)

    if args.out:
        export_json(args.out, args.pcap, c_stats, data, alerts)

if __name__ == "__main__":
    main()
