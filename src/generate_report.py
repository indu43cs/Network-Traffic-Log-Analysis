from pathlib import Path
import sys

import pandas as pd
from scapy.all import rdpcap

from detect_dns_anomalies import (
    collect_dns_queries,
    find_high_frequency_sources,
    find_random_looking_domains,
)
from detect_exfiltration import collect_large_outbound_packets
from detect_port_scans import collect_connection_attempts, find_port_scans


REPORTS_FOLDER = Path("reports")


def build_finding_rows(port_scans, high_frequency_dns, random_domains, exfiltration):
    rows = []

    for finding in port_scans:
        rows.append(
            {
                "finding_type": "port_scan",
                "source_ip": finding["source_ip"],
                "destination": finding["destination_ip"],
                "details": f"{finding['port_count']} ports scanned",
            }
        )

    for finding in high_frequency_dns:
        rows.append(
            {
                "finding_type": "high_frequency_dns",
                "source_ip": finding["source_ip"],
                "destination": "DNS",
                "details": f"{finding['query_count']} DNS queries",
            }
        )

    for finding in random_domains:
        rows.append(
            {
                "finding_type": "random_looking_domain",
                "source_ip": finding["source_ip"],
                "destination": finding["domain"],
                "details": "Domain name looks random",
            }
        )

    for finding in exfiltration:
        rows.append(
            {
                "finding_type": "possible_exfiltration",
                "source_ip": finding["source_ip"],
                "destination": finding["destination_ip"],
                "details": f"{finding['packet_size']} byte outbound packet",
            }
        )

    return rows


def write_text_report(report_path, pcap_path, packet_count, rows):
    with report_path.open("w", encoding="utf-8") as report_file:
        report_file.write("Network Traffic Analysis Report\n")
        report_file.write("=" * 40 + "\n")
        report_file.write(f"PCAP file: {pcap_path}\n")
        report_file.write(f"Total packets loaded: {packet_count}\n")
        report_file.write(f"Total findings: {len(rows)}\n\n")

        if not rows:
            report_file.write("No suspicious activity found.\n")
            return

        for row in rows:
            report_file.write(f"Finding type: {row['finding_type']}\n")
            report_file.write(f"Source IP: {row['source_ip']}\n")
            report_file.write(f"Destination: {row['destination']}\n")
            report_file.write(f"Details: {row['details']}\n")
            report_file.write("-" * 40 + "\n")


def write_csv_report(report_path, rows):
    report_table = pd.DataFrame(
        rows,
        columns=["finding_type", "source_ip", "destination", "details"],
    )

    report_table.to_csv(report_path, index=False)


def analyze_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))

    connection_attempts = collect_connection_attempts(packets)
    port_scans = find_port_scans(connection_attempts)

    dns_queries = collect_dns_queries(packets)
    high_frequency_dns = find_high_frequency_sources(dns_queries)
    random_domains = find_random_looking_domains(dns_queries)

    exfiltration = collect_large_outbound_packets(packets)

    rows = build_finding_rows(
        port_scans,
        high_frequency_dns,
        random_domains,
        exfiltration,
    )

    return packets, rows


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/generate_report.py captures/your_file.pcap")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    REPORTS_FOLDER.mkdir(exist_ok=True)

    packets, rows = analyze_pcap(pcap_path)
    text_report_path = REPORTS_FOLDER / "analysis_report.txt"
    csv_report_path = REPORTS_FOLDER / "analysis_report.csv"

    write_text_report(text_report_path, pcap_path, len(packets), rows)
    write_csv_report(csv_report_path, rows)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print(f"Found {len(rows)} suspicious items.")
    print(f"Text report written to {text_report_path}")
    print(f"CSV report written to {csv_report_path}")


if __name__ == "__main__":
    main()
