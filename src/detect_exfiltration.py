from ipaddress import ip_address
from pathlib import Path
import sys

from scapy.all import IP, rdpcap


LARGE_PACKET_SIZE_BYTES = 1000


def is_private_ip(ip_text):
    return ip_address(ip_text).is_private


def collect_large_outbound_packets(packets):
    findings = []

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        if not is_private_ip(source_ip):
            continue

        if is_private_ip(destination_ip):
            continue

        if packet_size < LARGE_PACKET_SIZE_BYTES:
            continue

        findings.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "packet_size": packet_size,
                "time": float(packet.time),
            }
        )

    return findings


def print_findings(findings):
    if not findings:
        print("No possible data exfiltration found.")
        return

    print("Possible data exfiltration found:")
    print("-" * 80)

    for finding in findings:
        print(
            f"{finding['source_ip']} sent "
            f"{finding['packet_size']} bytes to external IP "
            f"{finding['destination_ip']}."
        )


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/detect_exfiltration.py captures/your_file.pcap")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    packets = rdpcap(str(pcap_path))
    findings = collect_large_outbound_packets(packets)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_findings(findings)


if __name__ == "__main__":
    main()
