from collections import defaultdict
from pathlib import Path
import sys

from scapy.all import IP, TCP, UDP, rdpcap


TIME_WINDOW_SECONDS = 60
PORT_SCAN_THRESHOLD = 10


def get_destination_port(packet):
    if packet.haslayer(TCP):
        return packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].dport

    return None


def collect_connection_attempts(packets):
    attempts = defaultdict(list)

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        destination_port = get_destination_port(packet)

        if destination_port is None:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_time = float(packet.time)
        key = (source_ip, destination_ip)

        attempts[key].append((packet_time, destination_port))

    return attempts


def find_port_scans(attempts):
    findings = []

    for (source_ip, destination_ip), packets in attempts.items():
        sorted_packets = sorted(packets)

        for start_index, (start_time, _) in enumerate(sorted_packets):
            unique_ports = set()

            for packet_time, destination_port in sorted_packets[start_index:]:
                if packet_time - start_time > TIME_WINDOW_SECONDS:
                    break

                unique_ports.add(destination_port)

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                findings.append(
                    {
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "port_count": len(unique_ports),
                        "time_window_seconds": TIME_WINDOW_SECONDS,
                    }
                )
                break

    return findings


def print_findings(findings):
    if not findings:
        print("No port scan activity found.")
        return

    print("Possible port scan activity found:")
    print("-" * 80)

    for finding in findings:
        print(
            f"Source {finding['source_ip']} scanned "
            f"{finding['port_count']} ports on "
            f"{finding['destination_ip']} within "
            f"{finding['time_window_seconds']} seconds."
        )


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/detect_port_scans.py captures/your_file.pcap")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    packets = rdpcap(str(pcap_path))
    attempts = collect_connection_attempts(packets)
    findings = find_port_scans(attempts)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_findings(findings)


if __name__ == "__main__":
    main()
