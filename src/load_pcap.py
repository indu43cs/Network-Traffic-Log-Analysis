from pathlib import Path
import sys

from scapy.all import IP, TCP, UDP, rdpcap


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    return "OTHER"


def get_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return None, None


def print_packet_info(pcap_path):
    packets = rdpcap(str(pcap_path))

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print("-" * 80)

    for packet_number, packet in enumerate(packets, start=1):
        if not packet.haslayer(IP):
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = get_protocol_name(packet)
        source_port, destination_port = get_ports(packet)

        print(
            f"Packet {packet_number}: "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} "
            f"Protocol={protocol}"
        )


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/load_pcap.py captures/your_file.pcap")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    print_packet_info(pcap_path)


if __name__ == "__main__":
    main()
