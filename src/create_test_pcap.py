from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap


CAPTURES_FOLDER = Path("captures")
TEST_PCAP_PATH = CAPTURES_FOLDER / "test_suspicious.pcap"


def create_port_scan_packets():
    packets = []
    source_ip = "192.168.1.50"
    destination_ip = "10.0.0.20"

    for destination_port in range(20, 35):
        packet = IP(src=source_ip, dst=destination_ip) / TCP(
            sport=40000,
            dport=destination_port,
        )
        packets.append(packet)

    return packets


def create_dns_packets():
    packets = []
    source_ip = "192.168.1.60"
    dns_server_ip = "8.8.8.8"

    domain_names = [
        "example.com",
        "google.com",
        "a91xk283jd92ksl10293.example.com",
        "login9384759384.example.com",
    ]

    for domain_name in domain_names:
        packet = (
            IP(src=source_ip, dst=dns_server_ip)
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain_name))
        )
        packets.append(packet)

    return packets


def create_exfiltration_packet():
    large_payload = b"A" * 1200

    packet = (
        IP(src="192.168.1.70", dst="93.184.216.34")
        / TCP(sport=50000, dport=443)
        / Raw(load=large_payload)
    )

    return [packet]


def main():
    CAPTURES_FOLDER.mkdir(exist_ok=True)

    packets = []
    packets.extend(create_port_scan_packets())
    packets.extend(create_dns_packets())
    packets.extend(create_exfiltration_packet())

    wrpcap(str(TEST_PCAP_PATH), packets)

    print(f"Created {TEST_PCAP_PATH} with {len(packets)} packets.")


if __name__ == "__main__":
    main()
