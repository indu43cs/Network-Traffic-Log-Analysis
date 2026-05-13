from collections import Counter
from pathlib import Path
import sys

from scapy.all import DNS, DNSQR, IP, rdpcap


HIGH_QUERY_THRESHOLD = 20
LONG_LABEL_LENGTH = 20
DIGIT_RATIO_THRESHOLD = 0.30


def clean_domain_name(raw_query_name):
    if isinstance(raw_query_name, bytes):
        raw_query_name = raw_query_name.decode(errors="ignore")

    return raw_query_name.rstrip(".").lower()


def get_first_domain_label(domain_name):
    return domain_name.split(".")[0]


def looks_random(domain_name):
    first_label = get_first_domain_label(domain_name)

    if len(first_label) >= LONG_LABEL_LENGTH:
        return True

    digit_count = sum(character.isdigit() for character in first_label)
    digit_ratio = digit_count / max(len(first_label), 1)

    if digit_ratio >= DIGIT_RATIO_THRESHOLD:
        return True

    return False


def collect_dns_queries(packets):
    dns_queries = []

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        if not packet.haslayer(DNSQR):
            continue

        query_name = clean_domain_name(packet[DNSQR].qname)

        dns_queries.append(
            {
                "source_ip": packet[IP].src,
                "domain": query_name,
                "time": float(packet.time),
            }
        )

    return dns_queries


def find_high_frequency_sources(dns_queries):
    source_counts = Counter(query["source_ip"] for query in dns_queries)
    findings = []

    for source_ip, query_count in source_counts.items():
        if query_count >= HIGH_QUERY_THRESHOLD:
            findings.append(
                {
                    "source_ip": source_ip,
                    "query_count": query_count,
                }
            )

    return findings


def find_random_looking_domains(dns_queries):
    findings = []

    for query in dns_queries:
        if looks_random(query["domain"]):
            findings.append(query)

    return findings


def print_findings(dns_queries, high_frequency_findings, random_domain_findings):
    print(f"Found {len(dns_queries)} DNS queries.")
    print()

    if high_frequency_findings:
        print("High-frequency DNS sources:")
        print("-" * 80)

        for finding in high_frequency_findings:
            print(
                f"{finding['source_ip']} made "
                f"{finding['query_count']} DNS queries."
            )
    else:
        print("No high-frequency DNS sources found.")

    print()

    if random_domain_findings:
        print("Random-looking DNS queries:")
        print("-" * 80)

        for finding in random_domain_findings:
            print(f"{finding['source_ip']} queried {finding['domain']}")
    else:
        print("No random-looking DNS queries found.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/detect_dns_anomalies.py captures/your_file.pcap")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    packets = rdpcap(str(pcap_path))
    dns_queries = collect_dns_queries(packets)
    high_frequency_findings = find_high_frequency_sources(dns_queries)
    random_domain_findings = find_random_looking_domains(dns_queries)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_findings(dns_queries, high_frequency_findings, random_domain_findings)


if __name__ == "__main__":
    main()
