from pathlib import Path
import sys

from scapy.all import rdpcap

PROJECT_ROOT = Path(__file__).parent
SRC_FOLDER = PROJECT_ROOT / "src"
sys.path.append(str(SRC_FOLDER))

from src.create_test_pcap import main as create_test_pcap
from src.detect_dns_anomalies import (
    collect_dns_queries,
    find_high_frequency_sources,
    find_random_looking_domains,
    print_findings as print_dns_findings,
)
from src.detect_exfiltration import (
    collect_large_outbound_packets,
    print_findings as print_exfiltration_findings,
)
from src.detect_port_scans import (
    collect_connection_attempts,
    find_port_scans,
    print_findings as print_port_scan_findings,
)
from src.generate_report import (
    REPORTS_FOLDER,
    analyze_pcap,
    write_csv_report,
    write_text_report,
)
from src.load_pcap import print_packet_info


DEFAULT_PCAP_PATH = Path("captures/test_suspicious.pcap")


def ask_for_pcap_path():
    typed_path = input(f"PCAP path [{DEFAULT_PCAP_PATH}]: ").strip()

    if typed_path == "":
        return DEFAULT_PCAP_PATH

    return Path(typed_path)


def load_packets_from_user_path():
    pcap_path = ask_for_pcap_path()

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return None, None

    packets = rdpcap(str(pcap_path))
    return pcap_path, packets


def show_packet_info():
    pcap_path = ask_for_pcap_path()

    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        return

    print_packet_info(pcap_path)


def run_port_scan_detection():
    pcap_path, packets = load_packets_from_user_path()

    if packets is None:
        return

    attempts = collect_connection_attempts(packets)
    findings = find_port_scans(attempts)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_port_scan_findings(findings)


def run_dns_detection():
    pcap_path, packets = load_packets_from_user_path()

    if packets is None:
        return

    dns_queries = collect_dns_queries(packets)
    high_frequency_findings = find_high_frequency_sources(dns_queries)
    random_domain_findings = find_random_looking_domains(dns_queries)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_dns_findings(dns_queries, high_frequency_findings, random_domain_findings)


def run_exfiltration_detection():
    pcap_path, packets = load_packets_from_user_path()

    if packets is None:
        return

    findings = collect_large_outbound_packets(packets)

    print(f"Loaded {len(packets)} packets from {pcap_path}")
    print_exfiltration_findings(findings)


def run_full_report():
    pcap_path = ask_for_pcap_path()

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


def show_menu():
    print()
    print("Network Traffic Log Analysis")
    print("=" * 32)
    print("1. Create test suspicious PCAP")
    print("2. Show basic packet info")
    print("3. Detect port scans")
    print("4. Detect abnormal DNS queries")
    print("5. Detect possible data exfiltration")
    print("6. Generate full TXT and CSV report")
    print("7. Exit")
    print()


def main():
    while True:
        show_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            create_test_pcap()
        elif choice == "2":
            show_packet_info()
        elif choice == "3":
            run_port_scan_detection()
        elif choice == "4":
            run_dns_detection()
        elif choice == "5":
            run_exfiltration_detection()
        elif choice == "6":
            run_full_report()
        elif choice == "7":
            print("Goodbye.")
            break
        else:
            print("Please choose a number from 1 to 7.")


if __name__ == "__main__":
    main()
