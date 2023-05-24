from sniffer.arguments import parse_arguments
from sniffer.sniffer import Sniffer
from sniffer.packet_parser import parse_ethernet_header, parse_ip_header
from sniffer.network_analyzer import analyze_packet


def main():
    args = parse_arguments()
    sniffer = Sniffer(args.interface)

    try:
        sniffer.setup_sniffer()
        sniffer.start_sniffing()
        input("Press Enter to stop sniffing...")
    except KeyboardInterrupt:
        print("Sniffing interrupted.")
    finally:
        sniffer.stop_sniffing()
        sniffer.cleanup_sniffer()


if __name__ == "__main__":
    main()
