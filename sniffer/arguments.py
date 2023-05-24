import argparse
import psutil
import sys

def validate_interface(interface):
    interfaces = [iface.name for iface in psutil.net_if_stats().values() if iface.isup]
    if interface not in interfaces:
        error_msg = f"Interface '{interface}' does not exist or is not available."
        raise argparse.ArgumentTypeError(error_msg)
    return interface


def validate_mode(mode):
    valid_modes = ["capture", "analyze"]
    if mode not in valid_modes:
        error_msg = f"Invalid mode '{mode}'. Valid modes are: {', '.join(valid_modes)}"
        raise argparse.ArgumentTypeError(error_msg)
    return mode


def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Traffic Sniffer")
    parser.add_argument("-i", "--interface", metavar="INTERFACE", required=True, help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", metavar="FILTER", help="Filter for network traffic")
    parser.add_argument("-m", "--mode", metavar="MODE", choices=["capture", "analyze"], default="capture", help="Mode of operation (capture/analyze)")
    args = parser.parse_args()

    try:
        interface = validate_interface(args.interface)
        mode = validate_mode(args.mode)
    except argparse.ArgumentTypeError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

    return interface, args.filter, mode
