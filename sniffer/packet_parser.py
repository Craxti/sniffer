import struct
import socket


def parse_ethernet_header(data):
    try:
        ethernet_header = struct.unpack("!6s6sH", data[:14])
        destination_mac = format_mac_address(ethernet_header[0])
        source_mac = format_mac_address(ethernet_header[1])
        ethernet_type = ethernet_header[2]
        return destination_mac, source_mac, ethernet_type
    except struct.error as e:
        raise ValueError("Error parsing Ethernet header: {}".format(e))


def format_mac_address(mac):
    formatted_mac = ":".join("{:02x}".format(byte) for byte in mac)
    return formatted_mac


def parse_ip_header(data):
    try:
        ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        source_ip = socket.inet_ntoa(ip_header[8])
        destination_ip = socket.inet_ntoa(ip_header[9])
        return version, header_length, ttl, protocol, source_ip, destination_ip
    except struct.error as e:
        raise ValueError("Error parsing IP header: {}".format(e))


def parse_tcp_header(data):
    try:
        tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
        source_port = tcp_header[0]
        destination_port = tcp_header[1]
        sequence_number = tcp_header[2]
        acknowledgement_number = tcp_header[3]
        data_offset = (tcp_header[4] >> 4) * 4
        flags = tcp_header[5]
        window = tcp_header[6]
        checksum = tcp_header[7]
        urgent_pointer = tcp_header[8]
        return source_port, destination_port, sequence_number, acknowledgement_number, data_offset, flags, window, checksum, urgent_pointer
    except struct.error as e:
        raise ValueError("Error parsing TCP header: {}".format(e))


def parse_udp_header(data):
    try:
        udp_header = struct.unpack("!HHHH", data[:8])
        source_port = udp_header[0]
        destination_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]
        return source_port, destination_port, length, checksum
    except struct.error as e:
        raise ValueError("Error parsing UDP header: {}".format(e))


def parse_icmp_header(data):
    try:
        icmp_header = struct.unpack("!BBH", data[:4])
        icmp_type = icmp_header[0]
        icmp_code = icmp_header[1]
        checksum = icmp_header[2]
        return icmp_type, icmp_code, checksum
    except struct.error as e:
        raise ValueError("Error parsing ICMP header: {}".format(e))


def parse_dns_header(data):
    try:
        dns_header = struct.unpack("!HHHHHH", data[:12])
        transaction_id = dns_header[0]
        flags = dns_header[1]
        question_count = dns_header[2]
        answer_count = dns_header[3]
        authority_count = dns_header[4]
        additional_count = dns_header[5]
        return transaction_id, flags, question_count, answer_count, authority_count, additional_count
    except struct.error as e:
        raise ValueError("Error parsing DNS header: {}".format(e))


def extract_flags(tcp_flags):
    flags = {
        "FIN": bool(tcp_flags & 0x01),
        "SYN": bool(tcp_flags & 0x02),
        "RST": bool(tcp_flags & 0x04),
        "PSH": bool(tcp_flags & 0x08),
        "ACK": bool(tcp_flags & 0x10),
        "URG": bool(tcp_flags & 0x20),
        # Добавьте другие флаги, если необходимо
    }
    return flags
