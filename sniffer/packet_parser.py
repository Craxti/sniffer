import struct
import socket


class PacketParser:
    def parse_ethernet_header(self, data):
        try:
            if len(data) >= 14:
                ethernet_header = struct.unpack("!6s6sH", data[:14])
                destination_mac = self.format_mac_address(ethernet_header[0])
                source_mac = self.format_mac_address(ethernet_header[1])
                ethernet_type = ethernet_header[2]
                return destination_mac, source_mac, ethernet_type
        except struct.error as e:
            raise ValueError("Error parsing Ethernet header: {}".format(e))
        raise ValueError("Incomplete Ethernet header data.")

    def format_mac_address(self, mac):
        formatted_mac = ":".join("{:02x}".format(byte) for byte in mac)
        return formatted_mac

    def parse_ip_header(self, data):
        try:
            if len(data) >= 20:
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
        raise ValueError("Incomplete IP header data.")

    def parse_tcp_header(self, data):
        try:
            if len(data) >= 20:
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
        raise ValueError("Incomplete TCP header data.")

    def parse_udp_header(self, data):
        try:
            if len(data) >= 8:
                udp_header = struct.unpack("!HHHH", data[:8])
                source_port = udp_header[0]
                destination_port = udp_header[1]
                length = udp_header[2]
                checksum = udp_header[3]
                return source_port, destination_port, length, checksum
        except struct.error as e:
            raise ValueError("Error parsing UDP header: {}".format(e))
        raise ValueError("Incomplete UDP header data.")

    def parse_icmp_header(self, data):
        try:
            if len(data) >= 4:
                icmp_header = struct.unpack("!BBH", data[:4])
                icmp_type = icmp_header[0]
                icmp_code = icmp_header[1]
                checksum = icmp_header[2]
                return icmp_type, icmp_code, checksum
        except struct.error as e:
            raise ValueError("Error parsing ICMP header: {}".format(e))
        raise ValueError("Incomplete ICMP header data.")

    def parse_dns_header(self, data):
        try:
            if len(data) >= 12:
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
        raise ValueError("Incomplete DNS header data.")

    def parse_ipv6_header(self, data):
        try:
            if len(data) >= 40:
                ipv6_header = struct.unpack("!IHBB16s16s", data[:40])
                version = ipv6_header[0] >> 4
                traffic_class = (ipv6_header[0] & 0x0F) << 4 | (ipv6_header[1] >> 4)
                flow_label = (ipv6_header[1] & 0x0F) << 16 | (ipv6_header[2] << 8) | ipv6_header[3]
                payload_length = ipv6_header[4]
                next_header = ipv6_header[5]
                source_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[6])
                destination_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[7])
                return version, traffic_class, flow_label, payload_length, next_header, source_ip, destination_ip
        except struct.error as e:
            raise ValueError("Error parsing IPv6 header: {}".format(e))
        raise ValueError("Incomplete IPv6 header data.")

    def parse_icmpv6_header(self, data):
        try:
            if len(data) >= 8:
                icmpv6_header = struct.unpack("!BBH", data[:8])
                icmpv6_type = icmpv6_header[0]
                icmpv6_code = icmpv6_header[1]
                checksum = icmpv6_header[2]
                return icmpv6_type, icmpv6_code, checksum
        except struct.error as e:
            raise ValueError("Error parsing ICMPv6 header: {}".format(e))
        raise ValueError("Incomplete ICMPv6 header data.")

    def parse_packet(self, data):
        ethernet_header = self.parse_ethernet_header(data)
        ethernet_type = ethernet_header[2]

        if ethernet_type == 0x0800:  # IPv4
            ip_header = self.parse_ip_header(data[14:])
            protocol = ip_header[3]

            if protocol == 6:  # TCP
                return self.parse_tcp_header(data[14 + ip_header[1]:])

            elif protocol == 17:  # UDP
                return self.parse_udp_header(data[14 + ip_header[1]:])

            elif protocol == 1:  # ICMP
                return self.parse_icmp_header(data[14 + ip_header[1]:])

        elif ethernet_type == 0x86DD:  # IPv6
            ipv6_header = self.parse_ipv6_header(data[14:])
            next_header = ipv6_header[4]

            if next_header == 6:  # TCP
                return self.parse_tcp_header(data[54:])

            elif next_header == 17:  # UDP
                return self.parse_udp_header(data[54:])

            elif next_header == 58:  # ICMPv6
                return self.parse_icmpv6_header(data[54:])

        raise ValueError("Unsupported protocol or incomplete data.")


class PacketFilter:
    def filter_packets(self, packets, protocol=None, source_ip=None, destination_ip=None, source_port=None, destination_port=None):
        filtered_packets = []
        for packet in packets:
            if protocol is not None and packet['protocol'] != protocol:
                continue
            if source_ip is not None and packet['source_ip'] != source_ip:
                continue
            if destination_ip is not None and packet['destination_ip'] != destination_ip:
                continue
            if source_port is not None and packet['source_port'] != source_port:
                continue
            if destination_port is not None and packet['destination_port'] != destination_port:
                continue
            filtered_packets.append(packet)
        return filtered_packets
