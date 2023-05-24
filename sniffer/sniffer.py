import os
import json
import xml.etree.ElementTree as ET
from scapy.layers.inet import Ether
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.all import sniff


class Sniffer:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.captured_packets = None

    def setup_sniffer(self):
        pass  # No need for setup with Scapy

    def start_sniffing(self):
        self.running = True
        captured_packets = sniff(prn=self._handle_packet, iface=self.interface)
        self.captured_packets = captured_packets

        for packet in captured_packets:
            self._handle_packet(packet)

    def stop_sniffing(self):
        self.running = False

    def _handle_packet(self, packet):
        try:
            if Ether in packet and IP in packet:
                destination_mac = packet[Ether].dst
                source_mac = packet[Ether].src
                ethernet_type = packet[Ether].type

                version = packet[IP].version
                header_length = packet[IP].ihl
                ttl = packet[IP].ttl
                protocol = packet[IP].proto
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst

                source_port = None
                destination_port = None
                flags = None
                icmp_type = None
                icmp_code = None

                if protocol == 6 and TCP in packet:
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                    flags = packet[TCP].flags
                elif protocol == 17 and UDP in packet:
                    source_port = packet[UDP].sport
                    destination_port = packet[UDP].dport
                elif protocol == 1 and ICMP in packet:
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code

                # Output packet information to the terminal
                print("Ethernet Header:")
                print(f"Destination MAC: {destination_mac}")
                print(f"Source MAC: {source_mac}")
                print(f"Ethernet Type: {ethernet_type}")

                print("IP Header:")
                print(f"Version: {version}")
                print(f"Header Length: {header_length}")
                print(f"TTL: {ttl}")
                print(f"Protocol: {protocol}")
                print(f"Source IP: {source_ip}")
                print(f"Destination IP: {destination_ip}")

                if protocol == 6 and TCP in packet:
                    print("TCP Header:")
                    print(f"Source Port: {source_port}")
                    print(f"Destination Port: {destination_port}")
                    print(f"Flags: {flags}")

                elif protocol == 17 and UDP in packet:
                    print("UDP Header:")
                    print(f"Source Port: {source_port}")
                    print(f"Destination Port: {destination_port}")

                elif protocol == 1 and ICMP in packet:
                    print("ICMP Header:")
                    print(f"Type: {icmp_type}")
                    print(f"Code: {icmp_code}")

                # Additional packet processing
                # Save the packet to files in different formats
                self.save_packet_as_pcap(packet)
                self.save_packet_as_json(packet)
                self.save_packet_as_xml(packet)

        except Exception as e:
            print(f"Error handling packet: {e}")

    @staticmethod
    def save_packet_as_pcap(packet):
        try:
            # Check if the "reports" folder exists, otherwise create it
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # Generate a file name to save the packet as pcap
            filename = os.path.join("reports", "packet.pcap")

            # Save the packet to the file
            with open(filename, "ab") as file:
                file.write(bytes(packet))

        except Exception as e:
            print(f"Error saving packet as pcap: {e}")

    @staticmethod
    def save_packet_as_json(packet):
        try:
            # Check if the "reports" folder exists, otherwise create it
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # Generate a file name to save the packet as json
            filename = os.path.join("reports", "packet.json")

            # Convert the packet to a dictionary
            packet_dict = {
                "ethernet_header": {
                    "destination_mac": packet[Ether].dst,
                    "source_mac": packet[Ether].src,
                    "ethernet_type": packet[Ether].type
                },
                "ip_header": {
                    "version": packet[IP].version,
                    "header_length": packet[IP].ihl,
                    "ttl": packet[IP].ttl,
                    "protocol": packet[IP].proto,
                    "source_ip": packet[IP].src,
                    "destination_ip": packet[IP].dst
                },
                "tcp_header": {
                    "source_port": packet[TCP].sport if TCP in packet else None,
                    "destination_port": packet[TCP].dport if TCP in packet else None,
                    "flags": packet[TCP].flags if TCP in packet else None
                },
                "udp_header": {
                    "source_port": packet[UDP].sport if UDP in packet else None,
                    "destination_port": packet[UDP].dport if UDP in packet else None
                },
                "icmp_header": {
                    "type": packet[ICMP].type if ICMP in packet else None,
                    "code": packet[ICMP].code if ICMP in packet else None
                }
            }

            # Save the packet dictionary as json
            with open(filename, "a") as file:
                json.dump(packet_dict, file)
                file.write("\n")

        except Exception as e:
            print(f"Error saving packet as json: {e}")

    @staticmethod
    def save_packet_as_xml(packet):
        try:
            # Check if the "reports" folder exists, otherwise create it
            if not os.path.exists("reports"):
                os.makedirs("reports")

            # Generate a file name to save the packet as xml
            filename = os.path.join("reports", "packet.xml")

            # Create the root element for the XML tree
            root = ET.Element("packet")

            # Create sub-elements for the headers
            ethernet_header = ET.SubElement(root, "ethernet_header")
            ip_header = ET.SubElement(root, "ip_header")
            tcp_header = ET.SubElement(root, "tcp_header")
            udp_header = ET.SubElement(root, "udp_header")
            icmp_header = ET.SubElement(root, "icmp_header")

            # Set values for the sub-elements
            ethernet_header.set("destination_mac", packet[Ether].dst)
            ethernet_header.set("source_mac", packet[Ether].src)
            ethernet_header.set("ethernet_type", str(packet[Ether].type))

            ip_header.set("version", str(packet[IP].version))
            ip_header.set("header_length", str(packet[IP].ihl))
            ip_header.set("ttl", str(packet[IP].ttl))
            ip_header.set("protocol", str(packet[IP].proto))
            ip_header.set("source_ip", packet[IP].src)
            ip_header.set("destination_ip", packet[IP].dst)

            tcp_header.set("source_port", str(packet[TCP].sport) if TCP in packet else "")
            tcp_header.set("destination_port", str(packet[TCP].dport) if TCP in packet else "")
            tcp_header.set("flags", str(packet[TCP].flags) if TCP in packet else "")

            udp_header.set("source_port", str(packet[UDP].sport) if UDP in packet else "")
            udp_header.set("destination_port", str(packet[UDP].dport) if UDP in packet else "")

            icmp_header.set("type", str(packet[ICMP].type) if ICMP in packet else "")
            icmp_header.set("code", str(packet[ICMP].code) if ICMP in packet else "")

            # Create the XML tree and save it to the file
            tree = ET.ElementTree(root)
            tree.write(filename)

        except Exception as e:
            print(f"Error saving packet as xml: {e}")

    def cleanup_sniffer(self):
        pass  # No need for cleanup with Scapy

    def get_packet(self, index):
        if 0 <= index < len(self.captured_packets):
            return self.captured_packets[index]
        else:
            return None
