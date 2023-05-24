import os
from scapy.layers.inet import Ether
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.all import sniff


class Sniffer:
    def __init__(self, interface):
        self.interface = interface
        self.running = False

    def setup_sniffer(self):
        pass  # Нет необходимости в настройке сниффера с использованием Scapy

    def start_sniffing(self):
        self.running = True
        sniff(prn=self._handle_packet, iface=self.interface)

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

                # Вывод информации о пакете в терминал
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

                # Дополнительная обработка пакета
                # Сохранение пакета в файл для последующего анализа в папку reports
                self.save_packet(packet)

        except Exception as e:
            print(f"Error handling packet: {e}")

    @staticmethod
    def save_packet(packet):
        # Проверяем наличие папки "reports", иначе создаем ее
        if not os.path.exists("reports"):
            os.makedirs("reports")

        # Генерируем имя файла для сохранения пакета (можно использовать, например, текущую дату и время)
        filename = os.path.join("reports", "packet.pcap")

        # Сохраняем пакет в файл
        with open(filename, "ab") as file:
            file.write(bytes(packet))

    def cleanup_sniffer(self):
        pass  # Нет необходимости в очистке сниффера с использованием Scapy