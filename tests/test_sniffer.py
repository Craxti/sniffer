import os
import unittest
from scapy.layers.inet import Ether
from scapy.layers.inet import TCP, IP
from sniffer.sniffer import Sniffer
from scapy.sendrecv import sendp
from scapy.all import rdpcap
import time


class SnifferTestCase(unittest.TestCase):
    def setUp(self):
        self.test_interface = "Ethernet"  # Replace with your interface

    def test_packet_sniffing(self):
        # Создание сниффера
        sniffer = Sniffer(self.test_interface)

        # Запуск сниффинга в отдельном потоке
        sniffer.start_sniffing()

        # Отправка тестового пакета для сниффинга
        test_packet = Ether() / IP(dst="8.8.8.8") / TCP(dport=80)
        sendp(test_packet, iface=self.test_interface, verbose=False)

        # Ожидание сниффинга пакета в течение 2 секунд
        time.sleep(2)

        # Остановка сниффинга
        sniffer.stop_sniffing()

        # Проверка результатов сниффинга
        captured_packets = self.read_captured_packets()
        self.assertTrue(len(captured_packets) > 0, "No packets were captured")
        self.assertIn(test_packet, captured_packets, "Test packet was not captured")

    @staticmethod
    def read_captured_packets():
        packets = []
        pcap_file = "reports/packet.pcap"
        if os.path.isfile(pcap_file):
            packets = rdpcap(pcap_file)
        return packets


if __name__ == "__main__":
    unittest.main()
