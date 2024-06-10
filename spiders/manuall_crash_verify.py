import sys
import binascii
from scapy.all import *

def resend_packet(packet_hex, target_ip, target_port, ip_version=4, timeout=5):
    # Convert the hex string back to bytes
    packet_bytes = binascii.unhexlify(packet_hex)

    # Decode the packet
    if ip_version == 6:
        packet = IPv6(packet_bytes)
    else:
        packet = IP(packet_bytes)
    
    # Send the packet
    print(f"Sending packet to {target_ip}:{target_port}")
    response = sr1(packet, timeout=timeout, verbose=False)

    if response:
        response.show()
        print("Packet sent successfully and response received.")
    else:
        print("Packet sent but no response received.")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python resend_packet.py <packet_hex> <target_ip> <target_port> <ip_version>")
        sys.exit(1)

    packet_hex = sys.argv[1]
    target_ip = sys.argv[2]
    target_port = int(sys.argv[3])
    ip_version = int(sys.argv[4])

    resend_packet(packet_hex, target_ip, target_port, ip_version)
