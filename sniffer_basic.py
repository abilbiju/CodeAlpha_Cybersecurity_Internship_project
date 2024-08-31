
from scapy.all import *

def main():
    # Continuously capture and analyze packets
    sniff(prn=analyze_packet, store=0)

def analyze_packet(packet):
    if packet.haslayer(Ether):
        dest_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        eth_proto = packet[Ether].type
        print('\nEthernet Frame:')
        print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        ip_version = packet[IP].version
        ip_header_length = packet[IP].ihl * 4  # Multiply by 4 to get bytes
        print('Source IP: {}, Destination IP: {}'.format(src_ip, dest_ip))
        print('IPv4 Version: {}, IPv4 Header Length: {}'.format(ip_version, ip_header_length))

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            sequence = packet[TCP].seq
            acknowledgment = packet[TCP].ack
            tcp_flags = packet[TCP].flags
            tcp_data = packet[TCP].payload
            print('Source Port (TCP): {}, Destination Port (TCP): {}'.format(src_port, dest_port))
            print('Sequence Number: {}, Acknowledgment Number: {}'.format(sequence, acknowledgment))
            print('TCP Flags: {}'.format(tcp_flags))
            print('TCP Data: {}'.format(tcp_data))

if __name__ == "__main__":
    main()