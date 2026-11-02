from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        print(f"[+] Packet: Src: {src_ip} --> Dst: {dst_ip} | Proto: {proto}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print(f"    Ports -> Src: {packet.sport} | Dst: {packet.dport}\n")

def main():
    print("[*] Starting Network Sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
