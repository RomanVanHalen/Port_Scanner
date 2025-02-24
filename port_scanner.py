from scapy.all import *
import random
import time
import requests

# Function to perform SYN Stealth Scan
def syn_scan(target_ip, target_ports, decoy_ips=[]):
    print(f"[*] Starting SYN Stealth Scan on {target_ip}...")
    for port in random.sample(target_ports, len(target_ports)):  # Random order
        src_ip = random.choice(decoy_ips) if decoy_ips else None
        syn_packet = IP(dst=target_ip, src=src_ip)/TCP(dport=port, flags="S")
        
        response = sr1(syn_packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                print(f"[+] Port {port} is OPEN")
                send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)  # Send RST to avoid detection
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                print(f"[-] Port {port} is CLOSED")
        elif response is None:
            print(f"[?] Port {port} is FILTERED (No Response)")

        delay = random.uniform(0.5, 3)  # Random delay to evade IDS
        time.sleep(delay)

# Function to send Fragmented Packets
def fragmented_scan(target_ip, target_ports):
    print(f"[*] Sending fragmented packets to {target_ip}...")
    for port in target_ports:
        pkt = IP(dst=target_ip, flags="MF")/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        print(f"Sent fragmented packet to {target_ip}:{port}")

# Function to perform Decoy Scanning
def decoy_scan(target_ip, target_ports, decoy_ips):
    print(f"[*] Starting Decoy Scan on {target_ip} with decoys: {decoy_ips}...")
    for port in target_ports:
        for decoy in decoy_ips:
            pkt = IP(src=decoy, dst=target_ip)/TCP(dport=port, flags="S")
            send(pkt, verbose=0)
            print(f"Sent SYN packet from decoy {decoy} to {target_ip}:{port}")

# Function to Spoof HTTP Headers
def http_spoofing(target_ip):
    url = f"http://{target_ip}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Referer": "https://google.com",
        "Accept-Language": "en-US,en;q=0.5"
    }
    try:
        response = requests.get(url, headers=headers, timeout=3)
        print(f"[+] HTTP Response from {target_ip}: {response.status_code}")
    except requests.exceptions.RequestException:
        print(f"[?] Could not retrieve HTTP response from {target_ip}")

# Main function
def main():
    target_ip = input("Enter Target IP: ")
    ports = list(range(20, 1025))  # Scanning common ports
    decoys = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]  # Fake decoy IPs

    print("\n[1] SYN Stealth Scan")
    print("[2] Fragmented Packets Scan")
    print("[3] Decoy Scan")
    print("[4] HTTP Spoofing Scan")
    print("[5] Full Stealth Mode (All techniques)\n")
    
    choice = input("Choose scanning method: ")
    
    if choice == "1":
        syn_scan(target_ip, ports)
    elif choice == "2":
        fragmented_scan(target_ip, ports)
    elif choice == "3":
        decoy_scan(target_ip, ports, decoys)
    elif choice == "4":
        http_spoofing(target_ip)
    elif choice == "5":
        syn_scan(target_ip, ports, decoys)
        fragmented_scan(target_ip, ports)
        decoy_scan(target_ip, ports, decoys)
        http_spoofing(target_ip)
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
