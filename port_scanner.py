import socket

def port_scanner(target, start_port, end_port):
    print(f"Scanning {target} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"[+] Port {port} is OPEN")
        else:
            print(f"[-] Port {port} is CLOSED")  # Debugging line

        sock.close()

target_ip = input("Enter target IP: ")
port_scanner(target_ip, 1, 100)
