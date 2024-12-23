from scapy.all import sniff, TCP, IP
import re

# Function to parse HTTP/HTTPS packets
def packet_callback(packet):
    try:
        # Look for TCP packets with payload
        if packet.haslayer(TCP) and packet.haslayer(IP):
            payload = bytes(packet[TCP].payload)
            # Decode payload to string for searching
            payload_str = payload.decode(errors="ignore")
            
            # Look for email patterns
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            email_matches = re.findall(email_pattern, payload_str)

            # Look for password patterns (e.g., "password=xyz")
            password_pattern = r'(?i)(password=|pwd=|passwd=)(\w+)'
            password_matches = re.findall(password_pattern, payload_str)

            if email_matches or password_matches:
                print(f"Captured Data:\n")
                if email_matches:
                    print(f"Emails: {email_matches}")
                if password_matches:
                    print(f"Passwords: {[pwd[1] for pwd in password_matches]}")
                print("=" * 50)
    except Exception as e:
        print(f"Error parsing packet: {e}")

# Sniff function
def start_sniffing(interface="WiFi"):
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(iface="lo", filter="tcp and port 5000", prn=packet_callback, store=0)

if __name__ == "__main__":
    # Change "eth0" to the correct interface for your machine
    interface = "127.0.0.1"
    start_sniffing(interface)
