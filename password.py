import pyshark
tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe"  # Correct 


import pyshark

# Replace 'Wi-Fi' with your network interface name
interface = 'Adapter for loopback traffic capture'

capture = pyshark.LiveCapture(interface=interface,tshark_path=tshark_path,display_filter='http')

print("Starting packet capture... Press Ctrl+C to stop.")
try:
    for packet in capture.sniff_continuously(packet_count=5):
        print(f"Packet captured: {packet}")
except KeyboardInterrupt:
    print("\nCapture stopped.")
