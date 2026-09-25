"""
check_ports.py
-----------------
Quick check: what src/dst ports does this pcap actually use?
This tells us if our PORT_MAP is still missing something.

Usage:
    python check_ports.py path/to/capture.pcap
"""

import sys
import os
import asyncio
import pyshark

try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

if len(sys.argv) != 2:
    print("Usage: python check_ports.py path/to/capture.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]

# Known tshark install locations across the team's laptops.
# The first one that actually exists on this computer gets used.
KNOWN_CUSTOM_TSHARK_PATHS = [
    r"C:\Users\sumai\Sih26\Wireshark\tshark.exe",              # Sumaiya's laptop
    r"C:\Users\varsh\OneDrive\Documents\Wireshark\tshark.exe",  # Varshini's laptop
]
tshark_path = next(
    (path for path in KNOWN_CUSTOM_TSHARK_PATHS if os.path.exists(path)),
    None,
)

cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True, tshark_path=tshark_path)

seen_ports = set()
count = 0
for pkt in cap:
    count += 1
    if hasattr(pkt, "tcp"):
        try:
            src = int(pkt.tcp.srcport)
            dst = int(pkt.tcp.dstport)
            seen_ports.add(src)
            seen_ports.add(dst)
        except AttributeError:
            pass

cap.close()

print(f"Total packets: {count}")
print(f"All TCP ports seen in this file: {sorted(seen_ports)}")