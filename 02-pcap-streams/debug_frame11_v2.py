"""
debug_frame11_v2.py
---------------------
Wider version: instead of only looking at packets #9-13 (a guess),
this scans EVERY packet in the file and:
  1. Prints the total number of packets
  2. Prints every packet number that has a "tls" or "ssl" layer at all
  3. For each of those, prints the layer's fields

This way we find the real TLS Client Hello packet wherever it is,
instead of assuming it's near #11.

Usage:
    python debug_frame11_v2.py path\to\capture.pcap
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
    print("Usage: python debug_frame11_v2.py path\\to\\capture.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]

CUSTOM_TSHARK_PATH = r"C:\Users\sumai\Sih26\Wireshark\tshark.exe"
tshark_path = CUSTOM_TSHARK_PATH if os.path.exists(CUSTOM_TSHARK_PATH) else None

print(f"Opening {pcap_path} ...\n")

cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True, tshark_path=tshark_path)

total_packets = 0
tls_packets_found = []

for pkt in cap:
    total_packets += 1

    for layer_name in ("tls", "ssl"):
        if hasattr(pkt, layer_name):
            tls_packets_found.append((pkt.number, layer_name))
            layer = getattr(pkt, layer_name)
            print("=" * 60)
            print(f"Packet #{pkt.number} has a '{layer_name}' layer!")
            print(f"All layers on this packet: {[l.layer_name for l in pkt.layers]}")
            try:
                for field_name in layer.field_names:
                    print(f"    {field_name} = {getattr(layer, field_name)}")
            except Exception as e:
                print(f"    (couldn't list fields: {e})")
            print()

cap.close()

print("=" * 60)
print(f"Total packets in file: {total_packets}")
print(f"Packets with a tls/ssl layer: {tls_packets_found if tls_packets_found else 'NONE FOUND'}")