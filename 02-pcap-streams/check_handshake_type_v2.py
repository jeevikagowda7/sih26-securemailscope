"""
check_handshake_type_v2.py
-----------------------------
Same goal as before (find out why the main script's
"pkt.tls.handshake_type == '1'" check misses the Client Hello), but
this version scans every packet (no filtering by packet number,
since that seemed to misbehave last time) and reports the
handshake_type check for every packet that has a tls layer.

Usage:
    python check_handshake_type_v2.py path/to/capture.pcap
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
    print("Usage: python check_handshake_type_v2.py path/to/capture.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]

CUSTOM_TSHARK_PATH = r"C:\Users\sumai\Sih26\Wireshark\tshark.exe"
tshark_path = CUSTOM_TSHARK_PATH if os.path.exists(CUSTOM_TSHARK_PATH) else None

cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True, tshark_path=tshark_path)

for pkt in cap:
    if not hasattr(pkt, "tls"):
        continue

    print("=" * 60)
    print(f"Packet #{pkt.number}  (type of pkt.number: {type(pkt.number)})")

    has_handshake_type = hasattr(pkt.tls, "handshake_type")
    print(f"hasattr(pkt.tls, 'handshake_type') = {has_handshake_type}")

    if has_handshake_type:
        value = pkt.tls.handshake_type
        print(f"pkt.tls.handshake_type = {value!r}")
        print(f"Does it equal the string '1'? {value == '1'}")
    else:
        print("This packet's tls layer has NO handshake_type field at all.")

    if hasattr(pkt.tls, "content_type"):
        print(f"pkt.tls.content_type = {pkt.tls.content_type!r}")

cap.close()
print("=" * 60)
print("Done.")