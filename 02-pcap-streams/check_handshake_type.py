"""
check_handshake_type.py
--------------------------
Your main script's check is very specific:

    if hasattr(pkt, "tls"):
        if pkt.tls.handshake_type == "1":
            ... mark it as a Client Hello ...

We now know packet #11 DOES have a "tls" layer. This script checks
the exact next part: does pkt.tls.handshake_type actually exist,
and what is it actually set to? This will show us precisely why
the main script's check passed or failed.

Usage:
    python check_handshake_type.py path/to/capture.pcap
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
    print("Usage: python check_handshake_type.py path\\to\\capture.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]

CUSTOM_TSHARK_PATH = r"C:\Users\sumai\Sih26\Wireshark\tshark.exe"
tshark_path = CUSTOM_TSHARK_PATH if os.path.exists(CUSTOM_TSHARK_PATH) else None

cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True, tshark_path=tshark_path)

for pkt in cap:
    if pkt.number != "11":
        continue

    print(f"Packet #{pkt.number}")
    print(f"hasattr(pkt, 'tls') = {hasattr(pkt, 'tls')}")

    if hasattr(pkt, "tls"):
        print(f"hasattr(pkt.tls, 'handshake_type') = {hasattr(pkt.tls, 'handshake_type')}")
        try:
            value = pkt.tls.handshake_type
            print(f"pkt.tls.handshake_type = {value!r}  (type: {type(value)})")
        except AttributeError as e:
            print(f"Tried to read pkt.tls.handshake_type and got an error: {e}")

        # Also show content_type, which we know IS present (22 = Handshake)
        if hasattr(pkt.tls, "content_type"):
            print(f"pkt.tls.content_type = {pkt.tls.content_type!r}")

    break

cap.close()