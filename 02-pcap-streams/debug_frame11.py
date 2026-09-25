"""
debug_frame11.py
------------------
What this does, in plain words:

Jeevika found a bug: your script says "no TLS Client Hello" for
good_capture4 and good_capture6, but Sumaiya confirmed with tshark
that there IS one, at packet number 11.

This script opens the same pcap, walks straight to packet #11 (and
a couple around it, just in case the frame numbers are slightly
different), and prints out EVERYTHING pyshark can see on that
packet - every "layer" name it found, and every TLS-related field.

This tells us exactly why your main script's check
    if hasattr(pkt, "tls"):
was not catching it - e.g. maybe pyshark named the layer "ssl"
instead of "tls" for this capture, or the handshake_type field
looks different than expected.

Usage:
    python debug_frame11.py good_capture4_attachment.pcap
    python debug_frame11.py good_capture6_multirecipient.pcap
"""

import sys
import asyncio
import pyshark

# --- Fix for newer Python versions (3.12+) ---
# pyshark internally expects a "current event loop" to already exist in
# this thread, which older Python versions set up automatically. Newer
# Python versions stopped doing that automatically, so we create one
# by hand here before pyshark needs it. This is a one-time setup step,
# not something specific to your pcap files.
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())
# ----------------------------------------------

if len(sys.argv) != 2:
    print("Usage: python debug_frame11.py path/to/capture.pcap")
    sys.exit(1)

pcap_path = sys.argv[1]

# On this laptop, Wireshark/tshark was installed to a non-standard folder,
# so pyshark can't find it automatically. Point it there directly.
# (On a different computer where Wireshark is in the normal location,
# this extra path is simply ignored - harmless either way.)
import os
CUSTOM_TSHARK_PATH = r"C:\Users\sumai\Sih26\Wireshark\tshark.exe"
tshark_path = CUSTOM_TSHARK_PATH if os.path.exists(CUSTOM_TSHARK_PATH) else None

print(f"Opening {pcap_path} ...\n")

cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True, tshark_path=tshark_path)

target_numbers = {"9", "10", "11", "12", "13"}  # look around frame 11 too

for pkt in cap:
    if pkt.number not in target_numbers:
        continue

    print("=" * 60)
    print(f"Packet #{pkt.number}")
    print(f"Layers found on this packet: {[layer.layer_name for layer in pkt.layers]}")

    # Check for both possible names pyshark might use
    for layer_name in ("tls", "ssl"):
        if hasattr(pkt, layer_name):
            layer = getattr(pkt, layer_name)
            print(f"\n  Found a '{layer_name}' layer! Its fields:")
            try:
                for field_name in layer.field_names:
                    print(f"    {field_name} = {getattr(layer, field_name)}")
            except Exception as e:
                print(f"    (couldn't list fields: {e})")

    print()

cap.close()
print("Done. Scroll up and check: which layer name showed up ('tls' or 'ssl'),")
print("and what the handshake type field is actually called and set to.")