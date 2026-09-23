"""
02-pcap-streams starter script  (SIH'26 - SecureMailScope)
------------------------------------------------------------
What this does, in plain words:

A PCAP file is like a recording of everything that happened on the
network — every packet, from every conversation, all mixed together.

Your job (02-pcap-streams) is to be the "sorting" step:
  1. Open the recording (the .pcap file).
  2. Find every separate "conversation" between two computers
     (this is called a TCP stream).
  3. Figure out which conversations are email-related
     (SMTP / IMAP / POP3, based on the port number).
  4. Check whether that conversation used STARTTLS (i.e. it started
     in plain text and then said "ok, let's switch to encrypted now").
  5. Save a clean, organized JSON summary of each stream.

Someone else on the team (Jeevika, 03-tls-parser) will take YOUR
JSON output and dig deeper into the actual TLS handshake details.
So your output is the "handoff" — it needs to be clean and predictable.

Requirements:
    pip install pyshark
    (pyshark needs tshark installed - you already have this from Wireshark)

Usage:
    python pcap_stream_extractor.py path/to/capture.pcap
"""

import sys
import json
import os
from collections import defaultdict

try:
    import pyshark
except ImportError:
    print("pyshark not found. Install it with: pip install pyshark")
    sys.exit(1)


# ---------------------------------------------------------------
# STEP 1: Which ports mean which protocol?
# Think of a port number like an apartment number in a building.
# The IP address is the building, the port tells you which "door"
# the traffic is knocking on.
# ---------------------------------------------------------------
PORT_MAP = {
    25: ("SMTP", "plaintext-or-starttls"),
    587: ("SMTP", "plaintext-or-starttls"),   # submission port, usually STARTTLS
    465: ("SMTP", "implicit-tls"),            # SMTPS, TLS from the start
    143: ("IMAP", "plaintext-or-starttls"),
    993: ("IMAP", "implicit-tls"),            # IMAPS
    110: ("POP3", "plaintext-or-starttls"),
    995: ("POP3", "implicit-tls"),            # POP3S
}

# Commands that signal "we are about to upgrade to TLS"
STARTTLS_KEYWORDS = {
    "SMTP": [b"STARTTLS"],
    "IMAP": [b"STARTTLS", b"a1 STARTTLS", b"a STARTTLS"],
    "POP3": [b"STLS"],
}


def identify_protocol(src_port, dst_port):
    """Look at both ports, return protocol info if either one matches."""
    for port in (src_port, dst_port):
        if port in PORT_MAP:
            return PORT_MAP[port]
    return (None, None)


def extract_streams(pcap_path):
    """
    STEP 2: Group packets by "conversation".
    pyshark can tell us the tcp.stream number directly - Wireshark
    already does the hard work of figuring out which packets belong
    to which conversation. We just collect them.
    """
    print(f"Opening {pcap_path} ... this can take a bit for large files.")

    # Just the filename (e.g. "good_capture1.pcap"), not the whole path -
    # this goes into every stream entry so whoever reads the JSON later
    # (Jeevika) knows exactly which recording each stream came from.
    source_pcap = os.path.basename(pcap_path)

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter="tcp.port==25 or tcp.port==587 or tcp.port==465 "
                        "or tcp.port==143 or tcp.port==993 "
                        "or tcp.port==110 or tcp.port==995",
        use_json=True,
        include_raw=True,
    )

    streams = defaultdict(lambda: {
        "stream_id": None,
        "source_pcap": source_pcap,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "expected_security": None,   # "plaintext-or-starttls" or "implicit-tls"
        "packet_count": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "starttls_seen": False,
        "starttls_packet_number": None,
        "tls_client_hello_seen": False,
        "tls_client_hello_packet_number": None,
    })

    for pkt in cap:
        try:
            stream_id = int(pkt.tcp.stream)
        except AttributeError:
            continue  # not a TCP packet somehow, skip

        s = streams[stream_id]
        s["stream_id"] = stream_id
        s["packet_count"] += 1

        ts = float(pkt.sniff_timestamp)
        if s["first_timestamp"] is None:
            s["first_timestamp"] = ts
        s["last_timestamp"] = ts

        try:
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
        except AttributeError:
            continue

        if s["protocol"] is None:
            proto, expected_security = identify_protocol(src_port, dst_port)
            s["protocol"] = proto
            s["expected_security"] = expected_security
            s["src_ip"] = pkt.ip.src if hasattr(pkt, "ip") else None
            s["dst_ip"] = pkt.ip.dst if hasattr(pkt, "ip") else None
            s["src_port"] = src_port
            s["dst_port"] = dst_port

        # STEP 3: Check for STARTTLS in plaintext commands.
        # We look inside the raw TCP payload bytes for known keywords.
        if hasattr(pkt, "data") and hasattr(pkt.data, "data"):
            try:
                raw_bytes = bytes.fromhex(pkt.data.data.replace(":", ""))
            except (ValueError, AttributeError):
                raw_bytes = b""

            if raw_bytes and s["protocol"] in STARTTLS_KEYWORDS:
                for keyword in STARTTLS_KEYWORDS[s["protocol"]]:
                    if keyword in raw_bytes.upper():
                        s["starttls_seen"] = True
                        s["starttls_packet_number"] = int(pkt.number)
                        break

        # STEP 4: Check whether this packet is a TLS Client Hello.
        # That tells us "ok, encryption actually started here".
        if hasattr(pkt, "tls"):
            try:
                handshake_type = pkt.tls.handshake_type
                if handshake_type == "1":  # 1 = Client Hello
                    s["tls_client_hello_seen"] = True
                    s["tls_client_hello_packet_number"] = int(pkt.number)
            except AttributeError:
                pass

    cap.close()
    return streams


def save_results(streams, output_path):
    """
    STEP 5: Save as clean JSON.
    This is the file Jeevika (TLS parser) and the rules-engine
    person (Krithiksha) will read next.
    """
    result = []
    for stream_id, data in sorted(streams.items()):
        if data["protocol"] is None:
            continue  # not an email protocol stream, skip it
        data["duration_seconds"] = round(
            (data["last_timestamp"] - data["first_timestamp"]), 3
        ) if data["first_timestamp"] and data["last_timestamp"] else 0
        result.append(data)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nDone. Found {len(result)} email-related stream(s).")
    print(f"Saved to: {output_path}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python pcap_stream_extractor.py path/to/capture.pcap")
        sys.exit(1)

    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"File not found: {pcap_path}")
        sys.exit(1)

    output_path = os.path.splitext(pcap_path)[0] + "_streams.json"

    streams = extract_streams(pcap_path)
    save_results(streams, output_path)


if __name__ == "__main__":
    main()
