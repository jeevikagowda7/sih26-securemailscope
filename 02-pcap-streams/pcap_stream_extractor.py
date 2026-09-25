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
  5. If a conversation NEVER encrypted at all, check whether we can
     see a plaintext login (IMAP LOGIN, or POP3 USER/PASS) sitting in
     the open - that's the "leaked credentials" proof for the demo.
  6. Save a clean, organized JSON summary of each stream.

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
import re
import asyncio
from collections import defaultdict
from datetime import datetime

try:
    import pyshark
except ImportError:
    print("pyshark not found. Install it with: pip install pyshark")
    sys.exit(1)

# --- Fix for newer Python versions (3.12+) ---
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())
# ----------------------------------------------


PORT_MAP = {
    25: ("SMTP", "plaintext-or-starttls"),
    587: ("SMTP", "plaintext-or-starttls"),
    465: ("SMTP", "implicit-tls"),
    143: ("IMAP", "plaintext-or-starttls"),
    993: ("IMAP", "implicit-tls"),
    110: ("POP3", "plaintext-or-starttls"),
    995: ("POP3", "implicit-tls"),

    2525: ("SMTP", "plaintext-or-starttls"),  # good-mail SMTP
    2587: ("SMTP", "plaintext-or-starttls"),  # good-mail submission
    2993: ("IMAP", "implicit-tls"),           # good-mail IMAPS
    3525: ("SMTP", "plaintext-or-starttls"),  # bad-mail SMTP
    3587: ("SMTP", "plaintext-or-starttls"),  # bad-mail submission
    3993: ("IMAP", "implicit-tls"),           # bad-mail IMAPS
    3143: ("IMAP", "plaintext-or-starttls"),  # bad-mail plaintext IMAP
    2995: ("POP3", "implicit-tls"),           # good-mail POP3S
    3110: ("POP3", "plaintext-or-starttls"),  # bad-mail plaintext POP3
}

STARTTLS_KEYWORDS = {
    "SMTP": [b"STARTTLS"],
    "IMAP": [b"STARTTLS", b"a1 STARTTLS", b"a STARTTLS"],
    "POP3": [b"STLS"],
}

# Plaintext IMAP LOGIN command: "a1 LOGIN myuser mypassword" (one line).
IMAP_LOGIN_PATTERN = re.compile(
    rb'\bLOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', re.IGNORECASE
)

# NEW: plaintext POP3 login commands. Unlike IMAP, these come as two
# separate lines:  "USER bob"  then  "PASS mypassword"
POP3_USER_PATTERN = re.compile(rb'^\s*USER\s+(\S+)', re.IGNORECASE)
POP3_PASS_PATTERN = re.compile(rb'^\s*PASS\s+(\S+)', re.IGNORECASE)


def identify_protocol(src_port, dst_port):
    for port in (src_port, dst_port):
        if port in PORT_MAP:
            return PORT_MAP[port]
    return (None, None)


def parse_timestamp(ts_str):
    try:
        return float(ts_str)
    except ValueError:
        pass

    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(Z|[+-]\d{2}:\d{2})$", ts_str)
    if match:
        base, frac, tz = match.groups()
        frac_microseconds = (frac + "000000")[:6]
        tz_normalized = "+00:00" if tz == "Z" else tz
        iso_string = f"{base}.{frac_microseconds}{tz_normalized}"
        return datetime.fromisoformat(iso_string).timestamp()

    raise ValueError(f"Could not understand this timestamp format: {ts_str!r}")


def extract_streams(pcap_path):
    print(f"Opening {pcap_path} ... this can take a bit for large files.")

    source_pcap = os.path.basename(pcap_path)

    KNOWN_CUSTOM_TSHARK_PATHS = [
        r"C:\Users\sumai\Sih26\Wireshark\tshark.exe",
        r"C:\Users\varsh\OneDrive\Documents\Wireshark\tshark.exe",
    ]
    tshark_path = next(
        (path for path in KNOWN_CUSTOM_TSHARK_PATHS if os.path.exists(path)),
        None,
    )

    port_filter = " or ".join(f"tcp.port=={port}" for port in PORT_MAP)

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=port_filter,
        use_json=True,
        include_raw=True,
        tshark_path=tshark_path,
    )

    streams = defaultdict(lambda: {
        "stream_id": None,
        "source_pcap": source_pcap,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "expected_security": None,
        "packet_count": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "starttls_seen": False,
        "starttls_packet_number": None,
        "tls_client_hello_seen": False,
        "tls_client_hello_packet_number": None,
        "credentials_leaked": False,
        "leaked_username": None,
        "leaked_password": None,
    })

    for pkt in cap:
        try:
            stream_id = int(pkt.tcp.stream)
        except AttributeError:
            continue

        s = streams[stream_id]
        s["stream_id"] = stream_id
        s["packet_count"] += 1

        ts = parse_timestamp(pkt.sniff_timestamp)
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

            # Plaintext IMAP LOGIN credential check.
            if raw_bytes and s["protocol"] == "IMAP" and not s["credentials_leaked"]:
                match = IMAP_LOGIN_PATTERN.search(raw_bytes)
                if match:
                    s["credentials_leaked"] = True
                    s["leaked_username"] = match.group(1).decode(errors="replace")
                    s["leaked_password"] = match.group(2).decode(errors="replace")

            # NEW: Plaintext POP3 USER/PASS credential check.
            # First packet gives the username, a later packet gives the
            # password - we remember the username until the password
            # shows up, then mark it leaked.
            if raw_bytes and s["protocol"] == "POP3" and not s["credentials_leaked"]:
                user_match = POP3_USER_PATTERN.match(raw_bytes)
                if user_match:
                    s["leaked_username"] = user_match.group(1).decode(errors="replace")
                else:
                    pass_match = POP3_PASS_PATTERN.match(raw_bytes)
                    if pass_match and s["leaked_username"]:
                        s["leaked_password"] = pass_match.group(1).decode(errors="replace")
                        s["credentials_leaked"] = True

        if hasattr(pkt, "tls") and not s["tls_client_hello_seen"]:
            s["tls_client_hello_seen"] = True
            s["tls_client_hello_packet_number"] = int(pkt.number)

    cap.close()
    return streams


def save_results(streams, output_path):
    result = []
    for stream_id, data in sorted(streams.items()):
        if data["protocol"] is None:
            continue
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

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "extracted_streams")
    os.makedirs(output_dir, exist_ok=True)

    pcap_filename = os.path.basename(pcap_path)
    output_filename = os.path.splitext(pcap_filename)[0] + "_streams.json"
    output_path = os.path.join(output_dir, output_filename)

    streams = extract_streams(pcap_path)
    save_results(streams, output_path)


if __name__ == "__main__":
    main()