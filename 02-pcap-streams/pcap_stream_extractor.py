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
# pyshark internally expects a "current event loop" to already exist in
# this thread. Newer Python versions stopped setting that up
# automatically, so we create one by hand before pyshark needs it.
# Needed on computers running a newer Python (like Sumaiya's, on 3.14).
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())
# ----------------------------------------------


# ---------------------------------------------------------------
# STEP 1: Which ports mean which protocol?
# Think of a port number like an apartment number in a building.
# The IP address is the building, the port tells you which "door"
# the traffic is knocking on.
# ---------------------------------------------------------------
PORT_MAP = {
    # Standard ports
    25: ("SMTP", "plaintext-or-starttls"),
    587: ("SMTP", "plaintext-or-starttls"),   # submission port, usually STARTTLS
    465: ("SMTP", "implicit-tls"),            # SMTPS, TLS from the start
    143: ("IMAP", "plaintext-or-starttls"),
    993: ("IMAP", "implicit-tls"),            # IMAPS
    110: ("POP3", "plaintext-or-starttls"),
    995: ("POP3", "implicit-tls"),            # POP3S

    # Our team's docker-mailserver test ports (good-mail / bad-mail
    # containers use these instead of the standard ports above - see
    # Sumaiya's 01-data-lab setup notes).
    2525: ("SMTP", "plaintext-or-starttls"),  # good-mail SMTP
    2587: ("SMTP", "plaintext-or-starttls"),  # good-mail submission
    2993: ("IMAP", "implicit-tls"),           # good-mail IMAPS
    3525: ("SMTP", "plaintext-or-starttls"),  # bad-mail SMTP
    3587: ("SMTP", "plaintext-or-starttls"),  # bad-mail submission
    3993: ("IMAP", "implicit-tls"),           # bad-mail IMAPS
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


def parse_timestamp(ts_str):
    """
    Turn pkt.sniff_timestamp into a plain number of seconds, whichever
    format it comes in.

    Older tshark gives something like "1758537...123456" (a plain
    number already). Newer tshark (e.g. 4.6.8, seen on Sumaiya's
    laptop) instead gives a text date like
    "2026-09-22T10:08:00.631283360Z" - this crashed the old code,
    which just tried float() on it directly. This function handles
    both, so it works regardless of which tshark version is installed.
    """
    try:
        return float(ts_str)
    except ValueError:
        pass

    # Text-date format. Python's datetime can only handle up to
    # microseconds (6 digits) in the fractional-seconds part, but
    # tshark sometimes gives nanoseconds (9 digits), so trim that down
    # first.
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(Z|[+-]\d{2}:\d{2})$", ts_str)
    if match:
        base, frac, tz = match.groups()
        frac_microseconds = (frac + "000000")[:6]
        tz_normalized = "+00:00" if tz == "Z" else tz
        iso_string = f"{base}.{frac_microseconds}{tz_normalized}"
        return datetime.fromisoformat(iso_string).timestamp()

    raise ValueError(f"Could not understand this timestamp format: {ts_str!r}")


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

    # On some computers Wireshark/tshark gets installed to a non-standard
    # folder, so pyshark can't find it automatically. If we spot that
    # exact case, point straight at it. On any other computer (where
    # Wireshark is in the normal location) this is simply ignored.
    CUSTOM_TSHARK_PATH = r"C:\Users\sumai\Sih26\Wireshark\tshark.exe"
    tshark_path = CUSTOM_TSHARK_PATH if os.path.exists(CUSTOM_TSHARK_PATH) else None

    # Builds "tcp.port==25 or tcp.port==587 or ..." automatically from
    # every port in PORT_MAP above, so this list never goes out of sync
    # with it again (this is what caused the "0 streams found" bug -
    # this filter only listed the standard ports, so it silently threw
    # away all the packets on our team's actual docker-mailserver ports).
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
        #
        # NOTE: We used to check pkt.tls.handshake_type == "1" here, but
        # on newer tshark versions (e.g. 4.6.8) that field isn't exposed
        # the same way anymore - pyshark just doesn't see it, even on a
        # real Client Hello packet. (Bug found by Jeevika/Sumaiya on
        # good_capture4 and good_capture6, confirmed via direct tshark
        # inspection - tshark itself saw the Client Hello fine, but our
        # script's specific field lookup was silently missing it.)
        #
        # Fix: instead of hunting for that one field, we use a simpler,
        # more reliable rule - the FIRST packet in a stream that has any
        # TLS data at all is, in practice, always the Client Hello (it's
        # the opening move of a TLS handshake, nothing TLS-related comes
        # before it). So we just mark the first one we see per stream.
        if hasattr(pkt, "tls") and not s["tls_client_hello_seen"]:
            s["tls_client_hello_seen"] = True
            s["tls_client_hello_packet_number"] = int(pkt.number)

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