import pyshark
import json
import os

TSHARK_PATH = r'D:\Wireshark\tshark.exe'
PCAP_DIR = 'pcaps'
STREAMS_DIR = '../02-pcap-streams/extracted_streams'

all_results = []


def extract_tls_details(entry, filepath):
    """Open the pcap and pull real TLS version/cipher if a handshake exists."""
    if not os.path.exists(filepath):
        entry['encrypted'] = None
        entry['note'] = f'pcap file not found: {filepath}'
        return entry

    cap = pyshark.FileCapture(
        filepath,
        display_filter='tls.handshake.type==1 or tls.handshake.type==2',
        tshark_path=TSHARK_PATH
    )
    found_tls = False
    for packet in cap:
        try:
            tls_layer = packet.tls
            entry['tls_version'] = tls_layer.get_field_value('handshake_version')
            entry['cipher_suite'] = tls_layer.get_field_value('handshake_ciphersuite')
            entry['encrypted'] = True
            found_tls = True
            break
        except AttributeError:
            continue
    cap.close()
    if not found_tls:
        entry['encrypted'] = False
    return entry


# ---- Source 1: all_summaries.json (older 6 captures) ----
summaries_path = os.path.join(STREAMS_DIR, 'all_summaries.json')
if os.path.exists(summaries_path):
    with open(summaries_path) as f:
        data = json.load(f)

    for group in data:
        for stream in group.get('streams', []):
            signals = stream.get('signals', {})
            source_pcap = stream.get('source_pcap')
            entry = {
                'source_pcap': source_pcap,
                'endpoint_a': stream.get('endpoint_a'),
                'endpoint_b': stream.get('endpoint_b'),
                'starttls_offered_by_server': signals.get('starttls_offered_by_server'),
                'starttls_used_by_client': signals.get('starttls_used_by_client'),
                'insecure_auth': signals.get('insecure_auth'),
                'credentials_exposed': bool(signals.get('decoded_credentials')),
            }
            if not signals.get('starttls_used_by_client'):
                entry['encrypted'] = False
                entry['note'] = 'No STARTTLS used — plaintext session'
            else:
                entry = extract_tls_details(entry, os.path.join(PCAP_DIR, source_pcap))
            all_results.append(entry)
            print(entry)

# ---- Source 2: individual *_streams.json files (capture4, 5, 6) ----
for filename in os.listdir(STREAMS_DIR):
    if not filename.endswith('_streams.json'):
        continue
    filepath = os.path.join(STREAMS_DIR, filename)
    with open(filepath) as f:
        streams = json.load(f)

    for stream in streams:
        source_pcap = stream.get('source_pcap')
        entry = {
            'source_pcap': source_pcap,
            'src_ip': stream.get('src_ip'),
            'dst_ip': stream.get('dst_ip'),
            'starttls_seen': stream.get('starttls_seen'),
        }

        # Always verify against the actual pcap ourselves —
        # don't trust Varshini's tls_client_hello_seen flag blindly,
        # it was wrong for capture4/capture6 (confirmed by Sumaiya).
        entry = extract_tls_details(entry, os.path.join(PCAP_DIR, source_pcap))

        if entry.get('encrypted') is False:
            if stream.get('starttls_seen'):
                entry['note'] = 'STARTTLS requested but no TLS handshake found — downgrade'
            else:
                entry['note'] = 'No STARTTLS and no TLS handshake — plaintext'

        all_results.append(entry)
        print(entry)

print(f"\nDone. Processed {len(all_results)} streams total.")