import pyshark
import json
import os

TSHARK_PATH = r'D:\Wireshark\tshark.exe'
SUMMARIES_JSON = '../02-pcap-streams/extracted_streams/all_summaries.json'
PCAP_DIR = 'pcaps'  # your own folder, where you've already copied all the pcap files

with open(SUMMARIES_JSON) as f:
    data = json.load(f)

all_results = []

for group in data:
    for stream in group.get('streams', []):
        signals = stream.get('signals', {})
        source_pcap = stream.get('source_pcap')

        entry = {
            'source_pcap': source_pcap,
            'stream_file': stream.get('stream_file'),
            'endpoint_a': stream.get('endpoint_a'),
            'endpoint_b': stream.get('endpoint_b'),
            'starttls_offered_by_server': signals.get('starttls_offered_by_server'),
            'starttls_used_by_client': signals.get('starttls_used_by_client'),
            'insecure_auth': signals.get('insecure_auth'),
            'credentials_exposed': bool(signals.get('decoded_credentials')),
        }

        if not signals.get('starttls_used_by_client'):
            # No TLS was used at all in this stream — confirmed plaintext
            entry['encrypted'] = False
            if signals.get('starttls_offered_by_server'):
                entry['note'] = 'Server offered STARTTLS but client never used it — downgrade/misconfiguration'
            else:
                entry['note'] = 'No STARTTLS offered or used — fully plaintext session'
            all_results.append(entry)
            print(entry)
            continue

        # TLS was used — open the actual pcap to get version/cipher details
        filepath = os.path.join(PCAP_DIR, source_pcap)
        if not os.path.exists(filepath):
            entry['encrypted'] = None
            entry['note'] = f'source_pcap "{source_pcap}" not found in {PCAP_DIR} — copy it in first'
            all_results.append(entry)
            print(entry)
            continue

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
            entry['note'] = 'Client used STARTTLS but no TLS handshake packet found — possible downgrade attack'

        all_results.append(entry)
        print(entry)

with open('tls_parsed_output.json', 'w') as f:
    json.dump(all_results, f, indent=2)

print(f"\nDone. Processed {len(all_results)} streams.")