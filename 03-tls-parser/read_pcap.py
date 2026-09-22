import pyshark
import json
import os

PCAP_DIR = 'pcaps'
TSHARK_PATH = r'D:\Wireshark\tshark.exe'

all_results = []

for filename in os.listdir(PCAP_DIR):
    if not filename.endswith('.pcap'):
        continue

    filepath = os.path.join(PCAP_DIR, filename)
    label = 'good' if 'good' in filename.lower() else 'bad' if 'bad' in filename.lower() else 'unknown'

    cap = pyshark.FileCapture(
        filepath,
        display_filter='tls.handshake.type==1 or tls.handshake.type==2',
        tshark_path=TSHARK_PATH
    )

    found_tls = False

    for packet in cap:
        try:
            tls_layer = packet.tls
            entry = {
                'source_file': filename,
                'label': label,
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'tls_version': tls_layer.get_field_value('handshake_version'),
                'cipher_suite': tls_layer.get_field_value('handshake_ciphersuite'),
                'encrypted': True
            }
            all_results.append(entry)
            print(entry)
            found_tls = True
        except AttributeError:
            continue

    cap.close()

    # If no TLS handshake was found at all in this file, flag it
    if not found_tls:
        entry = {
            'source_file': filename,
            'label': label,
            'src_ip': None,
            'dst_ip': None,
            'tls_version': None,
            'cipher_suite': None,
            'encrypted': False,
            'note': 'No TLS handshake detected — likely plaintext/unencrypted traffic'
        }
        all_results.append(entry)
        print(entry)

with open('tls_parsed_output.json', 'w') as f:
    json.dump(all_results, f, indent=2)

print(f"\nDone. Parsed {len(os.listdir(PCAP_DIR))} files, found {sum(1 for r in all_results if r['encrypted'])} encrypted handshakes.")