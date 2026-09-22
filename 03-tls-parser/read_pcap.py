import pyshark

cap = pyshark.FileCapture(
    'good_v2.pcap',   # <- changed from sample_tls.pcap
    display_filter='tls.handshake.type==1 or tls.handshake.type==2',
    tshark_path=r'D:\Wireshark\tshark.exe'

)

results = []

for packet in cap:
    try:
        tls_layer = packet.tls
        entry = {
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'tls_version': tls_layer.get_field_value('handshake_version'),
            'cipher_suite': tls_layer.get_field_value('handshake_ciphersuite'),
        }
        results.append(entry)
        print(entry)
    except AttributeError:
        continue

cap.close()

import json
with open('tls_parsed_output.json', 'w') as f:
    json.dump(results, f, indent=2)