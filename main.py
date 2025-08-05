import pyshark
from dotenv import load_dotenv
import os
load_dotenv()
capture = pyshark.LiveCapture(interface='Wi-Fi', tshark_path=os.getenv("TSHARK_LOC"), display_filter='tls.handshake')
for packet in capture.sniff_continuously():
    try:
        if hasattr(packet, 'tls'):
            print("tls handshake found")
            if 'handshake_type' in packet.tls.field_names:
                print("Handshake type : ", packet.tls.handshake_type)
            if 'record_version' in packet.tls.field_names:
                print("TLS version : ", packet.tls.record_version)
            if 'handshake_ciphersuite' in packet.tls.field_names:
                print("Cipher suite: ", packet.tls.handshake_ciphersuite)
            if 'handshake_extensions_server_name' in packet.tls.field_names:
                print("Domain (SNI):", packet.tls.handshake_extensions_server_name)
            print("packet finished\n")
    except Exception as err:
        print("erorr found")