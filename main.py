import pyshark
from dotenv import load_dotenv
import os
load_dotenv()
capture = pyshark.LiveCapture(interface='Wi-Fi', tshark_path=os.getenv("TSHARK_LOC"), display_filter='tls.handshake')
cipher_suites = []
for packet in capture.sniff_continuously():
    try:
        

        if hasattr(packet, 'tls'):

            for i in packet.tls.handshake_ciphersuite.all_fields:
                cipher_suites.append(i.get_default_value())
            for i in packet.tls.field_names:
                print(i)
            print(packet.tls.handshake_extension_type.all_fields)
            for i in packet.tls.handshake_extension_type.all_fields:
                print(i.get_default_value())
            break
    except Exception as e:
        print(e)