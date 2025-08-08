import pyshark
from dotenv import load_dotenv
import os
from handlers.db import store_fingerprint

load_dotenv()
capture = pyshark.LiveCapture(interface='Wi-Fi', tshark_path=os.getenv("TSHARK_LOC"), display_filter='tls.handshake')

for packet in capture.sniff_continuously():
    try:
        
        cipher_suites = []
        cipher_string = ""
        extensions_list = []
        extensions_string = ""
        the_grand_list = []
        the_grand_string = ""
        ec_point_list = []
        ec_point_string = ""
        supported_groups_list = []
        supported_groups_string = ""

        if hasattr(packet, 'tls'):
            version = int(packet.tls.handshake_version, 16)
            the_grand_list.append(str(version))

            for i in packet.tls.handshake_ciphersuite.all_fields:
                cipher = int(i.get_default_value(), 16)
                cipher_suites.append(cipher)
            cipher_suites.sort()
            cipher_string= '-'.join(str(c) for c in cipher_suites)
            the_grand_list.append(cipher_string)

            for i in packet.tls.handshake_extension_type.all_fields:
                extensions_list.append(i.get_default_value())
            extensions_list.sort()
            extensions_string = '-'.join(str(e) for e in extensions_list)
            the_grand_list.append(extensions_string)

            for i in packet.tls.handshake_extensions_supported_group.all_fields:
                sg = int(i.get_default_value(), 16)
                supported_groups_list.append(sg)
            supported_groups_list.sort()
            supported_groups_string = "-".join(str(s) for s in supported_groups_list)
            the_grand_list.append(supported_groups_string)

            for ec in packet.tls.handshake_extensions_ec_point_format.all_fields:
                ec_point_list.append(ec.get_default_value())
            ec_point_list.sort()
            ec_point_string = '-'.join(str(ec) for ec in ec_point_list)
            the_grand_list.append(ec_point_string)

            # print(the_grand_list) 
            the_grand_string = ','.join(g for g in the_grand_list)
            store_fingerprint(the_grand_string)
            
                       
    except Exception as e:
        print(e)