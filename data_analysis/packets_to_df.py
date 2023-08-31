import pyshark, rich, sys
import pandas as pd

edhoc_pcap = './results/edhoc.pcap'
edhoc_csv = './results/edhoc_pcap.csv'
dtls_rpk_pcap = './results/dtls_rpk.pcap'
dtls_rpk_csv = './results/dtls_rpk_pcap.csv'
dtls_cert_pcap = './results/dtls_cert.pcap'
dtls_cert_csv = './results/dtls_cert_pcap.csv'

IEEE_802154_HEADER_LEN = 2+1+2+8+8
SIXLOWPAN_HEADER_LEN = 2+1+2+2+2
SIXLOWPAN_FRAG_1_HEADER_LEN = 4+2+1+2+2+2
SIXLOWPAN_FRAG_N_HEADER_LEN = 5
UDP_HEADER_LEN = 8

ORIGINATOR_SRC_ADDR = 'fe80::6c95:c0cd:7940:1680'

def get_direction(packet):
    """note: will not work for fragmented packets, except if it is the first fragment"""
    # return "up" if getattr(packet, '6lowpan').src == ORIGINATOR_SRC_ADDR else "down"
    return "🚀" if getattr(packet, '6lowpan').src == ORIGINATOR_SRC_ADDR else "⬇️"

def process_edhoc():
    cap = pyshark.FileCapture(edhoc_pcap, display_filter='coap', use_json=True, include_raw=True)
    rows = []
    def coap_payload_len(packet):
        try: return int(packet['coap'].payload_tree.payload_length)
        except: return 0
    for packet in cap:
        # print(packet)
        sizes = {
            "_fragments": 1,
            "_direction": get_direction(packet),
            "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
            "6LoWPAN": SIXLOWPAN_HEADER_LEN,
            "CoAP": int(packet.udp.length) - UDP_HEADER_LEN - coap_payload_len(packet),
            "Content": coap_payload_len(packet),
        }
        # if sum(sizes.values()) != int(packet.length):
        #     raise Exception("Sum does not match packet length.")
        sizes["_sum"] = int(packet.length)

        raw = bytes.fromhex(packet.wpan_raw.value)
        sizes["_802154"] = [raw[:IEEE_802154_HEADER_LEN].hex()]
        sizes["_6lowpan"] = [raw[IEEE_802154_HEADER_LEN:IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN].hex()]
        coap_header_len = int(packet.udp.length) - UDP_HEADER_LEN - coap_payload_len(packet)
        sizes["_coap"] = raw[IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN:IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN+coap_header_len].hex()
        try: sizes["_content"] = packet['coap'].payload_raw[0]
        except: sizes["_content"] = ""

        rows.append(sizes.values())

    df = pd.DataFrame(rows, columns=sizes.keys())
    print(df)
    df.to_csv(edhoc_csv, index=False)
    print(f"Written to {edhoc_csv}\n")

def process_dtls(pcap_file, csv_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='!icmpv6', use_json=True, include_raw=True)
    rows = []
    was_frag = False
    sizes_frag = {
        "_fragments": 0,
        "_direction": "",
        "IEEE 802.15.4": 0,
        "6LoWPAN": 0,
        "Content": 0,
        "_sum": 0,
    }
    last_direction = ""
    for packet in cap:
        # print(packet)
        if not was_frag and hasattr(packet, 'udp'):
            sizes_new = {
                "_fragments": 1,
                "_direction": get_direction(packet),
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_sum": int(packet.length)
            }
            rows.append(sizes_new)

        elif was_frag and hasattr(packet, 'udp'): # fragmentation is over
            sizes_new = {
                "_fragments": 1,
                "_direction": "",
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_sum": int(packet.length)
            }
            for k, v in sizes_new.items():
                sizes_frag[k] = sizes_frag[k] + v

            rows.append(sizes_frag)

            sizes_frag = {
                "_fragments": 0,
                "_direction": "",
                "IEEE 802.15.4": 0,
                "6LoWPAN": 0,
                "Content": 0,
                "_sum": 0,
            }
            was_frag = False
        elif was_frag: # fragmentation is going on (had a fragment before, and will still have another one)
            sizes_new_frag = {
                "_fragments": 1,
                "_direction": "",
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_sum": int(packet.length)
            }

            for k, v in sizes_new_frag.items():
                sizes_frag[k] = sizes_frag[k] + v

            was_frag = True

        else: # a new fragmentation packet
            sizes_new_frag = {
                "_fragments": 1,
                "_direction": get_direction(packet),
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_1_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_1_HEADER_LEN,
                "_sum": int(packet.length)
            }

            for k, v in sizes_new_frag.items():
                sizes_frag[k] = sizes_frag[k] + v

            was_frag = True

    df = pd.DataFrame(rows, columns=sizes_frag.keys())
    print(df)
    df.to_csv(csv_file, index=False)
    print(f"Written to {csv_file}\n")

process_edhoc()
process_dtls(dtls_rpk_pcap, dtls_rpk_csv)
process_dtls(dtls_cert_pcap, dtls_cert_csv)
