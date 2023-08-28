import pyshark, rich, sys
import pandas as pd

edhoc_pcap = './results/edhoc.pcap'
edhoc_csv = './results/edhoc_pcap.csv'
dtls_pcap = './results/dtls.pcap'
dtls_csv = './results/dtls_pcap.csv'

IEEE_802154_HEADER_LEN = 2+1+2+8+8
SIXLOWPAN_HEADER_LEN = 2+1+2+2+2
SIXLOWPAN_FRAG_1_HEADER_LEN = 4+2+1+2+2+2
SIXLOWPAN_FRAG_N_HEADER_LEN = 5
UDP_HEADER_LEN = 8

def process_edhoc():
    cap = pyshark.FileCapture(edhoc_pcap, display_filter='coap')
    rows = []
    def coap_payload_len(packet):
        try: return int(packet['coap'].payload_length)
        except: return 0
    for packet in cap:
        # print(packet)
        sizes = {
            "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
            "6LoWPAN": SIXLOWPAN_HEADER_LEN,
            "CoAP": int(packet.udp.length) - UDP_HEADER_LEN - coap_payload_len(packet),
            "Content": coap_payload_len(packet),
        }
        if sum(sizes.values()) != int(packet.length):
            raise Exception("Sum does not match packet length.")
        sizes["_total"] = int(packet.length)
        rows.append(sizes.values())

    df = pd.DataFrame(rows, columns=sizes.keys())
    print(df)
    df.to_csv(edhoc_csv, index=False)
    print(f"Written to {edhoc_csv}\n")

def process_dtls():
    cap = pyshark.FileCapture(dtls_pcap)
    rows = []
    was_frag = False
    sizes_frag = {
        "IEEE 802.15.4": 0,
        "6LoWPAN": 0,
        "Content": 0,
        "_total": 0,
    }
    for packet in cap:
        # print(packet)
        if not was_frag and hasattr(packet, 'udp'):
            sizes_new = {
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_total": int(packet.length)
            }
            rows.append(sizes_new)

        elif was_frag and hasattr(packet, 'udp'):
            sizes_new = {
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_total": int(packet.length)
            }
            for k, v in sizes_new.items():
                sizes_frag[k] = sizes_frag[k] + v

            rows.append(sizes_frag)

            sizes_frag = {
                "IEEE 802.15.4": 0,
                "6LoWPAN": 0,
                "Content": 0,
                "_total": 0,
            }
            was_frag = False
        elif was_frag:
            sizes_new_frag = {
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_N_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_N_HEADER_LEN,
                "_total": int(packet.length)
            }

            for k, v in sizes_new_frag.items():
                sizes_frag[k] = sizes_frag[k] + v

            was_frag = True

        else:
            sizes_new_frag = {
                "IEEE 802.15.4": IEEE_802154_HEADER_LEN,
                "6LoWPAN": SIXLOWPAN_FRAG_1_HEADER_LEN,
                "Content": int(packet.length) - IEEE_802154_HEADER_LEN - SIXLOWPAN_FRAG_1_HEADER_LEN,
                "_total": int(packet.length)
            }

            for k, v in sizes_new_frag.items():
                sizes_frag[k] = sizes_frag[k] + v

            was_frag = True

    df = pd.DataFrame(rows, columns=sizes_frag.keys())
    print(df)
    df.to_csv(dtls_csv, index=False)
    print(f"Written to {dtls_csv}\n")

process_edhoc()
process_dtls()
