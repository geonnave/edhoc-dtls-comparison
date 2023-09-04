import pyshark, rich, sys, json
import pandas as pd
from pyshark.packet.packet import Packet as PysharkPacket
from dataclasses import dataclass, field, asdict, fields
from dataclasses_json import dataclass_json, config
from typing import List

IEEE_802154_HEADER_LEN = 2+1+2+8+8
SIXLOWPAN_HEADER_LEN = 2+1+2+2+2
SIXLOWPAN_FRAG_1_HEADER_LEN = SIXLOWPAN_HEADER_LEN + 4
SIXLOWPAN_FRAG_N_HEADER_LEN = 5
UDP_HEADER_LEN = 8

ORIGINATOR_SRC_ADDR = 'fe80::6c95:c0cd:7940:1680'

def coap_payload_len(packet):
    try: return int(packet['coap'].payload_tree.payload_length)
    except: return 0

@dataclass_json
@dataclass
class Message:
    # packets: List[PysharkPacket] = field(default_factory=list, metadata=config(exclude=lambda x: True))
    packets: List[int] = field(default_factory=list)
    direction: str = None
    reassembled: bytes = None
    ieee_802154: List[bytes] = field(default_factory=list)
    sixlowpan: List[bytes] = field(default_factory=list)
    coap: List[bytes] = field(default_factory=list)
    payloads: List[bytes] = field(default_factory=list)
    src: str = None
    dst: str = None
    raw: List[bytes] = field(default_factory=list)

    def raw_lens(self):
        return [len(r) for r in self.raw]

    def reassembled_len(self):
        return len(self.reassembled)

    def ingest_packet(self, packet, six_header_len=SIXLOWPAN_HEADER_LEN):
        self.packets.append(packet.number-1)
        if hasattr(packet['6lowpan'], 'src'):
            self.set_direction(packet)
        self.add_raw(packet)
        self.add_802154(packet)
        self.add_6lowpan(packet, six_header_len)
        if 'coap' in packet:
            self.add_content_from_coap(packet)
        else:
            self.add_content_from_udp_or_fragment(packet)
        self.reassembled = b''.join(self.payloads)

    def set_direction(self, packet):
        self.src = packet['6lowpan'].src
        self.dst = packet['6lowpan'].dst
        self.direction = "🚀" if self.src == ORIGINATOR_SRC_ADDR else "⬇️"

    def add_raw(self, packet):
        self.raw.append(bytes.fromhex(packet.wpan_raw.value))

    def add_802154(self, packet):
        self.ieee_802154.append(self.raw[-1][:IEEE_802154_HEADER_LEN])

    def add_6lowpan(self, packet, six_header_len):
        self.sixlowpan.append(self.raw[-1][IEEE_802154_HEADER_LEN:IEEE_802154_HEADER_LEN+six_header_len])

    def add_content_from_coap(self, packet):
        coap_header_len = int(packet.udp.length) - UDP_HEADER_LEN - coap_payload_len(packet)
        self.coap.append(self.raw[-1][IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN:IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN+coap_header_len])
        try:
            payload = packet['coap'].payload_raw[0]
            payload = bytes.fromhex(payload)
        except:
            payload = b''
        self.payloads.append(payload)

    def add_content_from_udp_or_fragment(self, packet):
        offset = len(self.ieee_802154[-1]) + len(self.sixlowpan[-1])
        payload = self.raw[-1][offset:]
        self.payloads.append(payload)

    def get_sum(self, layer):
        return sum([len(e) for e in getattr(self, layer)])

    def get_hex(self, layer):
        return [e.hex() for e in getattr(self, layer)]

def df_sizes(pcap_file, messages: List[Message]):
    csv_file = pcap_file.replace('.pcap', '_pcap.csv')
    columns = ["_fragments", "IEEE 802.15.4", "6LoWPAN", "Content", "_sum"]
    rows = [
        [
            len(msg.packets),
            msg.get_sum('ieee_802154'),
            msg.get_sum('sixlowpan'),
            msg.get_sum('payloads'),
            sum(msg.raw_lens()),
        ]
        for msg in messages
    ]
    df = pd.DataFrame(rows, columns=columns)
    rich.print(df)
    df.to_csv(csv_file, index=False)
    print(f"Written to {csv_file}\n")
    return df

def process_edhoc_messages(pcap_file) -> List[Message]:
    cap = pyshark.FileCapture(pcap_file, display_filter='coap', use_json=True, include_raw=True)
    messages = []
    for packet in cap:
        msg = Message()
        msg.ingest_packet(packet)
        messages.append(msg)
    cap.close()
    return messages

def process_dtls_messages(pcap_file) -> List[Message]:
    cap = pyshark.FileCapture(pcap_file, display_filter='!icmpv6', use_json=True, include_raw=True)
    messages = []
    msg = None
    in_frag = False
    for packet in cap:
        if not in_frag and hasattr(packet, 'udp'): # new, non-fragmented packet
            msg = Message()
            msg.ingest_packet(packet)
            messages.append(msg)
        elif in_frag and hasattr(packet, 'udp'): # fragmentation is over
            msg.ingest_packet(packet, six_header_len=SIXLOWPAN_FRAG_N_HEADER_LEN)
            messages.append(msg)
            in_frag = False
        elif in_frag: # fragmentation is going on (had a fragment before, and will still have another one)
            msg.ingest_packet(packet, six_header_len=SIXLOWPAN_FRAG_N_HEADER_LEN)
        else: # a new fragmentation packet
            msg = Message()
            msg.ingest_packet(packet, six_header_len=SIXLOWPAN_FRAG_1_HEADER_LEN)
            in_frag = True
    cap.close()
    return messages

def save_messages_dict_file(pcap_file, messages):
    json_file = pcap_file.replace('.pcap', '_messages.json')
    messages_dict = [msg.to_dict() for msg in messages]
    with open(json_file, 'w') as f:
        f.write(str(messages_dict))
    print(f"Written to {json_file}\n")

def process_messages(pcap_files):
    for pcap_file in pcap_files:
        if 'edhoc' in pcap_file:
            messages = process_edhoc_messages(pcap_file)
        else:
            messages = process_dtls_messages(pcap_file)
        rich.print(messages)
        df_sizes(pcap_file, messages)
        save_messages_dict_file(pcap_file, messages)

if __name__ == '__main__':
    process_messages([
        './results/edhoc.pcap',
        './results/dtls_rpk.pcap',
        './results/dtls_cert.pcap',
    ])
