import pyshark, rich, sys
import pandas as pd
from pyshark.packet.packet import Packet as PysharkPacket
from dataclasses import dataclass, field, asdict, fields
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

@dataclass
class Message:
    packets: List[PysharkPacket] = field(default_factory=list)
    raw: List[bytes] = field(default_factory=list)
    ieee_802154: List[bytes] = field(default_factory=list)
    sixlowpan: List[bytes] = field(default_factory=list)
    coap: List[bytes] = field(default_factory=list)
    content: List[bytes] = field(default_factory=list)

    @property
    def last_raw(self):
        return self.raw[-1]

    @property
    def raw_lens(self):
        return [len(r) for r in self.raw]

    @property
    def direction(self):
        return "🚀" if self.packets[0]['6lowpan'].src == ORIGINATOR_SRC_ADDR else "⬇️"

    @property
    def reassembled(self):
        return b''.join(self.content)

    @property
    def reassembled_len(self):
        return len(self.reassembled)

    def ingest_packet(self, packet, six_header_len=SIXLOWPAN_HEADER_LEN):
        self.packets.append(packet)
        self.add_raw(packet)
        self.add_802154(packet)
        self.add_6lowpan(packet, six_header_len)
        if 'coap' in packet:
            self.add_content_from_coap(packet)
        else:
            self.add_content_from_udp_or_fragment(packet)

    def add_raw(self, packet):
        self.raw.append(bytes.fromhex(packet.wpan_raw.value))

    def add_802154(self, packet):
        self.ieee_802154.append(self.last_raw[:IEEE_802154_HEADER_LEN])

    def add_6lowpan(self, packet, six_header_len):
        self.sixlowpan.append(self.last_raw[IEEE_802154_HEADER_LEN:IEEE_802154_HEADER_LEN+six_header_len])

    def add_content_from_coap(self, packet):
        coap_header_len = int(packet.udp.length) - UDP_HEADER_LEN - coap_payload_len(packet)
        self.coap.append(self.last_raw[IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN:IEEE_802154_HEADER_LEN+SIXLOWPAN_HEADER_LEN+coap_header_len])
        try:
            payload = packet['coap'].payload_raw[0]
            payload = bytes.fromhex(payload)
        except:
            payload = b''
        self.content.append(payload)

    def add_content_from_udp_or_fragment(self, packet):
        offset = len(self.ieee_802154[-1]) + len(self.sixlowpan[-1])
        payload = self.last_raw[offset:]
        self.content.append(payload)

    def __repr__(self):
        field_strs = ', '.join(f"{f.name}={getattr(self, f.name)}" for f in fields(self) if f.name not in ['packets', 'raw'])
        additional_info = f"reassembled={self.reassembled}, direction={self.direction}, raw_lens={self.raw_lens}, reassembled_len={self.reassembled_len}"
        return f"{self.__class__.__name__}({field_strs}, {additional_info})"


def load_edhoc(pcap) -> List[Message]:
    cap = pyshark.FileCapture(pcap, display_filter='coap', use_json=True, include_raw=True)
    messages = []
    for packet in cap:
        msg = Message()
        msg.ingest_packet(packet)
        messages.append(msg)
    rich.print(messages, '\n')
    return messages

def load_dtls(pcap) -> List[Message]:
    cap = pyshark.FileCapture(pcap, display_filter='!icmpv6', use_json=True, include_raw=True)
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
    rich.print(messages, '\n')
    return messages

load_edhoc('./results/edhoc.pcap')
load_dtls('./results/dtls_rpk.pcap')
