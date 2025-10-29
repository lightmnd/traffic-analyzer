#!/usr/bin/env python3
"""
STUN Event Extractor - Wireshark-like
"""

import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
import struct

from scapy.all import rdpcap, bind_layers, Raw
from scapy.contrib.stun import STUN
from scapy.layers.inet import IP, UDP


PCAP_DIR = "./pcaps/"
CSV_REPORT = "stun_events_flat.csv"
JSON_REPORT = "stun_events_flat.json"

# STUN Standard Ports
STUN_PORTS = [3478, 5349]

# Associate UDP/STUN layers on known ports for Scapy analysis
for port in STUN_PORTS:
    bind_layers(UDP, STUN, dport=port)
    bind_layers(UDP, STUN, sport=port)

# Utility to create a datetime object
def ts_to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts))


def decode_xor_mapped_address(data: bytes, transaction_id: bytes) -> str | None:
    # Magic Cookie for STUN
    MAGIC_COOKIE = b"\x21\x12\xa4\x42"
    if len(data) < 8:
        return None

    family = data[1]
    # XOR-MAPPED-ADDRESS
    port = struct.unpack("!H", data[2:4])[0]
    xor_port = port ^ struct.unpack("!H", MAGIC_COOKIE[0:2])[0]

    if family == 0x01:  # IPv4 (4 bytes)
        # IP XOR (MAPPED-ADDRESS XOR MAGIC-COOKIE)
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:8], MAGIC_COOKIE))
        ip = ".".join(str(x) for x in ip_bytes)
        return f"{ip}:{xor_port}"

    elif family == 0x02:  # IPv6 (16 bytes)
        # IPv6 XOR (MAPPED-ADDRESS XOR (MAGIC-COOKIE + TRANSACTION-ID))
        xor_mask = MAGIC_COOKIE + transaction_id
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:20], xor_mask))
        ip = ":".join(f"{ip_bytes[i:i + 2].hex()}" for i in range(0, 16, 2))
        return f"[{ip}]:{xor_port}"

    return None


def parse_stun_attributes_flat(udp_payload: bytes) -> Tuple[Dict[str, str], bytes | None, int | None]:
    attributes: Dict[str, str] = {}
    transaction_id = None
    stun_type_code = None

    if len(udp_payload) < 20:
        return attributes, transaction_id, stun_type_code

    try:
        stun_type_code, msg_len = struct.unpack("!HH", udp_payload[0:4])
        magic_cookie = udp_payload[4:8]
        transaction_id = udp_payload[8:20]

        # Verify Magic Cookie STUN (0x2112A442)
        if magic_cookie != b'\x21\x12\xa4\x42':
            return attributes, None, None

        offset = 20  # Start from STUN

        while offset + 4 <= len(udp_payload):
            attr_type, attr_len = struct.unpack("!HH", udp_payload[offset:offset + 4])
            offset += 4

            if offset + attr_len > len(udp_payload):
                break

            attr_value = udp_payload[offset:offset + attr_len]

            # 0x0020: XOR-MAPPED-ADDRESS
            if attr_type == 0x0020:
                decoded = decode_xor_mapped_address(attr_value, transaction_id)
                if decoded:
                    attributes["XOR-MAPPED-ADDRESS"] = decoded

            offset += attr_len
            # Padding handling 32 bit (4 byte)
            offset += (4 - (attr_len % 4)) % 4

    except Exception:
        # Parsing Error
        pass

    return attributes, transaction_id, stun_type_code


def analyze_pcap_file(filepath: str) -> List[Dict[str, Any]]:
    print(f"[*] Analyzing file: {filepath} ...")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[-] Error reading {filepath}: {e}")
        return []

    if not packets:
        print(f"[!] No packets {filepath}")
        return []

    stun_events_flat: List[Dict[str, Any]] = []

    for idx, pkt in enumerate(packets):
        if IP in pkt and UDP in pkt:
            udp_payload = bytes(pkt[UDP].payload)

            attributes, tid, stun_type = parse_stun_attributes_flat(udp_payload)

            if stun_type is not None:
                msg_name = "N/D"
                if stun_type == 0x0001:
                    msg_name = "Binding Request"
                elif stun_type == 0x0101:
                    msg_name = "Binding Success Response"
                elif stun_type == 0x0111:
                    msg_name = "Binding Error Response"
                elif stun_type == 0x0002:
                    msg_name = "Shared Secret Request"
                # Add other types if necessary

                event = {
                    "file": os.path.basename(filepath),
                    "frame_number": idx + 1,
                    "timestamp": ts_to_dt(pkt.time).isoformat(),
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_port": pkt[UDP].sport,
                    "dst_port": pkt[UDP].dport,
                    "stun_message_type_hex": hex(stun_type),
                    "stun_message_name": msg_name,
                    "transaction_id": tid.hex() if tid else "N/D",
                    "xor_mapped_address": attributes.get("XOR-MAPPED-ADDRESS", "N/D"),
                }
                stun_events_flat.append(event)

    print(f"[+] Found {len(stun_events_flat)} STUN events.")
    return stun_events_flat


def write_csv_report(events: List[Dict[str, Any]], csv_path: str):
    if not events:
        print("[!] Nessun evento da scrivere nel CSV.")
        return

    fieldnames = list(events[0].keys())

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames,
                                    delimiter=';')
            writer.writeheader()
            writer.writerows(events)
        print(f"[+] Report CSV  completed - available in {csv_path}")
    except Exception as e:
        print(f"[-] Error writing CSV: {e}")


def write_json_report(events: List[Dict[str, Any]], json_path: str):
    if not events:
        print("[!] No event to write.")
        return

    try:
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(events, fh, indent=2)
        print(f"[+] JSON report available in {json_path}")
    except Exception as e:
        print(f"[-] Error writing JSON: {e}")



def main():
    if not os.path.exists(PCAP_DIR):
        print(f"[-] Directory PCAP {PCAP_DIR} not found. Create one before start scripting.")
        return

    pcap_files = [os.path.join(PCAP_DIR, f)
                  for f in os.listdir(PCAP_DIR)
                  if f.endswith(('.pcap', '.pcapng'))]

    if not pcap_files:
        print(f"[!] No .pcap or .pcapng found in {PCAP_DIR}.")
        return

    all_events_flat: List[Dict[str, Any]] = []

    for pcap in pcap_files:
        analysis = analyze_pcap_file(pcap)
        if analysis:
            all_events_flat.extend(analysis)

    if all_events_flat:
        write_csv_report(all_events_flat, CSV_REPORT)
        write_json_report(all_events_flat, JSON_REPORT)
    else:
        print("[!] No STUN event found.")


if __name__ == '__main__':
    main()
