#!/usr/bin/env python3
"""
STUN Event Extractor - Wireshark-like
"""

import os
import csv
import json
from datetime import datetime
from itertools import count
from typing import List, Dict, Any, Tuple
import struct

from scapy.all import rdpcap, bind_layers, Raw
from scapy.contrib.rtps import RTPS
from scapy.contrib.stun import STUN, MAGIC_COOKIE
from scapy.layers.inet import IP, UDP, TCP

PCAP_DIR = "./pcaps/"
CSV_REPORT = "stun_events_flat.csv"
JSON_REPORT = "stun_events_flat.json"
STREAM_INFO_REPORT_JSON = "stream_info.json"
STREAM_INFO_REPORT_CSV = "stream_info.csv"

REPORTS_DIR = "./reports"

all_events_flat: List[Dict[str, Any]] = []
collect_stream_info = []
events_ip_port: Dict[Any, Any] = {}

# STUN Standard Ports
# STUN_PORTS = [3478, 5349]

# Associate UDP/STUN layers on known ports for Scapy analysis
# for port in STUN_PORTS:
#     bind_layers(UDP, STUN, dport=port)
#     bind_layers(UDP, STUN, sport=port)

# Utility to create a datetime object
def ts_to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts))

## TO GET XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS
def decode_xor_addresses(data: bytes, transaction_id: bytes) -> str | None:
    # Magic Cookie for STUN
    MAGIC_COOKIE = b"\x21\x12\xa4\x42"
    if len(data) < 8:
        return None

    family = data[1]
    port = struct.unpack("!H", data[2:4])[0]
    xor_port = port ^ struct.unpack("!H", MAGIC_COOKIE[0:2])[0]

    if family == 0x01:  # IPv4 (4 bytes)
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:8], MAGIC_COOKIE))
        ip = ".".join(str(x) for x in ip_bytes)
        return f"{ip}:{xor_port}"

    elif family == 0x02:  # IPv6 (16 bytes)
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
                decoded = decode_xor_addresses(attr_value, transaction_id)
                if decoded:
                    attributes["XOR-MAPPED-ADDRESS_IP"] = decoded.split(":")[0]

                    attributes["XOR-MAPPED-ADDRESS_PORT"] = decoded.split(":")[1]

            # 0x0016 XOR-RELAYED-ADDRESS
            if attr_type == 0x0016:
                decoded = decode_xor_addresses(attr_value, transaction_id)
                if decoded:
                    attributes["XOR-RELAYED-ADDRESS_IP"] = decoded.split(":")[0]
                    attributes["XOR-RELAYED-ADDRESS_PORT"] = decoded.split(":")[1]

            # 0x0012 XOR-PEER-ADDRESS
            if attr_type == 0x0012:
                decoded = decode_xor_addresses(attr_value, transaction_id)
                if decoded:
                    attributes["XOR-PEER-ADDRESS_IP"] = decoded.split(":")[0]
                    attributes["XOR-PEER-ADDRESS_PORT"] = decoded.split(":")[1]

            offset += attr_len
            # Padding handling 32 bit (4 byte)
            offset += (4 - (attr_len % 4)) % 4

    except Exception:
        # Parsing Error
        pass

    return attributes, transaction_id, stun_type_code

def is_rtp_packet(packet):
    if UDP in packet and len(packet[UDP].payload) >= 12:
        payload = bytes(packet[UDP].payload)
        version = (payload[0] >> 6) & 0x03
        payload_type = payload[1] & 0x7F
        if payload_type >= 96 and payload_type <= 127:
            return True
        else:
            return False
    return False

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

    # Dict contains tuple
    list_stream = {}

    for idx, pkt in enumerate(packets):

        if IP in pkt and TCP in pkt:
            tcp_payload = bytes(pkt[TCP].payload)
            if len(tcp_payload) < 20:
                continue

            if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                continue

            magic_cookie = tcp_payload.find(b"\x21\x12\xa4\x42")
            if magic_cookie == -1:
                continue

            stun_index = max(0, magic_cookie -4)
            tcp_range = tcp_payload[stun_index:]

            attributes, tid, stun_type = parse_stun_attributes_flat(tcp_range)

            if stun_type:
                msg_type_class = ((stun_type & 0x0010) >> 4) | ((stun_type & 0x0100) >> 7)
                msg_type_method = (stun_type & 0x000F) | ((stun_type & 0x00E0) >> 1) | ((stun_type & 0x3E00) >> 2)

                event = {
                    "file": os.path.basename(filepath),
                    "frame_number": idx + 1,
                    "timestamp": ts_to_dt(pkt.time).isoformat(),
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "src_port": pkt[TCP].sport,
                    "dst_port": pkt[TCP].dport,
                    "stun_classes": msg_type_class,
                    "stun_method": msg_type_method,
                    "transaction_id": tid.hex() if tid else "N/D",
                    "xor_mapped_address_ip": attributes.get("XOR-MAPPED-ADDRESS_IP", "N/D"),
                    "xor_mapped_address_port": attributes.get("XOR-MAPPED-ADDRESS_PORT", "N/D"),
                    "xor_relayed_address_ip": attributes.get("XOR-RELAYED-ADDRESS_IP", "N/D"),
                    "xor_relayed_address_port": attributes.get("XOR-RELAYED-ADDRESS_PORT", "N/D"),
                    "xor_peer_address_ip": attributes.get("XOR-PEER-ADDRESS_IP", "N/D"),
                    "xor_peer_address_port": attributes.get("XOR-PEER-ADDRESS_PORT", "N/D"),
                }

                stun_events_flat.append(event)

                # Stun over TCP
                create_events_ip_port_list(pkt[IP].src, pkt[TCP].sport)
                create_events_ip_port_list(pkt[IP].dst, pkt[TCP].dport)
                create_events_ip_port_list(attributes.get("XOR-MAPPED-ADDRESS_IP", ""),
                                           attributes.get("XOR-MAPPED-ADDRESS_PORT", ""))
                create_events_ip_port_list(attributes.get("XOR-PEER-ADDRESS_IP", ""),
                                           attributes.get("XOR-PEER-ADDRESS_PORT", ""))
                create_events_ip_port_list(attributes.get("XOR-RELAYED-ADDRESS_IP", ""),
                                           attributes.get("XOR-RELAYED-ADDRESS_PORT", ""))

        if IP in pkt and UDP in pkt:
            udp_payload = bytes(pkt[UDP].payload)


            if is_rtp_packet(pkt):
                # Keys
                key_ls = pkt[IP].src + "__" + str(pkt[UDP].sport) + "||" + pkt[IP].dst + "__" + str(pkt[UDP].dport)

                if key_ls not in list_stream.keys():
                    list_stream[key_ls] = (1, pkt.time, pkt.time)
                else:
                    curr_tup = list_stream[key_ls]
                    list_stream[key_ls] = (curr_tup[0] + 1, curr_tup[1], pkt.time)

            else:
                attributes, tid, stun_type = parse_stun_attributes_flat(udp_payload)

                # get STUN info parsing STUN over TCP

                msg_type_class = None
                msg_type_method = None

                ### split stun type in method and class
                if stun_type:
                    msg_type_class = (( stun_type & 0x0010) >> 4) | ((stun_type & 0x0100) >> 7)
                    msg_type_method = (stun_type & 0x000F) | ((stun_type & 0x00E0) >> 1) | ((stun_type & 0x3E00) >> 2)

                    event = {
                        "file": os.path.basename(filepath),
                        "frame_number": idx + 1,
                        "timestamp": ts_to_dt(pkt.time).isoformat(),
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "src_port": pkt[UDP].sport,
                        "dst_port": pkt[UDP].dport,
                        "stun_classes": msg_type_class,
                        "stun_method": msg_type_method,
                        "transaction_id": tid.hex() if tid else "N/D",
                        "xor_mapped_address_ip": attributes.get("XOR-MAPPED-ADDRESS_IP", "N/D"),
                        "xor_mapped_address_port": attributes.get("XOR-MAPPED-ADDRESS_PORT", "N/D"),
                        "xor_relayed_address_ip": attributes.get("XOR-RELAYED-ADDRESS_IP", "N/D"),
                        "xor_relayed_address_port": attributes.get("XOR-RELAYED-ADDRESS_PORT", "N/D"),
                        "xor_peer_address_ip": attributes.get("XOR-PEER-ADDRESS_IP", "N/D"),
                        "xor_peer_address_port": attributes.get("XOR-PEER-ADDRESS_PORT", "N/D"),
                    }

                    stun_events_flat.append(event)

                    # Stun over UDP
                    create_events_ip_port_list(pkt[IP].src, pkt[UDP].sport)
                    create_events_ip_port_list(pkt[IP].dst, pkt[UDP].dport)
                    create_events_ip_port_list(attributes.get("XOR-MAPPED-ADDRESS_IP", ""), attributes.get("XOR-MAPPED-ADDRESS_PORT", ""))
                    create_events_ip_port_list(attributes.get("XOR-PEER-ADDRESS_IP", ""), attributes.get("XOR-PEER-ADDRESS_PORT", ""))
                    create_events_ip_port_list(attributes.get("XOR-RELAYED-ADDRESS_IP", ""), attributes.get("XOR-RELAYED-ADDRESS_PORT", ""))

                    # events_ip_port.append()

                    ### stun classes
                    # define STUN_REQUEST 0x0
                    # define STUN_INDICATION 0x01
                    # define STUN_SUCCESS_RESPONSE 0x02
                    # define STUN_ERROR_RESPONSE 0x03

                    ### method
                    # define STUN_BINDING 0x0001
                    # define STUN_ALLOCATE 0x0003
                    # define STUN_SEND 0x0006
                    # define STUN_CREATEPERMISSION 0x0008
    print(f"Events IP:PORT(s): {events_ip_port}")

    # get_stream(list_stream)
    print(f"[+] Found {len(stun_events_flat)} STUN events.")
    return stun_events_flat

def create_events_ip_port_list(ip, port):
    if ip != '' and port != '':
        port_int = int(port)
        if ip not in events_ip_port:
            events_ip_port[ip] = [port_int]
        else:
            if port_int not in events_ip_port[ip]:
                events_ip_port[ip].append(port_int)

def create_conversation_contact_points():
    for ip, ports in events_ip_port.items():
        target_public_ip_found = False
        peer_ip_found = False
        target_ip_found = False
        is_stun_server = False

        if 3478 in ports:
            is_stun_server = True

        if not is_stun_server:
            for item in all_events_flat:
                # Check target ip not with 3478 port
                if ((item['src_ip'] == ip) and (item['dst_port'] == 3478)) or ((item['dst_ip'] == ip) and (item['src_port'] == 3478)):
                    print(f'Target IP: {ip}')
                    target_ip_found = True
                    break

        if not target_ip_found and not is_stun_server:
            for item_two in all_events_flat:
                # CHeck if attribute is present
                if (item_two['src_port'] == 3478) and (item_two['xor_mapped_address_ip'] == ip):
                    print(f'Target Public IP: {ip}')
                    target_public_ip_found = True
                    break

        if not target_public_ip_found and not target_ip_found and not is_stun_server:
            for item_three in all_events_flat:
                # Check peer address
                if (item_three['stun_classes'] == 0 and item_three['stun_method']  == 1) and (item_three['dst_ip'] == ip):
                    print(f'Peer Address IP: {ip}')
                    peer_ip_found = True
                    break

        if target_ip_found == False and not is_stun_server and target_public_ip_found == False and peer_ip_found == False:
            print(ip, ports)

def get_stream(list_stream: Dict):
    sorted_stream = sorted(list_stream.items(), key=lambda item: item[1][0], reverse=True)[:2]
    print("sorted stream ->", sorted_stream)
    stream_ip_port = sorted_stream[0][0].split("||")
    if stream_ip_port[1] + "||" + stream_ip_port[0] == sorted_stream[1][0]:
        duration_1 = sorted_stream[0][1][2] - sorted_stream[0][1][1]
        duration_2 = sorted_stream[1][1][2] - sorted_stream[1][1][1]

        global collect_stream_info
        collect_stream_info = [{"duration_1":str(duration_1)}, {"duratoin_2": str(duration_2)},
                               {"stream_ip_port[0]": stream_ip_port[0].replace("__", ":")},
                               {"stream_ip_port[1]": stream_ip_port[1].replace("__", ":")}]

        print(f"Collected Stream Info: {collect_stream_info}")

def write_csv_report(events: List[Dict[str, Any]], csv_path: str):
    if not csv_path.startswith(REPORTS_DIR):
        csv_path = os.path.join(REPORTS_DIR, csv_path)

    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

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
    if not json_path.startswith(REPORTS_DIR):
        json_path = os.path.join(REPORTS_DIR, json_path)

    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    if not events:
        print("[!] No event to write.")
        return

    try:
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(events, fh, indent=2)
        print(f"[+] JSON report available in {json_path}")
    except Exception as e:
        print(f"[-] Error writing JSON: {e}")

def write_stream_info_json(json_path: str):
    if not json_path.startswith(REPORTS_DIR):
        json_path = os.path.join(REPORTS_DIR, json_path)

    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    try:
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(collect_stream_info, fh, indent=2)

        print(f"[+] Stream Info JSON report available in {json_path}")
    except Exception as e:
        print(f"[-] Error writing Stream Info JSON: {e}")

def write_stream_info_csv(csv_path: str):
    if not csv_path.startswith(REPORTS_DIR):
        csv_path = os.path.join(REPORTS_DIR, csv_path)

    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    fieldnames = set()
    for item in collect_stream_info:
        if isinstance(item, dict):
            fieldnames.update(item.keys())

    fieldnames = list(fieldnames)
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames,
                                    delimiter=';')
            writer.writeheader()
            writer.writerows(collect_stream_info)
            print(f"[+] Stream Info CSV  completed - available in {csv_path}")
    except Exception as e:
        print(f"[-] Error writing Stream Info CSV: {e}")

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

    for pcap in pcap_files:
        analysis = analyze_pcap_file(pcap)
        if analysis:
            all_events_flat.extend(analysis)

    write_stream_info_json(STREAM_INFO_REPORT_JSON)
    write_stream_info_csv(STREAM_INFO_REPORT_CSV)

    if all_events_flat:
        write_csv_report(all_events_flat, CSV_REPORT)
        write_json_report(all_events_flat, JSON_REPORT)
    else:
        print("[!] No STUN event found.")

    # Create and highlight the conversation involved parts (Targets, Peers, ...)
    create_conversation_contact_points()

if __name__ == '__main__':
    main()
