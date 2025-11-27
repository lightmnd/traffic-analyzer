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
from collections import Counter
from scapy.all import rdpcap, bind_layers, Raw
from scapy.contrib.rtps import RTPS
from scapy.contrib.stun import STUN, MAGIC_COOKIE
from scapy.layers.inet import IP, UDP, TCP
from datetime import datetime
from ipaddress import IPv4Address
from rich.console import Console

console = Console()

PCAP_DIR = "./pcaps/"
IP_RANGES_DIR = "./ip_ranges/"
REPORTS_DIR = "./reports"
CSV_REPORT = "stun_events_flat.csv"
JSON_REPORT = "stun_events_flat.json"
STREAM_INFO_REPORT_JSON = "stream_info.json"
STREAM_INFO_REPORT_CSV = "stream_info.csv"


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

        count = 0
        while offset + 4 <= len(udp_payload):
            count += 1
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

            # 0x0014 REALM
            if attr_type == 0x0014:
                try:
                    decoded = attr_value
                    if decoded:
                        attributes["REALM"] = decoded.decode("utf-8")
                except UnicodeDecodeError:
                    print('here exception')

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
    print(f"⌛  Analyzing file: {filepath} ...")

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

        # GET STUN  over TCP
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
                    "transaction_id": tid.hex() if tid else "",
                    "xor_mapped_address_ip": attributes.get("XOR-MAPPED-ADDRESS_IP", ""),
                    "xor_mapped_address_port": attributes.get("XOR-MAPPED-ADDRESS_PORT", ""),
                    "xor_relayed_address_ip": attributes.get("XOR-RELAYED-ADDRESS_IP", ""),
                    "xor_relayed_address_port": attributes.get("XOR-RELAYED-ADDRESS_PORT", ""),
                    "xor_peer_address_ip": attributes.get("XOR-PEER-ADDRESS_IP", ""),
                    "xor_peer_address_port": attributes.get("XOR-PEER-ADDRESS_PORT", ""),
                    "realm": attributes.get("REALM")
                }

                stun_events_flat.append(event)

                create_events_ip_port_list(pkt[IP].src, pkt[TCP].sport, ts_to_dt(pkt.time).isoformat())
                create_events_ip_port_list(pkt[IP].dst, pkt[TCP].dport, ts_to_dt(pkt.time).isoformat())
                create_events_ip_port_list(attributes.get("XOR-MAPPED-ADDRESS_IP", ""),
                                           attributes.get("XOR-MAPPED-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())
                create_events_ip_port_list(attributes.get("XOR-PEER-ADDRESS_IP", ""),
                                           attributes.get("XOR-PEER-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())
                create_events_ip_port_list(attributes.get("XOR-RELAYED-ADDRESS_IP", ""),
                                           attributes.get("XOR-RELAYED-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())

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
                        "transaction_id": tid.hex() if tid else "",
                        "xor_mapped_address_ip": attributes.get("XOR-MAPPED-ADDRESS_IP", ""),
                        "xor_mapped_address_port": attributes.get("XOR-MAPPED-ADDRESS_PORT", ""),
                        "xor_relayed_address_ip": attributes.get("XOR-RELAYED-ADDRESS_IP", ""),
                        "xor_relayed_address_port": attributes.get("XOR-RELAYED-ADDRESS_PORT", ""),
                        "xor_peer_address_ip": attributes.get("XOR-PEER-ADDRESS_IP", ""),
                        "xor_peer_address_port": attributes.get("XOR-PEER-ADDRESS_PORT", ""),
                        "realm": attributes.get("REALM")
                    }

                    stun_events_flat.append(event)

                    # Stun over UDP
                    create_events_ip_port_list(pkt[IP].src, pkt[UDP].sport, ts_to_dt(pkt.time).isoformat())
                    create_events_ip_port_list(pkt[IP].dst, pkt[UDP].dport, ts_to_dt(pkt.time).isoformat())
                    create_events_ip_port_list(attributes.get("XOR-MAPPED-ADDRESS_IP", ""), attributes.get("XOR-MAPPED-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())
                    create_events_ip_port_list(attributes.get("XOR-PEER-ADDRESS_IP", ""), attributes.get("XOR-PEER-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())
                    create_events_ip_port_list(attributes.get("XOR-RELAYED-ADDRESS_IP", ""), attributes.get("XOR-RELAYED-ADDRESS_PORT", ""), ts_to_dt(pkt.time).isoformat())

                    # STUN REFERENCES
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

    console.print(f"✅ Found {len(stun_events_flat)} STUN events.")
    console.print(f"ℹ️  Events IPs:PORTs: {events_ip_port}")
    get_stream(list_stream)

    sorted_ip_occurrences_by_key = sorted(ip_occurrences.items(), key=lambda x: x[1], reverse=True)
    console.print(f"ℹ️  IP occurrences: {dict(sorted_ip_occurrences_by_key)}")
    console.print(f"ℹ️  IP By Timestamp: {ip_by_timestamp}")

    console.print(f"ℹ️  Last Counted IP: {last_counted_ip}")

    return stun_events_flat


# Parse Telegram IP Ranges from CSV if exists
ip_ranges = {}
def parse_tg_ip_ranges() -> Dict[str, List[str]]:
    global ip_ranges
    for filename in os.listdir(IP_RANGES_DIR):
        if filename.endswith(".csv"):
            with open(os.path.join(IP_RANGES_DIR, filename), "r") as fh:
                reader = csv.reader(fh)
                for row in reader:
                    ip_ranges[row[0]] = row[0:2]
    return ip_ranges

ip_occurrences = Counter()
last_counted_ip = None
ip_by_timestamp = {}
def create_events_ip_port_list(ip, port, ts):
    global last_counted_ip, ip_by_timestamp
    if ip != '' and port != '':
        port_int = int(port)

        ip_occurrences[ip] += 1
        ip_by_timestamp[ip] = ts
        
        ordered_data = sorted(ip_by_timestamp.items(), key = lambda x:datetime.fromisoformat(x[1]), reverse=True)
        ip_by_timestamp = dict(ordered_data)
        
        # Update to the IP with the most recent timestamp across all packets processed
        if ip_by_timestamp:
            most_recent_ip = max(ip_by_timestamp.items(), key=lambda x: datetime.fromisoformat(x[1]))[0]
            last_counted_ip = most_recent_ip
                    
        if ip not in events_ip_port:
            events_ip_port[ip] = [port_int]
        else:
            if port_int not in events_ip_port[ip]:
                events_ip_port[ip].append(port_int)
   
def identify_tg_ranges(ip) -> bool:
    tg_ranges_subset = parse_tg_ip_ranges().values()
    if tg_ranges_subset:
        for tg_range in tg_ranges_subset:
            if IPv4Address(ip) >= IPv4Address(tg_range[0]) and IPv4Address(ip) <= IPv4Address(tg_range[1]):
                return True
    return False

peer_addresses_list = {}
peer_sorted_by_timestamp_and_occurences = {}

def create_conversation_contact_points():
    global peer_addresses_list, peer_sorted_by_timestamp_and_occurences
    
    # Variables reset
    peer_addresses_list = {}
    peer_sorted_by_timestamp_and_occurences = {} 
    
    for ip, ports in events_ip_port.items():
        target_public_ip_found = False
        peer_ip_found = False
        xor_peer_address_found = False
        xor_relayed_address_found = ""
        peer_address_found_present = False
        target_ip_found = False
        is_stun_server = False

        # Standard port
        if 3478 in ports:
            is_stun_server = True

        # Telegram port(s)
        if 1400 in ports:
            is_stun_server = True
            
        # Telegram IP ranges to skip
        tg_ranges = identify_tg_ranges(ip)
        if tg_ranges:
            is_stun_server = True
            
        if not is_stun_server:
            for item in all_events_flat:
                # Check target ip not with 3478 port
                if ((item['src_ip'] == ip) and (item['dst_port'] == 3478 or item['dst_port'] == 1400)) or ((item['dst_ip'] == ip) and (item['src_port'] == 3478 or item['src_port'] == 1400) and is_private_ip(ip)):
                    console.print(f'🎯 Target Private IP: {ip}', style="dodger_blue1")
                    target_ip_found = True
                    break

        if not target_ip_found and not is_stun_server:
            for item_two in all_events_flat:
                # Check if attribute is present
                if (item_two['src_port'] == 3478 or item_two['src_port'] == 1400) and (item_two['xor_mapped_address_ip'] == ip and not is_private_ip(ip)):
                    console.print(f'🎯 Target Public IP: {ip}', style="dodger_blue1")
                    target_public_ip_found = True
                    break

        if not target_public_ip_found and not target_ip_found and not is_stun_server:
            for item_three in all_events_flat:
                # Check peer address
                if (item_three['stun_classes'] == 0 and item_three['stun_method']  == 1) and (item_three['dst_ip'] == ip and not is_private_ip(ip)):
                    peer_ip_found = True
                if item_three['xor_peer_address_ip'] != '':
                    peer_address_found_present = True
                    if item_three['xor_peer_address_ip'] == ip:
                        xor_peer_address_found = True

                if item_three['xor_relayed_address_ip'] == ip:
                    xor_relayed_address_found = ip

            occ_count = ip_occurrences.get(ip, 0)
            
            # Eg: WathsApp or LAN Telegram call
            if peer_ip_found and not peer_address_found_present and not xor_relayed_address_found:
                if not is_private_ip(ip):
                    peer_addresses_list[ip] = occ_count
                    console.print(f'🟢 Peer Address IP (WathsApp or LAN Telegram call): {ip}',  style="bold blue", end="")
            # Eg: Telegram or other apps
            elif peer_ip_found and peer_address_found_present and xor_peer_address_found and not xor_relayed_address_found:

                stream_ip_1 = collect_stream_info[2]['stream_ip_port[0]'].split(':')[0] if len(collect_stream_info) > 2 else ""
                stream_ip_2 = collect_stream_info[3]['stream_ip_port[1]'].split(':')[0] if len(collect_stream_info) > 3 else ""

                # This scenario can keep track of a multiple Signal App used for the same account is running on different devices
                if ip != stream_ip_1 and ip != stream_ip_2: 
                    if not is_private_ip(ip):
                        peer_addresses_list[ip] = occ_count
                        console.print(f'🟢 Peer Address IP (Others): {ip}', style="bold green")
                else:
                    peer_addresses_list[ip] = occ_count
                    console.print(f'🟢 Peer Address IP (PRINCIPAL): {ip}', style="bold green")
            else:
                # This block captures the IPs that are not included in the WA/Others/Signal category.
                # Here we are excluding the Relay Server without printing it
                pass
        if target_ip_found == False and not is_stun_server and target_public_ip_found == False and peer_ip_found == False:
            console.print('⚠️  Unknown, no IP, no STUN, not an important address: ', ip, ports, style="bright_yellow", end="")
            
        peer_addresses_list_sorted = sorted(peer_addresses_list.items(), key = lambda x:x[1], reverse=True)
        
        for ip_item, i in peer_addresses_list_sorted:
            if ip_item in ip_by_timestamp:
                peer_sorted_by_timestamp_and_occurences[i] = ip_item
                
        peer_sorted_by_timestamp_and_occurences = dict(sorted(peer_sorted_by_timestamp_and_occurences.items(), key=lambda x:x[0], reverse=True))

    # print(f"ℹ️ Peer Addresses List (the most frequent and recent): {peer_sorted_by_timestamp_and_occurences}",)
    console.print("ℹ️  Peer Addresses List (the most frequent and recent): ", peer_sorted_by_timestamp_and_occurences, style="bold green", end="")

def is_private_ip(ip_addr):    
    
    # Exception for Private IP directly involved in the Stream
    # In this case we have to consider it as a valid Peer Address
    ip_1_list = [stream_info.get("stream_ip_port[0]").split(":")[0] for stream_info in collect_stream_info if "stream_ip_port[0]" in stream_info]
    ip_2_list = [stream_info.get("stream_ip_port[1]").split(":")[0] for stream_info in collect_stream_info if "stream_ip_port[1]" in stream_info]
    if ip_addr in ip_1_list or ip_addr in ip_2_list:
        return False
            
    ip_parse= ip_addr.split(".")
    if len(ip_parse) >= 4:
        if int(ip_parse[0]) == 10:
            return True
        if int(ip_parse[0]) == 100 and 64 <= int(ip_parse[1]) <= 127:
            return True
        if int(ip_parse[0]) == 172 and 16 <= int(ip_parse[1]) <= 31:
            return True
        if int(ip_parse[0]) == 192 and int(ip_parse[1]) == 0 and int(ip_parse[2]) == 0:
            return True
        if int(ip_parse[0]) == 192 and int(ip_parse[1]) == 168:
            return True
        if int(ip_parse[0]) == 198 and 18 <= int(ip_parse[1]) <= 19:
            return True

    return False

def get_stream(list_stream: Dict):
    global last_counted_ip
    sorted_stream = sorted(list_stream.items(), key=lambda item: item[1][0], reverse=True)[:2]
    stream_ip_port = sorted_stream[0][0].split("||")
    if stream_ip_port[1] + "||" + stream_ip_port[0] == sorted_stream[1][0]:
        duration_1 = sorted_stream[0][1][2] - sorted_stream[0][1][1]
        duration_2 = sorted_stream[1][1][2] - sorted_stream[1][1][1]
        ip_1 = stream_ip_port[0].replace("__", ":")
        ip_2 = stream_ip_port[1].replace("__", ":")
        
        timestamp_1 = sorted_stream[0][1][1]
        timestamp_2 = sorted_stream[1][1][1]
        
        # Determine which stream started later (more recent)
        if timestamp_1 >= timestamp_2:
            last_counted_ip = ip_1.split(":")[0]  # Extract just the IP part
        else:
            last_counted_ip = ip_2.split(":")[0]  # Extract just the IP part
        
        global collect_stream_info
        collect_stream_info = [{"duration_1":str(duration_1)}, 
                               {"duratoin_2": str(duration_2)},
                               {"stream_ip_port[0]": ip_1},
                               {"stream_ip_port[1]": ip_2}
        ]
        console.print(f"📞 Collected Stream Info: {collect_stream_info}", style="dodger_blue1")

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
        print(f"✅ Report CSV  completed - available in {csv_path}")
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
        print(f"✅ JSON report available in {json_path}")
    except Exception as e:
        print(f"[-] Error writing JSON: {e}")

def write_stream_info_json(json_path: str):
    if not json_path.startswith(REPORTS_DIR):
        json_path = os.path.join(REPORTS_DIR, json_path)

    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    try:
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(collect_stream_info, fh, indent=2)

        print(f"✅ Stream Info JSON report available in {json_path}")
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
            print(f"✅ Stream Info CSV  completed - available in {csv_path}")
    except Exception as e:
        print(f"[-] Error writing Stream Info CSV: {e}")

def main():
    
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    if not os.path.exists(IP_RANGES_DIR):
        print(f"[-] Directory IP Ranges {IP_RANGES_DIR} not found. Create one before start scripting.")
        return
    
    # Parse IP Ranges
    parse_tg_ip_ranges()    
   


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

    # Create and highlight the conversation involved parts (Targets, Peers, ...)
    create_conversation_contact_points()
    
    # Write Reports as JSON and CSV
    write_stream_info_json(STREAM_INFO_REPORT_JSON)
    write_stream_info_csv(STREAM_INFO_REPORT_CSV)

    if all_events_flat:
        write_csv_report(all_events_flat, CSV_REPORT)
        write_json_report(all_events_flat, JSON_REPORT)
    else:
        print("[!] No STUN event found.")


if __name__ == '__main__':
    main()
