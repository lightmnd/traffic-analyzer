#!/usr/bin/env python3
"""
VoIP & STUN Flow Analyzer

This script scans a directory of PCAP/PCAPNG files and extracts STUN/TURN events
and heuristically reconstructs VoIP call summaries. It produces two artifacts:
 - voip_calls_summary.csv  (human-readable table)
 - voip_analysis.json      (detailed JSON structured analysis)

Comments and variable names are in English as requested.

Usage:
 - put your .pcap / .pcapng files into the PCAP_DIR (default: ./pcaps/)
 - run: python3 voip_stun_analyzer.py

Requirements:
 - scapy with contrib modules (scapy.contrib.stun)

"""

import os
import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any
import ipaddress
import struct

from scapy.all import rdpcap, IP, UDP, bind_layers, Raw
from scapy.contrib.stun import STUN

# ---------------------------
# Configuration
# ---------------------------
PCAP_DIR = "./pcaps/"
CSV_REPORT = "voip_calls_summary.csv"
JSON_REPORT = "voip_analysis.json"

# Known STUN/TURN ports (common ones + Google public STUN ports)
STUN_PORTS = [3478, 5349, 19302, 19305, 19307, 19308]

# Bind STUN layer to UDP on known ports to help Scapy parse STUN
for port in STUN_PORTS:
    bind_layers(UDP, STUN, dport=port)
    bind_layers(UDP, STUN, sport=port)

# ---------------------------
# Utility helpers
# ---------------------------

def is_private_ip(ip: str) -> bool:
    """Return True if the IP is private (RFC1918 or IPv6 unique local)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def ts_to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts))


# Robust extraction of STUN attributes from the parsed STUN layer
def get_stun_attributes(stun_layer: STUN) -> Dict[str, str]:
    """Extract STUN attributes and decode XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS."""
    attributes: Dict[str, str] = {}

    TYPE_MAP = {
        0x0001: "MAPPED-ADDRESS",
        0x0020: "XOR-MAPPED-ADDRESS",
        0x0012: "RESPONSE-ORIGIN-ADDRESS",
        0x0014: "OTHER-ADDRESS",
        0x0016: "XOR-PEER-ADDRESS",
        0x0021: "XOR-RELAYED-ADDRESS",
    }

    current = getattr(stun_layer, 'payload', None)
    if current is None or getattr(current, 'name', 'Raw') == 'Raw':
        return attributes

    while current:
        try:
            attr_type = getattr(current, 'type', None)
            attr_value = getattr(current, 'value', None)
            if attr_type is None or attr_value is None:
                break

            # Decode XOR attributes
            if attr_type in (0x0020, 0x0016):  # XOR-MAPPED-ADDRESS or XOR-PEER-ADDRESS
                result = decode_xor_mapped_address(bytes(attr_value), getattr(stun_layer, 'id', b''))
                if result:
                    ip, port = result
                    attributes[TYPE_MAP[attr_type]] = ip

            # Normal non-XOR attributes (if Scapy parsed them)
            elif hasattr(current, 'addr') and attr_type in TYPE_MAP:
                attributes[TYPE_MAP[attr_type]] = current.addr

        except Exception:
            pass

        # Move to next TLV payload
        nxt = getattr(current, 'payload', None)
        if nxt and getattr(nxt, 'name', 'Raw') != 'Raw':
            current = nxt
        else:
            break

    return attributes



def find_most_common_private_ip(packets) -> str:
    """Return the most frequently seen private IP address in the pcap (best guess for local device).

    If no private IP is found, returns a sentinel string 'N/D (No Private IP Found)'.
    """
    counts = defaultdict(int)
    for pkt in packets:
        if IP in pkt:
            s = pkt[IP].src
            d = pkt[IP].dst
            if is_private_ip(s):
                counts[s] += 1
            if is_private_ip(d):
                counts[d] += 1

    if not counts:
        return "N/D (No Private IP Found)"
    return max(counts, key=counts.get)


def parse_stun_attributes(raw_data: bytes, transaction_id: bytes) -> dict:
    """Parse STUN attributes manually from raw bytes."""
    attrs = {}
    offset = 20  # STUN header is 20 bytes (type, length, magic cookie, transaction ID)

    while offset + 4 <= len(raw_data):
        attr_type, attr_len = struct.unpack("!HH", raw_data[offset:offset+4])
        offset += 4
        if offset + attr_len > len(raw_data):
            break
        attr_value = raw_data[offset:offset+attr_len]
        offset += attr_len
        offset += (4 - (attr_len % 4)) % 4  # padding to 4 bytes

        if attr_type in (0x0001, 0x0020):  # MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
            decoded = decode_xor_mapped_address(attr_value, transaction_id)
            if decoded:
                attrs["XOR-MAPPED-ADDRESS"] = decoded

    return attrs


def decode_xor_mapped_address(data: bytes, transaction_id: bytes) -> str | None:
    """Decode XOR-MAPPED-ADDRESS according to RFC 8489."""
    if len(data) < 8:
        return None

    family = data[1]
    port = struct.unpack("!H", data[2:4])[0]
    xor_port = port ^ 0x2112

    if family == 0x01:  # IPv4
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:8], b"\x21\x12\xa4\x42"))
        ip = ".".join(str(x) for x in ip_bytes)
        return f"{ip}:{xor_port}"

    elif family == 0x02:  # IPv6
        xor_mask = b"\x21\x12\xa4\x42" + transaction_id
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:20], xor_mask))
        ip = ":".join(f"{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}" for i in range(0, 16, 2))
        return f"{ip}:{xor_port}"

    return None



# Heuristic to guess the VoIP app based on ports and server hints
def guess_voip_app(server_ips: List[str], seen_ports: List[int]) -> str:
    """Return a best-effort guess of the application used for VoIP.

    This is heuristic — combine STUN ports, well-known port ranges, and server IP hints.
    """
    ports = set(seen_ports)

    # Simple heuristics
    if 19302 in ports or 19305 in ports:
        return "WebRTC / Google STUN"
    if any(p in ports for p in range(8801, 8820)):
        return "Zoom"
    if 3478 in ports or 5349 in ports:
        # Many services (Teams, WhatsApp, generic STUN/TURN) use 3478/5349
        return "Generic STUN/TURN (possible Teams/WhatsApp/other)"

    # ASN or IP-based hints (weak): e.g., Google ranges -> WebRTC, Microsoft ranges -> Teams
    for ip in server_ips:
        try:
            if ip.startswith('172.') or ip.startswith('74.'):
                # weak hint only
                return "WebRTC / browser-based client"
        except Exception:
            pass

    return "Unknown"


def detect_rtp_like_streams(packets, local_ip: str) -> List[Dict[str, Any]]:
    """Detect UDP streams that look like RTP based on simple heuristics.

    Heuristics used:
    - UDP packets to/from local_ip
    - Destination or source port often > 10000 (many RTP ports are ephemeral)
    - Payload length typical of RTP (> 12 bytes; not pure STUN)

    Returns a list of stream summaries (one item per packet match). The script aggregates counts later.
    """
    streams = []

    for pkt in packets:
        if IP in pkt and UDP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            if (src == local_ip or dst == local_ip) and not pkt.haslayer(STUN):
                payload_len = len(bytes(pkt[UDP].payload))
                if payload_len > 12 and (sport > 10000 or dport > 10000):
                    streams.append({
                        'time': pkt.time,
                        'src': src,
                        'dst': dst,
                        'sport': sport,
                        'dport': dport,
                        'payload_len': payload_len,
                    })
    return streams


# ---------------------------
# Main per-file analysis
# ---------------------------

def analyze_pcap_file(filepath: str) -> Dict[str, Any]:
    """Analyze a single pcap file and return a structured summary for JSON and CSV.

    The return value is a dict containing both high-level summary fields and a detailed 'events' list.
    """
    print(f"[*] Analyzing file: {filepath} ...")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[-] Error reading {filepath}: {e}")
        return {}

    if not packets:
        print(f"[!] No packets in {filepath}")
        return {}

    local_ip = find_most_common_private_ip(packets)
    print(f"    [i] Guessed local private IP: {local_ip}")

    first_ts = packets[0].time
    last_ts = packets[-1].time
    start_dt = ts_to_dt(first_ts)
    end_dt = ts_to_dt(last_ts)
    duration_sec = int(round(last_ts - first_ts))

    # Aggregate flows keyed by (local_ip, remote_ip)
    flows = {}
    seen_server_ips = set()
    seen_ports = set()
    all_events = []

    for idx, pkt in enumerate(packets):
        if IP in pkt and UDP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            # Only consider traffic that involves the guessed local private IP
            if local_ip not in (src, dst):
                continue

            # Normalize flow so that (local, remote) is key
            if src == local_ip:
                flow_key = (local_ip, dst)
                direction = "outbound"
                remote_ip = dst
            else:
                flow_key = (local_ip, src)
                direction = "inbound"
                remote_ip = src

            seen_server_ips.add(remote_ip)
            seen_ports.update([sport, dport])

            if flow_key not in flows:
                # The tuple becomes the key for this flow
                flows[flow_key] = {
                    "file": os.path.basename(filepath),
                    "device_private_ip": local_ip,
                    "device_public_ip": "Not Found",
                    "server_ip": remote_ip,
                    "server_port": dport,
                    "peer_public_ip": "Not Found",
                    "stun_events": [],
                    "first_packet_time": pkt.time,
                    "last_packet_time": pkt.time,
                }

            # Update first/last timestamps
            flows[flow_key]["last_packet_time"] = pkt.time
            if pkt.time < flows[flow_key]["first_packet_time"]:
                flows[flow_key]["first_packet_time"] = pkt.time

            # --- ✅ Begin STUN parsing section ---
            if UDP in pkt:
                udp_payload = bytes(pkt[UDP].payload)
                # Check if the UDP payload is enough to contain a STUN message
                if len(udp_payload) >= 20:
                    stun_type_code = struct.unpack("!H", udp_payload[0:2])[0]
                    # stun_msg_length = struct.unpack("!H", udp_payload[2:4])[0]
                    # magic_cookie = struct.unpack("!I", udp_payload[4:8])[0]
                    transaction_id = udp_payload[8:20]

                    # Solo Binding Success Response
                    if stun_type_code == 0x0101:  # 0x0101 = Binding Success Response
                        offset = 20
                        attrs = {}
                        while offset + 4 <= len(udp_payload):
                            attr_type, attr_len = struct.unpack("!HH", udp_payload[offset:offset+4])
                            attr_value = udp_payload[offset+4:offset+4+attr_len]

                            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                                public_ip = decode_xor_mapped_address(attr_value, transaction_id)
                                attrs["XOR-MAPPED-ADDRESS"] = public_ip
                                flows[flow_key]["device_public_ip"] = public_ip
                                print(f"    [✓] Found XOR-MAPPED-ADDRESS: {public_ip}")

                            # Passa all'attributo successivo con padding a 4 byte
                            offset += 4 + attr_len
                            if attr_len % 4 != 0:
                                offset += 4 - (attr_len % 4)

                        # Aggiungi evento STUN al flow
                        flows[flow_key]["stun_events"].append({
                            "packet_index": idx + 1,
                            "time": ts_to_dt(pkt.time).isoformat(),
                            "direction": direction,
                            "stun_message_type": stun_type_code,
                            "stun_message_name": "Binding Success Response",
                            "attributes": attrs
                        })
            # --- End STUN parsing section ---


            else:
                # Non-STUN UDP packet involving local IP -> candidate RTP/RTCP
                # We'll analyze RTP-like streams later in batch
                pass

    # Detect RTP-like streams for the whole file (per local IP)
    rtp_streams = detect_rtp_like_streams(packets, local_ip)

    # Prepare per-flow summaries to return
    flow_summaries = []

    for (local, remote), f in flows.items():
        # Convert first/last packet times to isoformat
        start_time = ts_to_dt(f['first_packet_time']).isoformat()
        end_time = ts_to_dt(f['last_packet_time']).isoformat()
        duration = int(round(f['last_packet_time'] - f['first_packet_time']))

        # If peer_public_ip wasn't found in STUN attributes, attempt to infer from remote IP
        peer_ip_final = f['peer_public_ip'] if f['peer_public_ip'] != 'Not Found' else remote

        # Count RTP-like packets for this flow
        rtp_count = sum(1 for s in rtp_streams if (s['src'] == local and s['dst'] == remote) or (s['src'] == remote and s['dst'] == local))

        app_guess = guess_voip_app(list(seen_server_ips), list(seen_ports))

        # Build flow summary
        # Set filename one time only (per flow) in the
        
        summary = {
            'file': f['file'],
            'start_time': start_time,
            'end_time': end_time,
            'duration_seconds': duration,
            'device_private_ip': f['device_private_ip'],
            'device_public_ip': f['device_public_ip'],
            'server_ip': f['server_ip'],
            'server_port': dport,
            'peer_public_ip': peer_ip_final,
            'voip_app_guess': app_guess,
            'rtp_packets_detected': rtp_count,
            'stun_event_count': len(f['stun_events']),
            'stun_events': f['stun_events'],
        }

        flow_summaries.append(summary)

    # Build final JSON structure for this file
    file_analysis = {
        'file': os.path.basename(filepath),
        'analysis_generated_at': datetime.utcnow().isoformat() + 'Z',
        'pcap_start_time': start_dt.isoformat(),
        'pcap_end_time': end_dt.isoformat(),
        'pcap_duration_seconds': duration_sec,
        'guessed_device_private_ip': local_ip,
        'detected_rtp_like_packets_total': len(rtp_streams),
        'flows': flow_summaries,
        'notable_events': all_events,
    }

    return file_analysis


# ---------------------------
# Reporting: CSV and JSON
# ---------------------------

def write_csv_summary(all_flow_records: List[Dict[str, Any]], csv_path: str):
    """Write a compact CSV table summarizing detected VoIP flows across files."""
    if not all_flow_records:
        print("[!] No records to write to CSV.")
        return

    fieldnames = [
        'file', 'start_time', 'end_time', 'duration_seconds',
        'device_private_ip', 'device_public_ip', 'server_ip', 'server_port', 'peer_public_ip',
        'voip_app_guess', 'rtp_packets_detected', 'stun_event_count'
    ]

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            for rec in all_flow_records:

                # Some JSON file records contain nested flows; flatten
                for flow in rec.get('flows', []):
                    writer.writerow({k: flow.get(k, '') for k in fieldnames})
        print(f"[+] CSV summary written to {csv_path}")
    except Exception as e:
        print(f"[-] Error writing CSV: {e}")


def write_json_report(all_file_analyses: List[Dict[str, Any]], json_path: str):
    try:
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(all_file_analyses, fh, indent=2)
        print(f"[+] JSON analysis written to {json_path}")
    except Exception as e:
        print(f"[-] Error writing JSON: {e}")


# ---------------------------
# Main orchestration
# ---------------------------

def main():
    if not os.path.exists(PCAP_DIR):
        print(f"[-] PCAP directory {PCAP_DIR} not found. Create it and place your .pcap/.pcapng files inside.")
        return

    pcap_files = [os.path.join(PCAP_DIR, f)
                  for f in os.listdir(PCAP_DIR)
                  if f.endswith(('.pcap', '.pcapng'))]

    if not pcap_files:
        print(f"[!] No .pcap or .pcapng files found in {PCAP_DIR}.")
        return

    all_file_analyses = []

    for pcap in pcap_files:
        analysis = analyze_pcap_file(pcap)
        if analysis:
            all_file_analyses.append(analysis)

    # Write reports
    write_csv_summary(all_file_analyses, CSV_REPORT)
    write_json_report(all_file_analyses, JSON_REPORT)


if __name__ == '__main__':
    main()
