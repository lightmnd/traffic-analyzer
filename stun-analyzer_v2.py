import os, csv, struct
from ipaddress import IPv4Address, IPv6Address
from collections import defaultdict, Counter
from scapy.all import PcapReader, IP, IPv6, UDP, DNS, TCP
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
PCAP_DIR = "./pcaps/"
IP_RANGES_DIR = "./ip_ranges/"

class ForensicFinalReport:
    def __init__(self):
        self.MAGIC_COOKIE = b"\x21\x12\xa4\x42"
        self.target_private = "analysis..."
        self.infra_map = [] # For infrestructure servers (STUN, TURN, ...)
        self.discovered_publics = set()
        self.discovered_privates = set()
        self.realms = set()
        self.infra_from_pcap = set() 
        self.streams = defaultdict(lambda: {'pkts': 0, 'bytes': 0, 'start': 0, 'end': 0})
        self.target_candidates = Counter()
        self.private_pair_ips = None
        self.source_count = Counter()
        self.dest_count = Counter()
        self.is_wa_since_unknown_method = None
        self.detected_app_by_sni = None
        # For Direction Detection 
        self.push_candidates = {} 
        self.syn_candidates = {}  
        self.call_direction = "UNKNOWN"
        self.detected_app_by_infra = set()
        self.detected_snapchat_infra = False 
        
    def load_infra(self):
        """Upload IP ranges from CSV and use the filename as label for the used App"""
        if not os.path.exists(IP_RANGES_DIR): return
        for f in os.listdir(IP_RANGES_DIR):
            if f.endswith(".csv"):
                app_name = ""
                with open(os.path.join(IP_RANGES_DIR, f), "r") as fh:
                    for row in csv.reader(fh):
                        parse_app_name = "".join(row[-1])
                        if "SNAPCHAT" in parse_app_name.upper(): 
                            app_name = "SNAPCHAT"
                            self.detected_snapchat_infra = app_name
                        if len(row) >= 2:
                            try:
                                start = int(IPv4Address(row[0].strip()))
                                end = int(IPv4Address(row[1].strip()))
                                self.infra_map.append((start, end, app_name))
                            except: continue

    def get_ip_info(self, ip_str):
        try:
            val = int(IPv4Address(ip_str))
            for start, end, app in self.infra_map:
                if start <= val <= end:
                    return True, app
        except: pass
        
        # If the app name is not in the IP ranges filename check if is present in the REALM indication
        if ip_str in self.infra_from_pcap:
            return True, "INFRA (from Realm)"
            
        return False, None


    # Utility for STUN port detection
    STUN_PORTS = frozenset((3478, 1400, 443))

    def verify_stun_port(self, port_num):
        return port_num in self.STUN_PORTS
    
    def get_tls_sni(self, packet):
        """
        Find Signal app reference indication analyzing TLS handshake
        and retriving information parsing the handshake paylaod.
        Signal usually uses the cloud providers as network infrastructure. 
        For an Heuristic implementation, the most used cloud providers are Cloudflare and AWS.
        """
        if packet.haslayer(TCP) and packet.haslayer('Raw'):
            # if not packet.haslayer('Raw'): return None
            payload = bytes(packet['Raw'].load)
            
            # Find 0x16 the TLS record for the TLS Handshake, (0x16 0x03 0x01 or 0x16 0x03 0x03) is the Client Hello 
            # Ppattern 0x16 0x03 is often specific for the TLS
            if len(payload) > 11 and payload[0] == 0x16 and payload[1] == 0x03:
                # Finding the Signal critical domains in the Client Hello payload
                targets = [
                    b"signal.org", b"whispersystems.org", b"signal.me", b"signal.art",
                    b"signal.group", b"signal.link",
                    b"fastly.signal.org",
                    b"turn.whispersystems.org",
                    b"cloudflare",
                    b"turn",
                    b"kinesis.us-east-1.amazonaws.com",
                    b"cloudfront.net"
                ]
                for target in targets:
                    if target in payload:
                        # if packet[TCP].dport != 443:
                        #     print(f"[DEBUG] SNI {target.decode()} captured on PROXY port: {packet[IP].dst}:{packet[TCP].dport}")
                        # else:
                        #     print(f"[DEBUG] SNI {target.decode()} captured on standard 443 port: {packet[IP].dst}:{packet[TCP].dport}")
                        return "SIGNAL"
        return None
    
    
    def analyze_ipv6(self, ip_addr):
        """
        This module to analyze IPv6 addresses tha could be contained in a pcap as STUN event
        """
        try:
            addr = IPv6Address(ip_addr)
            if addr.is_private or addr.is_link_local:
                self.discovered_privates.add(ip_addr)
            else:
                self.discovered_publics.add(ip_addr)
        except Exception:
            pass
        
        
    CUSTOM_WA_METHODS = frozenset((0x201, 0x202, 0x4000, 0x4001, 0x4002, 0x4003, 0x4004, 0x4007))
    
    def detect_custom_wa_method(self, msg_type_method):
        """
        Detect if the given STUN message type method corresponds to a custom WhatsApp method.
        """
        if msg_type_method in self.CUSTOM_WA_METHODS:
            return "WHATSAPP"
        return None
    
    def run(self):
        self.load_infra()
        pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))]
        
        # Temporary cache for the Server Name Indication
        self.detected_app_by_sni = None
        
        for pcap in pcap_files:
            # PcapReader instead of rdpcap that actually create a generator, it is better for memory consumption.
            with PcapReader(os.path.join(PCAP_DIR, pcap)) as reader:
                for pkt in reader:
                    
                    if IP in pkt and TCP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        
                        # Detect inbound Push Notification on every IP
                        # When Target receives a call a Push Notification reactivates the VoIP application
                        # This could means that the Target is the receiver
                        # IMPORTANT: Oftec with the Apple devices the 443 is the preferred port, but also Android can use when the 5222 is blocked by a firewall
                        if pkt[TCP].sport in [5228, 5229, 5230, 5223]: # Google Firebase Notification or Apple APNs (5223)
                            if dst_ip not in self.push_candidates:
                                self.push_candidates[dst_ip] = pkt.time

                        # Detect outbound SYN to WA (port 5222 Android, 443 iOS)
                        # With this condition we are decetting both cases:
                        # if the Target is the RECEIVER this call occurs few seconds after the Push Notification
                        # if the Target is the CALLER this call starts without attending the push notification 
                        if pkt[TCP].flags == "S" and pkt[TCP].dport in [5222, 443]:
                            if src_ip not in self.syn_candidates:
                                self.syn_candidates[src_ip] = pkt.time
                                
                    app_sni = self.get_tls_sni(pkt)
                    if app_sni and self.detected_app_by_sni != "WHATSAPP":
                        self.detected_app_by_sni = app_sni
                        
                    #if IP not in pkt or UDP not in pkt: continue
                    if (IP in pkt or IPv6 in pkt) and UDP in pkt:
                        layer = IP if IP in pkt else IPv6
                        ip_s, ip_d = pkt[layer].src, pkt[layer].dst
                        port_s, port_d = pkt[layer].sport, pkt[layer].dport
                        payload = bytes(pkt[UDP].payload)
                        
                        # IMPORTANT!!!
                        # For group calls, port 10000 is always used according to official specifications.
                        if UDP in pkt:
                            if pkt[UDP].sport == 10000 or pkt[UDP].dport == 10000:
                                self.detected_app_by_sni = "SIGNAL"
                        
                        if self.MAGIC_COOKIE in payload:
                            # If STUN port is used by the source, the target is the destination
                            if port_s in self.STUN_PORTS:
                                self.target_candidates[ip_d] += 1
                            # If STUN port is used by the destination, the target is the source
                            if port_d in self.STUN_PORTS:
                                self.target_candidates[ip_s] += 1

                            idx = payload.find(self.MAGIC_COOKIE)
                            stun = payload[idx-4:]
                            try:
                                # Parse header discovering message type and class
                                stun_type, msg_len = struct.unpack("!HH", stun[0:4])
                                msg_type_class = ((stun_type & 0x0010) >> 4) | ((stun_type & 0x0100) >> 7)
                                msg_type_method = (stun_type & 0x000F) | ((stun_type & 0x00E0) >> 1) | ((stun_type & 0x3E00) >> 2)
                                
                                is_wa = self.detect_custom_wa_method(msg_type_method)
                                if is_wa == "WHATSAPP":
                                    self.detected_app_by_sni = "WHATSAPP"
                                
                                # Check if is a Binding Request 
                                is_binding_request = msg_type_class == 0 and msg_type_method == 1
                                
                                if is_binding_request:
                                    is_private_ip_source = False
                                    
                                    # If the source is the target, the peer is the destination
                                    if IP in pkt:
                                        is_private_ip_source = ip_s.startswith(("192.168.", "10.", "172."))
                                        is_private_ip_destination = ip_d.startswith(("192.168.", "10.", "172."))
                                    else:
                                        is_private_ip_source = IPv6Address(ip_s).is_private or IPv6Address(ip_s).is_link_local
                                        is_private_ip_destination = IPv6Address(ip_d).is_private or IPv6Address(ip_d).is_link_local
                                    
                                    peer_ip = ip_d if is_private_ip_source else ip_s
                                    
                                    if is_private_ip_source and is_private_ip_destination:
                                        self.private_pair_ips = f"{ip_s}-{ip_d}"
                                    
                                   
                                    # Detect infrastructure servers (STUN, TURN, ...)    
                                    is_infra, _ = self.get_ip_info(peer_ip)
                                    is_stun_port = self.verify_stun_port(port_s) or self.verify_stun_port(port_d)
                                    
                                    if not is_infra and not is_stun_port:
                                        # Add IPs in the correct group (Public/Private)
                                        if IP in pkt:
                                            if peer_ip.startswith(("192.168.", "10.", "172.")):
                                                self.discovered_privates.add(peer_ip)
                                            else:
                                                is_in_csv, _ = self.get_ip_info(peer_ip)
                                                if not is_in_csv:
                                                    self.discovered_publics.add(peer_ip)
                                                # elif "SNAPCHAT" in app_label.upper(): 
                                                #     self.detected_snapchat_infra = True
                                        else:
                                            self.analyze_ipv6(peer_ip)
                                            
                                off = 20
                                while off < msg_len + 20:
                                    t, l = struct.unpack("!HH", stun[off:off+4])
                                    if t == 0x0014: # REALM
                                        r_val = stun[off+4:off+4+l].decode('utf-8', 'ignore')
                                        self.realms.add(r_val)
                                    off += 4 + l + (4 - (l % 4)) % 4
                            except: pass


        # Detect Private Target (Auto-Detect) IP
        if self.target_candidates:
            self.target_private = self.target_candidates.most_common(1)[0][0]
            
            # Get call direction based on PSH/SYN occurrences
            t_push = self.push_candidates.get(self.target_private)
            t_syn = self.syn_candidates.get(self.target_private)
            if t_push and t_syn:
                # PSH 2 seconds before SYN
                if 0 < (t_syn - t_push) < 5:
                    self.call_direction = "<- INBOUND"
                    self.push_timestamp = t_push
                    self.syn_timestamp = t_syn
                else:
                    self.call_direction = "-> OUTBOUND"
            elif t_syn:
                self.call_direction = "-> OUTBOUND"
                self.syn_timestamp = t_syn
                
        # If the detected Target IP is also appearing in the Binding Request, ignore it removing from the 
        if self.target_private in self.discovered_privates:
            self.discovered_privates.remove(self.target_private)
            
        self.remove_dual_role_ip_from_private()
   
        self.print_report()

    def remove_dual_role_ip_from_private(self):
        """Remove only the IP that appears in both the source and destination"""
        if self.private_pair_ips:
            ip1, ip2 = self.private_pair_ips.split('-')
            
            ip1_is_source_and_dest = self.source_count[ip1] > 0 and self.dest_count[ip1] > 0
            ip2_is_source_and_dest = self.source_count[ip2] > 0 and self.dest_count[ip2] > 0
            
            if ip1_is_source_and_dest and ip1 in self.discovered_privates:
                self.discovered_privates.remove(ip1)
            
            if ip2_is_source_and_dest and ip2 in self.discovered_privates:
                self.discovered_privates.remove(ip2)
                
                                
    def print_report(self):
        # App indication from Realm or IP ranges filename
        app_final = "Generic / Not identified"
        combined_realms = "".join(list(self.realms)).lower()
        #snapchat_app_label = self.infra_map[0].strip()

        detected_sni = str(self.detected_app_by_sni).upper() if self.detected_app_by_sni else ""
        
        print(self.detected_app_by_infra)

        if "WHATSAPP" in combined_realms or "WHATSAPP" in detected_sni: 
            app_final = "WhatsApp (STUN Method)"
        elif "TELEGRAM" in self.detected_app_by_infra or "telegram" in combined_realms: 
            app_final = "Telegram"
        elif "VIBER" in self.detected_app_by_infra or "viber" in combined_realms: 
            app_final = "Viber"
        elif self.detected_snapchat_infra:
            app_final = "Snapchat (Infrastructure)"
        elif "SIGNAL" in detected_sni:
            app_final = "Signal (Heuristic)"
        
        
        id_info = f"[bold white]PRIVATE Target (Auto-Detected):[/bold white] {self.target_private}\n"
        id_info += f"[bold cyan]Call Direction:[/bold cyan] {self.call_direction}\n"
        id_info += f"[bold red]PUBLIC Targets (Binding Request):[/bold red] {', '.join(sorted(self.discovered_publics))}\n"
        id_info += f"[bold red]PRIVATE Targets (Binding Request):[/bold red] {', '.join(sorted(self.discovered_privates))}\n"
        id_info += f"[bold green]Detected Platform:[/bold green] {app_final}"
        console.print(Panel(id_info, title="🔍 Forensic Identity (recap)", expand=False))

       
ForensicFinalReport().run()
