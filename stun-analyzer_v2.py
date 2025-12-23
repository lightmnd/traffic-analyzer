import os, csv, struct
from ipaddress import IPv4Address
from collections import defaultdict, Counter
from scapy.all import PcapReader, IP, UDP
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
        self.infra_map = []
        self.discovered_publics = set()
        self.realms = set()
        self.infra_from_pcap = set() 
        self.streams = defaultdict(lambda: {'pkts': 0, 'bytes': 0, 'start': 0, 'end': 0})
        self.target_candidates = Counter()

    def load_infra(self):
        """Upload IP ranges from CSV and use the filename as label for the used App"""
        if not os.path.exists(IP_RANGES_DIR): return
        for f in os.listdir(IP_RANGES_DIR):
            if f.endswith(".csv"):
                app_label = f.replace(".csv", "").upper()
                with open(os.path.join(IP_RANGES_DIR, f), "r") as fh:
                    for row in csv.reader(fh):
                        if len(row) >= 2:
                            try:
                                start = int(IPv4Address(row[0].strip()))
                                end = int(IPv4Address(row[1].strip()))
                                self.infra_map.append((start, end, app_label))
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

    def run(self):
        self.load_infra()
        pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))]
        
        for pcap in pcap_files:
            # PcapReader instead of rdpcap that actually create a generator, it is better for memory consumption.
            with PcapReader(os.path.join(PCAP_DIR, pcap)) as reader:
                for pkt in reader:
                    if IP not in pkt or UDP not in pkt: continue
                    ip_s, ip_d = pkt[IP].src, pkt[IP].dst
                    payload = bytes(pkt[UDP].payload)
                    
                    if self.MAGIC_COOKIE in payload:
                        # Auto-detection Target (Private IP who interrogate STUN)
                        if ip_s.startswith(("192.168.", "10.", "172.")):
                            self.target_candidates[ip_s] += 1

                        # Attributes STUN analysis
                        idx = payload.find(self.MAGIC_COOKIE)
                        stun = payload[idx-4:]
                        try:
                            msg_len = struct.unpack("!H", stun[2:4])[0]
                            off = 20
                            while off < msg_len + 20:
                                t, l = struct.unpack("!HH", stun[off:off+4])
                                if t == 0x0020: # XOR Mapped IP
                                    xip = ".".join(map(str, [a^b for a,b in zip(stun[off+8:off+12], self.MAGIC_COOKIE)]))
                                    is_infra, _ = self.get_ip_info(xip)
                                    if not xip.startswith(("192.168.", "10.")) and not is_infra:
                                        self.discovered_publics.add(xip)
                                elif t == 0x0014: # REALM
                                    r_val = stun[off+4:off+4+l].decode('utf-8', 'ignore')
                                    self.realms.add(r_val)
                                    self.infra_from_pcap.add(ip_s) 
                                off += 4 + l + (4 - (l % 4)) % 4
                        except: pass

                    # Stream Aggregation
                    pair = tuple(sorted([ip_s, ip_d]))
                    s = self.streams[pair]
                    if s['pkts'] == 0: s['start'] = pkt.time
                    s['pkts'] += 1
                    s['end'] = pkt.time
                    s['bytes'] += len(payload)

        if self.target_candidates:
            self.target_private = self.target_candidates.most_common(1)[0][0]

        self.print_report()

    def print_report(self):
        # App indication from Realm or IP ranges filename
        app_final = "Generic / Not identified"
        combined_realms = "".join(list(self.realms)).lower()
        if "whatsapp" in combined_realms: app_final = "WhatsApp"
        elif "telegram" in combined_realms: app_final = "Telegram"
        
        id_info = f"[bold white]Private Target (Auto-Detected):[/bold white] {self.target_private}\n"
        id_info += f"[bold red]Public Targets (XOR Mapping):[/bold red] {', '.join(sorted(self.discovered_publics))}\n"
        id_info += f"[bold green]Detected Platform:[/bold green] {app_final}"
        console.print(Panel(id_info, title="🔍 Forensic Identity (recap)", expand=False))

        table = Table(title="\n🟢 AGGREGATED STREAM DETAILS", border_style="bold blue")
        table.add_column("A", style="cyan")
        table.add_column("B", style="yellow")
        table.add_column("Dutation", justify="right")
        table.add_column("Traffic Volume", justify="right")
        table.add_column("Forensic info / Type", justify="left")

        for (ip_a, ip_b), data in self.streams.items():
            if data['pkts'] > 100 and "8.8.8.8" not in [ip_a, ip_b]:
                durata = f"{round(float(data['end'] - data['start']), 1)}s"
                vol_kb = data['bytes'] / 1024
                
                # Identify if one of these is part of the communication infrastructure
                is_infra_a, app_a = self.get_ip_info(ip_a)
                is_infra_b, app_b = self.get_ip_info(ip_b)
                
                if is_infra_a or is_infra_b:
                    app_name = app_a if is_infra_a else app_b
                    if vol_kb < 100:
                        tipo = f"[bold red]Relay {app_name}: Signaling (No Voice)[/bold red]"
                    else:
                        tipo = f"[bold orange3]Relay {app_name}: Media Traffic[/bold orange3]"
                else:
                    if vol_kb > 150:
                        tipo = "[bold green]P2P: Direct communication[/bold green]"
                    else:
                        tipo = "[cyan]P2P: Discovery / Signaling LAN[/cyan]"
                
                table.add_row(ip_a, ip_b, durata, f"{round(vol_kb, 1)} KB", tipo)

        console.print(table)

ForensicFinalReport().run()
