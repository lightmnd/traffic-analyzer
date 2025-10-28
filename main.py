import os
import csv
from scapy.all import rdpcap, IP, UDP, bind_layers
from scapy.contrib.stun import STUN
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import ipaddress

# --- Configurazione ---
REPORT_FILE = "stun_flow_summary.csv"
PCAP_DIR = "./pcaps/" 

# Assicurati che STUN sia caricato, come fatto nel codice precedente

STUN_PORTS = [3478, 5349, 19302, 19305, 19307] 

# Ogni volta che Scapy vede un pacchetto UDP destinato alla porta 3478, 
# il payload non è più Raw Data. È un pacchetto STUN. 
# quindi Scapy parsa i byte successivi usando la logica del protocollo STUN.
# Questo è l'unico modo per forzare Scapy a scendere al livello STUN quando si sa, 
# per convenzione (numero di porta), che quel protocollo dovrebbe essere presente. In questo modo, 
# garantisci che if STUN in packet: diventi finalmente vero per tutti i pacchetti sulle porte STUN/TURN note.

for port in STUN_PORTS:
    # Associa il livello STUN al livello UDP basandosi sulla porta di destinazione
    bind_layers(UDP, STUN, dport=port)
    # Associa il livello STUN al livello UDP basandosi sulla porta di sorgente
    bind_layers(UDP, STUN, sport=port)

def is_private_ip(ip: str) -> bool:
    """Controlla se un IP è un indirizzo privato (RFC 1918)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_stun_attributes(stun_layer: STUN) -> Dict[str, str]:
    """Estrae gli attributi STUN chiave, mappando il tipo con l'indirizzo."""
    attributes = {}
    
    # Mappatura dei tipi di attributo chiave
    TYPE_MAP = {
        0x0001: "MAPPED-ADDRESS",
        0x0020: "XOR-MAPPED-ADDRESS",
        0x0012: "RESPONSE-ORIGIN-ADDRESS",
        0x0014: "OTHER-ADDRESS",
        0x0016: "XOR-PEER-ADDRESS",
        0x0021: "XOR-RELAYED-ADDRESS" # Attributo TURN
    }
    
    current_attr = stun_layer
    while current_attr:
        if hasattr(current_attr, 'type') and current_attr.type in TYPE_MAP and hasattr(current_attr, 'addr'):
            attributes[TYPE_MAP[current_attr.type]] = current_attr.addr
        
        # Passa all'attributo successivo
        current_attr = current_attr.payload if current_attr.name == 'STUN Attribute' else None

    return attributes

def find_local_ip(packets) -> str:
    """Trova l'indirizzo IP privato più frequente (probabile host locale)."""
    ip_counts = defaultdict(int)
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if is_private_ip(src_ip):
                ip_counts[src_ip] += 1
            if is_private_ip(dst_ip):
                ip_counts[dst_ip] += 1

    if not ip_counts:
        return "N/D (Nessun IP Privato Trovato)"
        
    # Restituisce l'IP privato con il conteggio più alto
    return max(ip_counts, key=ip_counts.get)


def analyze_pcap_file(filepath: str) -> List[Dict[str, Any]]:
    """Analizza un singolo file pcap e riassume i flussi STUN."""
    print(f"[*] Analisi di: {filepath}...")
    
    try:
        packets = rdpcap(filepath)
       
    except Exception as e:
        print(f"[-] Errore nella lettura del file {filepath}: {e}")
        return []

    # 1. Identificazione dell'Host Intercettato
    local_ip = find_local_ip(packets)
    print(f"    [i] IP Privato Locale Presunto: {local_ip}")
    
    # Struttura per aggregare i dati per flusso (IP_Sorgente:Porta -> IP_Destinazione:Porta)
    flow_summaries = {} # Chiave: (IP_Sorgente, IP_Destinazione)
    
    for i, packet in enumerate(packets):

        print("======-----> ", packet.haslayer(STUN))
        if packet.haslayer(STUN):
            print(f"[*] Analisi del pacchetto {i + 1}...")
        
        if IP in packet and UDP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Definiamo il flusso in base alla coppia (IP Locale, IP Remoto)
            is_local_src = (src_ip == local_ip)
            
            if is_local_src:
                flow_key = (local_ip, dst_ip)
                interlocutor_ip = dst_ip
            elif dst_ip == local_ip:
                flow_key = (local_ip, src_ip) # Normalizziamo il flusso su (Locale, Remoto)
                interlocutor_ip = src_ip
            else:
                 # Ignora il traffico non da/per l'host locale presunto
                 continue
                 
            
            if flow_key not in flow_summaries:
                flow_summaries[flow_key] = {
                    "File": os.path.basename(filepath),
                    "IP_Intercettato_Privato": local_ip,
                    "IP_Interlocutore": interlocutor_ip,
                    "IP_Intercettato_Pubblico": "Non Trovato", # Sarà popolato da XOR-MAPPED
                    "IP_XOR_PEER_ADDRESS": "Non Trovato", # L'IP del peer remoto per la P2P
                    "Tipo_Flusso": "STUN/TURN",
                    "Eventi_STUN": [] # Lista di tuple: (Numero Pacchetto, Tipo Messaggio, Attributi)
                }
            
            # --- 2. Analisi STUN in Dettaglio ---
            stun_layer = packet.getlayer(STUN) 
            print("STUN LAYER: ", stun_layer)
            
            if stun_layer:
                # Tipo di messaggio STUN (es. 0x0001, 0x0101, ecc.)
                try:
                    message_type = stun_layer.type
                    message_name = stun_layer.get_field('type').i2s[message_type]
                except (AttributeError, KeyError):
                    message_name = f"Sconosciuto({message_type if 'message_type' in locals() else 'N/D'})"

                
                stun_attrs = get_stun_attributes(stun_layer)
                
                # Registrazione dell'evento
                flow_summaries[flow_key]["Eventi_STUN"].append(
                    (i + 1, message_name, stun_attrs)
                )

                # 3. Estrazione degli IP Pubblici
                # L'IP Pubblico dell'intercettato è nell'XOR-MAPPED-ADDRESS della RISPOSTA (0x0101)
                if 'Response' in message_name:
                    xor_mapped = stun_attrs.get("XOR-MAPPED-ADDRESS")
                    if xor_mapped:
                        flow_summaries[flow_key]["XOR-MAPPED-ADDRESS"] = xor_mapped
                        print('>>>>>>>>',flow_summaries[flow_key]["XOR-MAPPED-ADDRESS"] )
                        # flow_summaries[flow_key]["IP_Intercettato_Pubblico"] = xor_mapped
                
                # L'IP del Peer remoto è spesso in XOR-PEER-ADDRESS
                xor_peer = stun_attrs.get("XOR-PEER-ADDRESS")
                if xor_peer and flow_summaries[flow_key]["IP_XOR_PEER_ADDRESS"] == "Non Trovato":
                     flow_summaries[flow_key]["IP_XOR_PEER_ADDRESS"] = xor_peer
            

    # --- 4. Formattazione dell'Output Finale ---
    final_records = []
    
    for (local, remote), summary in flow_summaries.items():
        # Riassunto degli eventi STUN per la colonna del report
        event_details = []
        for pkt_num, msg_type, attrs in summary["Eventi_STUN"]:
            # Raggruppa gli IP di interesse (XOR-MAPPED, XOR-PEER, MAPPED)
            ip_details = [f"{k}: {v}" for k, v in attrs.items()]
            
            event_details.append(
                f"[Pkt {pkt_num}] {msg_type} ({'; '.join(ip_details)})"
            )

        final_records.append({
            "File": summary["File"],
            "IP_Locale_Privato": summary["IP_Intercettato_Privato"],
            "IP_Locale_Pubblico_Rilevato": summary["IP_Intercettato_Pubblico"],
            "IP_Interlocutore_Remoto_Server": remote,
            "IP_XOR_PEER_ADDRESS": summary["IP_XOR_PEER_ADDRESS"],
            "Riassunto_Flusso_STUN": " | ".join(event_details)
        })
        
    return final_records

def generate_report(data: List[Dict[str, Any]]):
    """Scrive i dati aggregati in un file CSV."""
    if not data:
        print("[!] Nessun dato da scrivere nel report.")
        return

    fieldnames = [
        "File", 
        "IP_Locale_Privato", 
        "IP_Locale_Pubblico_Rilevato", 
        "IP_Interlocutore_Remoto_Server", 
        "IP_XOR_PEER_ADDRESS",
        "Riassunto_Flusso_STUN"
    ]

    print(f"\n[+] Scrittura del report riassuntivo su {REPORT_FILE}...")
    try:
        with open(REPORT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerows(data)
        print("[+] Report riassuntivo completato con successo.")
    except Exception as e:
        print(f"[-] Errore durante la scrittura del file CSV: {e}")

def main():
    """Funzione principale per gestire i file multipli."""
    all_flow_records = []
    
    if not os.path.exists(PCAP_DIR):
        print(f"[-] Directory {PCAP_DIR} non trovata. Creala e inserisci i tuoi file pcap.")
        return
        
    pcap_files = [os.path.join(PCAP_DIR, f) 
                  for f in os.listdir(PCAP_DIR) 
                  if f.endswith(('.pcap', '.pcapng'))]

    if not pcap_files:
        print(f"[!] Nessun file .pcap o .pcapng trovato nella directory {PCAP_DIR}.")
        return

    for pcap_file in pcap_files:
        file_records = analyze_pcap_file(pcap_file)
        all_flow_records.extend(file_records)

    generate_report(all_flow_records)

if __name__ == "__main__":
    main()