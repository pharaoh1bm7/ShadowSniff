from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich.live import Live
from rich.table import Table
from collections import defaultdict
from oauth2client.service_account import ServiceAccountCredentials
import gspread
import time

# Set the path to your Google credentials JSON
GOOGLE_CREDENTIALS_PATH = "credentials.json"
GOOGLE_SHEET_NAME = "Network Attack Logs"

# Traffic counters
icmp_flood = defaultdict(int)
syn_flood = defaultdict(int)
udp_flood = defaultdict(int)
port_scan = defaultdict(set)

# Google Sheets setup
def send_to_google_sheet(data_rows):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDENTIALS_PATH, scope)
    client = gspread.authorize(creds)
    sheet = client.open(GOOGLE_SHEET_NAME).sheet1

    # Optional: Add header once
    if sheet.row_count == 0:
        sheet.append_row(["Source IP", "ICMP Flood", "SYN Flood", "UDP Flood", "Ports Scanned", "Timestamp"])

    for row in data_rows:
        sheet.append_row(row)

# Analyze each packet
def detect_attack(packet):
    if IP not in packet:
        return

    src = packet[IP].src

    if packet.haslayer(ICMP):
        icmp_flood[src] += 1

    elif packet.haslayer(TCP):
        if packet[TCP].flags == "S":
            syn_flood[src] += 1
            port_scan[src].add(packet[TCP].dport)

    elif packet.haslayer(UDP):
        udp_flood[src] += 1

# Build terminal table
def build_table():
    table = Table(title="📡 Network Attack Monitor - Live", style="bold cyan")
    table.add_column("Source IP", style="bold")
    table.add_column("ICMP Flood", style="yellow")
    table.add_column("SYN Flood", style="red")
    table.add_column("UDP Flood", style="green")
    table.add_column("Ports Scanned", style="magenta")

    all_ips = set(icmp_flood) | set(syn_flood) | set(udp_flood) | set(port_scan)

    for ip in all_ips:
        table.add_row(
            ip,
            str(icmp_flood[ip]),
            str(syn_flood[ip]),
            str(udp_flood[ip]),
            str(len(port_scan[ip]))
        )
    return table

# Main monitoring loop
def main():
    print("[*] Starting live network attack monitor...")
    with Live(build_table(), refresh_per_second=1) as live:
        def handle_packet(pkt):
            detect_attack(pkt)
            live.update(build_table())

        try:
            sniff(prn=handle_packet, store=0)
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped. Exporting data...")

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            all_ips = set(icmp_flood) | set(syn_flood) | set(udp_flood) | set(port_scan)
            rows = [
                [ip, icmp_flood[ip], syn_flood[ip], udp_flood[ip], len(port_scan[ip]), timestamp]
                for ip in all_ips
            ]

            send_to_google_sheet(rows)
            print("[✓] Data exported to Google Sheets.")

if __name__ == "__main__":
    main()
