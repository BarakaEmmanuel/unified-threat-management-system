import os
import sys
import re
import socket
import struct
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import database

def get_local_ip():
    """Gets the primary local IP address of the active interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_mac_vendor(mac):
    """Queries SQLite MAC OUI database table."""
    return database.lookup_mac_vendor(mac)

def query_netbios(ip, timeout=0.3):
    """Queries NetBIOS Name Service (UDP 137) to discover Windows/Samba names."""
    nb_packet = b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(nb_packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 56:
            name_data = data[57:72].decode('latin-1', errors='ignore').strip()
            return name_data
    except Exception:
        pass
    return None

def query_mdns(ip, timeout=0.3):
    """Queries mDNS (UDP 5353) for multicast .local hostnames on target endpoint."""
    try:
        ip_parts = ip.split('.')
        arpa_name = f"{ip_parts[3]}.{ip_parts[2]}.{ip_parts[1]}.{ip_parts[0]}.in-addr.arpa"
        
        packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for part in arpa_name.split('.'):
            packet += bytes([len(part)]) + part.encode('utf-8')
        packet += b'\x00\x00\x0c\x00\x01'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 12:
            raw_str = data[12:].decode('latin-1', errors='ignore')
            matches = re.findall(r'[\w\-]+(?:\.local|\.lan)', raw_str, re.IGNORECASE)
            if matches:
                return matches[0]
    except Exception:
        pass
    return None

def query_ssdp(ip, timeout=0.3):
    """Queries SSDP/UPnP (UDP 1900) for OS/device response details."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg.encode(), (ip, 1900))
        data, _ = sock.recvfrom(1024)
        sock.close()
        resp = data.decode('utf-8', errors='ignore').lower()
        if "windows" in resp or "microsoft" in resp:
            return "Windows OS"
        elif "android" in resp:
            return "Android OS"
        elif "darwin" in resp or "mac os" in resp or "ios" in resp:
            return "macOS / iOS"
        elif "linux" in resp:
            return "Linux OS"
    except Exception:
        pass
    return None

def resolve_hostname(ip, mac="", os_type="Unknown OS"):
    """Multi-tiered reverse lookup: NetBIOS -> mDNS -> Reverse DNS -> MAC Vendor -> OS Fallback."""
    # 1. NetBIOS Query
    nb_name = query_netbios(ip)
    if nb_name:
        return nb_name

    # 2. mDNS (.local) Query
    mdns_name = query_mdns(ip)
    if mdns_name:
        return mdns_name

    # 3. Fast Reverse DNS Lookup
    socket.setdefaulttimeout(0.4)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass

    # 4. Hardware Vendor Name Fallback
    vendor = get_mac_vendor(mac)
    if vendor:
        return f"{vendor} Endpoint"

    # 5. Detected OS Display Fallback
    if os_type and os_type != "Unknown OS":
        return f"{os_type} Endpoint"

    return "Unknown Device"

def fingerprint_os(ip, mac=""):
    """
    Tiered Fingerprint Engine:
    Tier 1: SSDP/UPnP Protocol Inspection
    Tier 2: Port & Vendor Disambiguation
    Tier 3: ICMP TTL Heuristics
    """
    vendor = get_mac_vendor(mac)

    ssdp_os = query_ssdp(ip)
    if ssdp_os:
        return ssdp_os

    open_ports = []
    probe_ports = [22, 135, 445, 5555, 62078]
    for port in probe_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    if 62078 in open_ports:
        return "iOS / iPadOS"
    if 135 in open_ports or 445 in open_ports:
        return "Windows OS"
    if 5555 in open_ports:
        return "Android OS"

    if vendor == "Apple":
        return "macOS / iOS"
    elif vendor in ("Samsung", "Xiaomi", "Huawei"):
        return "Android OS"
    elif vendor == "Raspberry Pi":
        return "Linux (Raspberry Pi OS)"
    elif vendor == "Espressif (IoT)":
        return "Smart Home / IoT Device"

    ttl = None
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
        match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
    except Exception:
        pass

    if ttl:
        if ttl <= 64:
            if 22 in open_ports:
                return "Linux OS"
            return "Linux / Unix / Mobile"
        elif ttl <= 128:
            return "Windows OS"
        elif ttl <= 255:
            return "Embedded Network Device"

    return "Unknown OS"

def scan_arp_table():
    """Parses /proc/net/arp to collect connected active network devices."""
    devices = []
    arp_file = "/proc/net/arp"
    
    if os.path.exists(arp_file):
        try:
            with open(arp_file, "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        flags = parts[2]
                        mac = parts[3]
                        
                        if flags != "0x0" and mac != "00:00:00:00:00:00" and ip != "0.0.0.0":
                            devices.append({"ip": ip, "mac": mac})
        except Exception as e:
            print(f"[-] Error reading ARP cache: {e}")
            
    return devices

def trigger_subnet_sweep():
    """Fast concurrent ICMP ping sweep across local /24 subnet."""
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return

    subnet_prefix = ".".join(local_ip.split(".")[:-1]) + "."
    
    def ping_target(ip):
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=40) as executor:
        ips = [f"{subnet_prefix}{i}" for i in range(1, 255)]
        executor.map(ping_target, ips)

def process_device(dev):
    """Processes fingerprinting and database updates for a single endpoint."""
    ip = dev["ip"]
    mac = dev["mac"]
    
    os_type = fingerprint_os(ip, mac)
    hostname = resolve_hostname(ip, mac, os_type=os_type)

    database.upsert_connected_device(
        ip=ip,
        mac=mac,
        hostname=hostname,
        detected_os=os_type,
        bytes_in=0,
        bytes_out=0
    )

def run_device_scanner(interval_seconds=15, daemon_mode=True):
    """Main loop sweeping network and updating connected devices."""
    database.init_db()
    print("[+] Enhanced Device Scanner initialized. Monitoring network endpoints...")

    def scan_cycle():
        while True:
            try:
                trigger_subnet_sweep()
                discovered_devices = scan_arp_table()

                local_ip = get_local_ip()
                if local_ip != "127.0.0.1" and not any(d["ip"] == local_ip for d in discovered_devices):
                    discovered_devices.append({
                        "ip": local_ip,
                        "mac": "LOCAL_HOST"
                    })

                seen_ips = set()
                unique_devices = []
                for dev in discovered_devices:
                    if dev["ip"] not in seen_ips:
                        seen_ips.add(dev["ip"])
                        unique_devices.append(dev)

                with ThreadPoolExecutor(max_workers=25) as executor:
                    executor.map(process_device, unique_devices)

            except Exception as e:
                print(f"[-] Device Scanner Error: {e}")

            time.sleep(interval_seconds)

    if daemon_mode:
        scanner_thread = threading.Thread(target=scan_cycle, daemon=True)
        scanner_thread.start()
        return scanner_thread
    else:
        scan_cycle()

if __name__ == "__main__":
    run_device_scanner(interval_seconds=10, daemon_mode=False)
