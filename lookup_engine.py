import ipaddress
from functools import lru_cache

# Static In-Memory Subnet & Service Lookup Table
# Ordered by specificity for accurate CIDR matching
KNOWN_NETWORKS = {
    # Public DNS Resolvers
    ipaddress.ip_network("8.8.8.8/32"): "Google Public DNS",
    ipaddress.ip_network("8.8.4.4/32"): "Google Secondary DNS",
    ipaddress.ip_network("1.1.1.1/32"): "Cloudflare Primary DNS",
    ipaddress.ip_network("1.0.0.1/32"): "Cloudflare Secondary DNS",
    ipaddress.ip_network("9.9.9.9/32"): "Quad9 Threat-Blocking DNS",
    ipaddress.ip_network("208.67.222.222/32"): "OpenDNS",

    # Major Cloud & Infrastructure Ranges
    ipaddress.ip_network("172.217.0.0/16"): "Google Infrastructure / Web Services",
    ipaddress.ip_network("142.250.0.0/16"): "Google Cloud / Meet / Video Stream",
    ipaddress.ip_network("104.16.0.0/12"):  "Cloudflare Edge / CDN",
    ipaddress.ip_network("172.64.0.0/13"):   "Cloudflare CDN & DDoS Protection",
    ipaddress.ip_network("13.107.0.0/16"):  "Microsoft Office 365 / Cloud",
    ipaddress.ip_network("20.36.0.0/14"):   "Microsoft Azure Services",
    ipaddress.ip_network("52.96.0.0/12"):   "AWS Cloud Infrastructure",
    ipaddress.ip_network("140.82.112.0/20"): "GitHub Platform Services",
    ipaddress.ip_network("151.101.0.0/16"): "Fastly Global Content Delivery Network",

    # Private & Internal Network Ranges
    ipaddress.ip_network("127.0.0.0/8"):    "Localhost (Loopback)",
    ipaddress.ip_network("10.0.0.0/8"):     "Private Corporate / Internal Network",
    ipaddress.ip_network("172.16.0.0/12"):  "Private LAN Subnet",
    ipaddress.ip_network("192.168.0.0/16"): "Local LAN / Gateway Environment",
    ipaddress.ip_network("169.254.0.0/16"): "Link-Local / APIPA Address",
}


@lru_cache(maxsize=2048)
def lookup_ip_context(ip_str: str) -> str:
    """
    Evaluates an IP string against known CIDR blocks and IP ranges purely in-memory.
    Uses LRU cache so repeated lookups resolve in sub-microseconds without disk/network I/O.
    """
    if not ip_str or str(ip_str).strip().upper() in ("N/A", "NONE", "UNKNOWN", ""):
        return "N/A"

    ip_clean = str(ip_str).strip()

    try:
        ip_obj = ipaddress.ip_address(ip_clean)

        # 1. Match against explicit subnet definitions
        for network, label in KNOWN_NETWORKS.items():
            if ip_obj in network:
                return label

        # 2. General fallback categorization based on IP attributes
        if ip_obj.is_loopback:
            return "Localhost (Loopback)"
        if ip_obj.is_private:
            return "Local LAN / Private Subnet"
        if ip_obj.is_multicast:
            return "Multicast Broadcast Group"
        if ip_obj.is_reserved:
            return "Reserved IETF Subnet"
        if ip_obj.is_link_local:
            return "Link-Local Address"

        return "External Host (Unknown)"

    except ValueError:
        return "Invalid IP Format"


def clear_lookup_cache():
    """Flushes the LRU cache if networks are updated dynamically."""
    lookup_ip_context.cache_clear()


def get_cache_stats():
    """Returns memory cache hit/miss statistics."""
    return lookup_ip_context.cache_info()


if __name__ == "__main__":
    test_ips = [
        "192.168.1.1",
        "8.8.8.8",
        "172.217.16.14",
        "104.16.20.1",
        "140.82.121.4",
        "10.0.0.50",
        "45.33.32.156",
        "invalid_ip",
        "N/A"
    ]
    
    print("[+] Testing lookup_engine.py mapping & speed:\n")
    for ip in test_ips:
        res = lookup_ip_context(ip)
        print(f"  {ip:<18} -> {res}")
    
    print(f"\n[+] Cache Info: {get_cache_stats()}")
