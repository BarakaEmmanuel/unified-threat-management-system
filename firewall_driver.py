import subprocess
import ipaddress
import logging
import os

logging.basicConfig(level=logging.INFO, format="[FirewallDriver] %(levelname)s: %(message)s")

CHAIN_NAME = "UTM_FILTER"

class FirewallDriver:
    def __init__(self):
        self.dry_run = not self._check_root_and_iptables()
        if self.dry_run:
            logging.warning("Operating in DRY-RUN mode. Kernel firewall rules will be simulated.")
        else:
            self._ensure_custom_chain()

    def _check_root_and_iptables(self) -> bool:
        """Verifies root privileges and iptables presence."""
        if os.name == "nt": # Windows fallback
            return False
        if os.geteuid() != 0:
            return False
        try:
            res = subprocess.run(["iptables", "--version"], capture_output=True, text=True)
            return res.returncode == 0
        except FileNotFoundError:
            return False

    def _ensure_custom_chain(self):
        """Creates an isolated UTM chain in iptables and attaches to INPUT and OUTPUT chains."""
        if self.dry_run:
            return
        
        # Create custom chain
        subprocess.run(["iptables", "-N", CHAIN_NAME], capture_output=True)
        
        # Link chain to both INPUT and OUTPUT tables for complete Layer 4 enforcement
        for chain in ["INPUT", "OUTPUT"]:
            check_link = subprocess.run(["iptables", "-C", chain, "-j", CHAIN_NAME], capture_output=True)
            if check_link.returncode != 0:
                subprocess.run(["iptables", "-I", chain, "1", "-j", CHAIN_NAME], capture_output=True)

    def validate_ip(self, ip_str: str) -> bool:
        """Validates IP format to prevent command injection."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            logging.error(f"Invalid IP address provided: '{ip_str}'")
            return False

    def block_ip(self, ip_str: str) -> bool:
        """Applies bidirectional DROP rules for the specified IP (Used for BLACKLIST and BLOCKED)."""
        if not self.validate_ip(ip_str):
            return False

        if self.dry_run:
            logging.info(f"[DRY-RUN] Blocked IP: {ip_str}")
            return True

        # Idempotency check: Don't re-add if already blocked bidirectionally
        check_s = subprocess.run(["iptables", "-C", CHAIN_NAME, "-s", ip_str, "-j", "DROP"], capture_output=True)
        check_d = subprocess.run(["iptables", "-C", CHAIN_NAME, "-d", ip_str, "-j", "DROP"], capture_output=True)
        if check_s.returncode == 0 and check_d.returncode == 0:
            return True

        # Clear existing rules for this IP to avoid rule duplication or conflict
        self.unblock_ip(ip_str)

        # Apply bidirectional DROP
        res_s = subprocess.run(["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-j", "DROP"], capture_output=True, text=True)
        res_d = subprocess.run(["iptables", "-I", CHAIN_NAME, "1", "-d", ip_str, "-j", "DROP"], capture_output=True, text=True)

        if res_s.returncode == 0 and res_d.returncode == 0:
            logging.info(f"Successfully applied bidirectional DROP rules for {ip_str}")
            return True
        else:
            logging.error(f"Failed to block {ip_str}: {res_s.stderr or res_d.stderr}")
            return False

    def allow_ip(self, ip_str: str) -> bool:
        """Applies an ACCEPT rule for the specified IP (Used for WHITELIST)."""
        if not self.validate_ip(ip_str):
            return False

        if self.dry_run:
            logging.info(f"[DRY-RUN] Whitelisted IP: {ip_str}")
            return True

        # Remove drop rule if existing
        self.unblock_ip(ip_str)

        check = subprocess.run(["iptables", "-C", CHAIN_NAME, "-s", ip_str, "-j", "ACCEPT"], capture_output=True)
        if check.returncode == 0:
            return True

        cmd = ["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-j", "ACCEPT"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            logging.info(f"Successfully applied ACCEPT rule for {ip_str}")
            return True
        else:
            logging.error(f"Failed to whitelist {ip_str}: {res.stderr}")
            return False

    def unblock_ip(self, ip_str: str) -> bool:
        """Removes all custom rules (DROP or ACCEPT) for the given IP address."""
        if not self.validate_ip(ip_str):
            return False

        if self.dry_run:
            logging.info(f"[DRY-RUN] Cleared rules for IP: {ip_str}")
            return True

        # Delete DROP rules (both source and destination)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip_str, "-j", "DROP"], capture_output=True)
        
        # Delete ACCEPT rules
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip_str, "-j", "ACCEPT"], capture_output=True)
        
        logging.info(f"Cleared firewall rules for {ip_str}")
        return True


if __name__ == "__main__":
    fw = FirewallDriver()
    fw.block_ip("192.168.1.100")
    fw.allow_ip("10.0.0.1")
    fw.unblock_ip("192.168.1.100")
