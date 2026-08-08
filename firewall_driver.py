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
        """Creates an isolated UTM chain in iptables, attaches to INPUT/OUTPUT chains, and enforces connection tracking safety."""
        if self.dry_run:
            return
        
        # Create custom chain
        subprocess.run(["iptables", "-N", CHAIN_NAME], capture_output=True)
        
        # Link chain to both INPUT and OUTPUT tables for complete Layer 4 enforcement
        for chain in ["INPUT", "OUTPUT"]:
            check_link = subprocess.run(["iptables", "-C", chain, "-j", CHAIN_NAME], capture_output=True)
            if check_link.returncode != 0:
                subprocess.run(["iptables", "-I", chain, "1", "-j", CHAIN_NAME], capture_output=True)

        # Stateful Connection Bypass: Protect active connections (e.g., Google Meet, SSH) from mid-session drops
        check_state = subprocess.run(
            ["iptables", "-C", CHAIN_NAME, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            capture_output=True
        )
        if check_state.returncode != 0:
            subprocess.run(
                ["iptables", "-I", CHAIN_NAME, "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                capture_output=True
            )

    def validate_ip(self, ip_str: str) -> bool:
        """Validates IP format to prevent command injection."""
        if not ip_str or ip_str == "N/A":
            return False
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            logging.error(f"Invalid IP address provided: '{ip_str}'")
            return False

    def block_ip(self, ip_str: str, dest_ip: str = "N/A") -> bool:
        """Applies DROP rules for specified IP. Supports directional filtering if dest_ip is provided."""
        if not self.validate_ip(ip_str):
            return False

        has_dest = self.validate_ip(dest_ip)

        if self.dry_run:
            log_target = f"{ip_str} -> {dest_ip}" if has_dest else ip_str
            logging.info(f"[DRY-RUN] Blocked IP: {log_target}")
            return True

        # Clear existing rules for this IP pair to avoid rule duplication or conflict
        self.unblock_ip(ip_str, dest_ip)

        if has_dest:
            # Directional DROP rule
            res = subprocess.run(["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-d", dest_ip, "-j", "DROP"], capture_output=True, text=True)
            if res.returncode == 0:
                logging.info(f"Successfully applied directional DROP rule for {ip_str} -> {dest_ip}")
                return True
            else:
                logging.error(f"Failed to apply directional DROP for {ip_str} -> {dest_ip}: {res.stderr}")
                return False
        else:
            # Global bidirectional DROP
            res_s = subprocess.run(["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-j", "DROP"], capture_output=True, text=True)
            res_d = subprocess.run(["iptables", "-I", CHAIN_NAME, "1", "-d", ip_str, "-j", "DROP"], capture_output=True, text=True)

            if res_s.returncode == 0 and res_d.returncode == 0:
                logging.info(f"Successfully applied bidirectional DROP rules for {ip_str}")
                return True
            else:
                logging.error(f"Failed to block {ip_str}: {res_s.stderr or res_d.stderr}")
                return False

    def allow_ip(self, ip_str: str, dest_ip: str = "N/A") -> bool:
        """Applies an ACCEPT rule for specified IP. Supports directional filtering if dest_ip is provided."""
        if not self.validate_ip(ip_str):
            return False

        has_dest = self.validate_ip(dest_ip)

        if self.dry_run:
            log_target = f"{ip_str} -> {dest_ip}" if has_dest else ip_str
            logging.info(f"[DRY-RUN] Whitelisted IP: {log_target}")
            return True

        # Remove drop rule if existing
        self.unblock_ip(ip_str, dest_ip)

        if has_dest:
            cmd = ["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-d", dest_ip, "-j", "ACCEPT"]
        else:
            cmd = ["iptables", "-I", CHAIN_NAME, "1", "-s", ip_str, "-j", "ACCEPT"]

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            logging.info(f"Successfully applied ACCEPT rule for {ip_str}" + (f" -> {dest_ip}" if has_dest else ""))
            return True
        else:
            logging.error(f"Failed to whitelist {ip_str}: {res.stderr}")
            return False

    def unblock_ip(self, ip_str: str, dest_ip: str = "N/A") -> bool:
        """Removes custom rules (DROP or ACCEPT) for the given IP address (and optional dest_ip)."""
        if not self.validate_ip(ip_str):
            return False

        if self.dry_run:
            logging.info(f"[DRY-RUN] Cleared rules for IP: {ip_str}")
            return True

        if self.validate_ip(dest_ip):
            subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-d", dest_ip, "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-d", dest_ip, "-j", "ACCEPT"], capture_output=True)

        # Clear global rules for ip_str
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip_str, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-s", ip_str, "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-D", CHAIN_NAME, "-d", ip_str, "-j", "ACCEPT"], capture_output=True)
        
        logging.info(f"Cleared firewall rules for {ip_str}")
        return True


if __name__ == "__main__":
    fw = FirewallDriver()
    fw.block_ip("192.168.1.100", dest_ip="8.8.8.8")
    fw.allow_ip("10.0.0.1")
    fw.unblock_ip("192.168.1.100", dest_ip="8.8.8.8")
