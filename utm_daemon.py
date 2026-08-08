import time
import signal
import sys
import logging
import database
from firewall_driver import FirewallDriver

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="[UTM Daemon] %(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)

class UTMDaemon:
    def __init__(self, check_interval=2):
        self.check_interval = check_interval
        self.fw = FirewallDriver()
        self.running = True
        
        # Track currently enforced IPs in memory for quick reconciliation
        self.enforced_ips = set()

        # Handle system signals for clean exit
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

    def shutdown(self, signum, frame):
        """Gracefully stops the daemon loop."""
        logging.info("Shutdown signal received. Stopping UTM Daemon...")
        self.running = False

    def sync_initial_state(self):
        """Loads existing active database rules into memory at startup to maintain parity."""
        try:
            all_db_rules = database.get_ip_rules()
            self.enforced_ips = {rule[0] for rule in all_db_rules if len(rule) > 0}
            logging.info(f"Initialized daemon state with {len(self.enforced_ips)} existing rule(s) from database.")
        except Exception as e:
            logging.error(f"Failed to synchronize initial state from database: {e}")

    def sync_rules(self):
        """Syncs newly added or modified rules from SQLite to the firewall kernel."""
        unapplied_rules = database.get_unapplied_ip_rules()
        for rule in unapplied_rules:
            # Support both (ip, rule_type) and (ip, dest_ip, rule_type) tuple structures
            if len(rule) >= 3:
                ip, dest_ip, rule_type = rule[0], rule[1], rule[2]
            else:
                ip, rule_type = rule[0], rule[1]
                dest_ip = "N/A"

            success = False
            if rule_type in ("BLACKLIST", "BLOCKED"):
                success = self.fw.block_ip(ip, dest_ip=dest_ip)
            elif rule_type == "WHITELIST":
                success = self.fw.allow_ip(ip, dest_ip=dest_ip)

            if success:
                database.mark_rule_as_active(ip)
                self.enforced_ips.add(ip)
                logging.info(f"Enforced kernel rule [{rule_type}] for IP: {ip} (Dest: {dest_ip})")

    def check_ttl_expirations(self):
        """Checks for temporary blocks that reached their 15-minute expiration."""
        expired_ips = database.get_expired_blocked_ips()
        for ip in expired_ips:
            logging.info(f"15-Minute TTL expired for temporary block on {ip}. Auto-unblocking...")
            self.fw.unblock_ip(ip)
            database.delete_ip_rule(ip)
            self.enforced_ips.discard(ip)

    def reconcile_deleted_rules(self):
        """Detects if a rule was deleted via GUI and removes kernel enforcement."""
        all_db_rules = database.get_ip_rules()
        db_ips = {rule[0] for rule in all_db_rules}

        # Any IP currently enforced that was removed from DB gets unblocked
        orphaned_ips = self.enforced_ips - db_ips
        for ip in list(orphaned_ips):
            logging.info(f"Rule for {ip} was removed from database. Removing firewall block...")
            self.fw.unblock_ip(ip)
            self.enforced_ips.discard(ip)

    def run(self):
        """Main execution loop."""
        logging.info("Starting Layer 4 Enforcement & Execution Daemon...")
        database.init_db()
        
        # Phase 1: Seed in-memory tracking before entering loop
        self.sync_initial_state()

        while self.running:
            try:
                self.sync_rules()
                self.check_ttl_expirations()
                self.reconcile_deleted_rules()
            except Exception as e:
                logging.error(f"Error during daemon execution loop: {e}")

            time.sleep(self.check_interval)

        logging.info("UTM Daemon shut down successfully.")


if __name__ == "__main__":
    daemon = UTMDaemon(check_interval=2)
    daemon.run()
