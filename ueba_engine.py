#!/usr/bin/env python3
import argparse
import json
import pickle
import sys
import time
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
import database

MAX_PAYLOAD_SIZE = 50000  # DLP threshold: 50KB

class UEBAEngine:
    def __init__(self, user_id=1, username=None, window_size=5.0):
        self.user_id = user_id
        self.username = username
        self.model = IsolationForest(contamination=0.02, random_state=42)
        self.feature_buffer = []
        self.is_trained = False
        self.window_size = window_size  # Sliding window duration in seconds
        self.ip_windows = defaultdict(deque)  # Tracks packet history per source IP

    def extract_features(self, packet):
        return [
            float(packet.get("packet_size", 0)),
            float(packet.get("payload_size", 0)),
            float(packet.get("dest_port", 0))
        ]

    def collect_sample(self, packet):
        """Collects feature vectors during baseline training mode."""
        features = self.extract_features(packet)
        self.feature_buffer.append(features)

    def finalize_and_save_baseline(self):
        """Fits Isolation Forest on collected samples and saves model to SQLite."""
        if len(self.feature_buffer) < 50:
            print(f"[-] Not enough samples to build a reliable baseline (need at least 50, got {len(self.feature_buffer)}).")
            return False

        X = np.array(self.feature_buffer)
        self.model.fit(X)
        self.is_trained = True

        # Serialize model into binary BLOB
        model_blob = pickle.dumps(self.model)

        # Save model blob to user_baselines table
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_baselines (user_id, model_data, baseline_metrics, last_trained)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                model_data = excluded.model_data,
                baseline_metrics = excluded.baseline_metrics,
                last_trained = CURRENT_TIMESTAMP
        ''', (self.user_id, model_blob, f"Samples: {len(self.feature_buffer)}"))
        conn.commit()
        conn.close()

        user_desc = f"User ID {self.user_id}" + (f" ({self.username})" if self.username else "")
        print(f"[+] Baseline successfully built and saved to database for {user_desc}! ({len(self.feature_buffer)} samples used)")
        return True

    def load_baseline(self):
        """Loads serialized baseline model for this user from SQLite."""
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT model_data FROM user_baselines WHERE user_id = ?", (self.user_id,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            self.model = pickle.loads(row[0])
            self.is_trained = True
            print(f"[+] Successfully loaded baseline model for User ID {self.user_id}.")
            return True
        else:
            print(f"[-] No baseline model found for User ID {self.user_id}. Please run in --mode train first.")
            return False

    def _update_and_get_window(self, source_ip, packet):
        """Updates sliding window for source_ip and prunes records older than window_size."""
        now = time.time()
        dest_port = packet.get("dest_port", 0)
        protocol = str(packet.get("protocol", "")).upper()
        pkt_size = packet.get("packet_size", 0)

        win = self.ip_windows[source_ip]
        win.append((now, dest_port, protocol, pkt_size))

        # Prune packets older than window_size (e.g., 5 seconds)
        cutoff = now - self.window_size
        while win and win[0][0] < cutoff:
            win.popleft()

        return win

    def analyze_packet(self, packet):
        """Evaluates live packet against baseline, DLP rules, and stateful attack signatures."""
        is_anomaly = False
        reasons = []

        source_ip = packet.get("source_ip")
        dest_ip = packet.get("dest_ip")
        payload_size = packet.get("payload_size", 0)
        packet_size = packet.get("packet_size", 0)
        dest_port = packet.get("dest_port", 0)

        # 1. Check Whitelist: Never flag or block whitelisted IPs
        if source_ip and database.get_ip_rule(source_ip) == "WHITELIST":
            return False, []

        # 2. DLP Check: Destination Blacklisted
        if dest_ip and database.get_ip_rule(dest_ip) == "BLACKLIST":
            is_anomaly = True
            reasons.append(f"Malicious Target Attempt: Connection to blacklisted IP {dest_ip}")

        # 3. DLP Check: Large Outbound Payload
        if payload_size > MAX_PAYLOAD_SIZE:
            is_anomaly = True
            reasons.append(f"Data Exfiltration Risk: Payload ({payload_size} B) exceeds 50KB limit")

        # 4. Stateful Traffic Pattern Analysis (DDoS, Port Scan, Ping Flood)
        if source_ip:
            win = self._update_and_get_window(source_ip, packet)

            # 4a. Port Scan Detection
            unique_ports = len(set(p[1] for p in win if p[1]))
            if unique_ports > 20:
                is_anomaly = True
                reasons.append(f"Port Scanning Detected: {unique_ports} unique ports accessed in {int(self.window_size)}s")

            # 4b. ICMP Ping Flood Detection
            icmp_count = sum(1 for p in win if p[2] in ("ICMP", "1"))
            if icmp_count > 50:
                is_anomaly = True
                reasons.append(f"Ping Flood Detected: {icmp_count} ICMP packets in {int(self.window_size)}s")

            # 4c. DDoS / Traffic Spike Detection
            pkt_count = len(win)
            if pkt_count > 200:
                is_anomaly = True
                reasons.append(f"DDoS Traffic Spike: {pkt_count} packets in {int(self.window_size)}s")

        # 5. UEBA Check: Compare against loaded baseline ML model
        if self.is_trained:
            features = self.extract_features(packet)
            prediction = self.model.predict([features])[0]
            if prediction == -1:
                is_anomaly = True
                reasons.append(f"Behavioral Anomaly: Deviates from baseline (Port {dest_port}, Size {packet_size} B)")

        return is_anomaly, reasons

def main():
    parser = argparse.ArgumentParser(description="UTM Layer 2 UEBA & DLP Engine")
    parser.add_argument("--mode", choices=["train", "detect"], default="detect", help="Mode: 'train' to record baseline, 'detect' to evaluate live traffic")
    parser.add_argument("--samples", type=int, default=None, help="Number of packets to collect in training mode before saving baseline")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds for baseline training mode (e.g., 3600 for 1 hour)")
    parser.add_argument("--user_id", type=int, default=1, help="ID of the authenticated user")
    parser.add_argument("--username", type=str, default=None, help="Username associated with the user_id")
    args = parser.parse_args()

    database.init_db()
    engine = UEBAEngine(user_id=args.user_id, username=args.username)

    # Set default sample limit to 200 if neither samples nor duration is specified
    max_samples = args.samples if args.samples is not None else (200 if args.duration is None else None)

    if args.mode == "train":
        start_time = time.time()
        duration_str = f"{args.duration}s duration" if args.duration else ""
        sample_str = f"{max_samples} samples" if max_samples else ""
        limit_desc = " and ".join(filter(None, [sample_str, duration_str])) or "until stream ends"

        print(f"[+] TRAIN MODE ACTIVE for User ID {args.user_id} ({args.username or 'Default'}): Collecting baseline ({limit_desc})...")
        count = 0
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    packet = json.loads(line)
                    engine.collect_sample(packet)
                    count += 1
                    database.log_packet(packet, is_anomaly=False, user_id=engine.user_id)
                    
                    elapsed = time.time() - start_time
                    print(f"\r[{count} packets recorded | {int(elapsed)}s elapsed]", end="", flush=True)

                    # Check termination conditions
                    if max_samples and count >= max_samples:
                        print("\n[+] Reached sample limit.")
                        break
                    if args.duration and elapsed >= args.duration:
                        print("\n[+] Reached training duration limit.")
                        break
                except json.JSONDecodeError:
                    continue
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user. Finalizing current baseline...")

        print()
        engine.finalize_and_save_baseline()

    elif args.mode == "detect":
        if not engine.load_baseline():
            print(f"[-] Cannot start detection without a trained baseline for User ID {args.user_id}. Run with --mode train first.")
            sys.exit(1)

        print(f"[+] DETECTION MODE ACTIVE for User ID {args.user_id}: Evaluating live stream against baseline...")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
                is_anomaly, reasons = engine.analyze_packet(packet)
                database.log_packet(packet, is_anomaly=is_anomaly, user_id=engine.user_id)

                if is_anomaly:
                    reason_str = ", ".join(reasons)
                    
                    # Target dest_ip if connection to a blacklisted IP, otherwise source_ip
                    if any("blacklisted IP" in r for r in reasons):
                        target_ip = packet.get("dest_ip")
                    else:
                        target_ip = packet.get("source_ip")

                    # Add BLOCKED rule with 15-minute TTL if not Whitelisted or already Blocked
                    if target_ip and database.get_ip_rule(target_ip) not in ("WHITELIST", "BLOCKED"):
                        database.add_or_update_ip_rule(
                            ip_address=target_ip, 
                            rule_type="BLOCKED", 
                            reason=f"Auto-Block ({reason_str})", 
                            ttl_seconds=900
                        )

                    print(f"[!] ANOMALY DETECTED & BLOCKED: {target_ip} | Reasons: {reason_str}")
                else:
                    print(f"[OK] Packet matches baseline: {packet.get('source_ip')} -> {packet.get('dest_ip')}:{packet.get('dest_port')}")
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main()
