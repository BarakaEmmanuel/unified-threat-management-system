import sys
import json
import pickle
import argparse
import numpy as np
from sklearn.ensemble import IsolationForest
import database

MAX_PAYLOAD_SIZE = 50000  # DLP threshold: 50KB

class UEBAEngine:
    def __init__(self, user_id=1):
        self.user_id = user_id
        self.model = IsolationForest(contamination=0.02, random_state=42)
        self.feature_buffer = []
        self.is_trained = False

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
                last_trained = CURRENT_TIMESTAMP
        ''', (self.user_id, model_blob, f"Samples: {len(self.feature_buffer)}"))
        conn.commit()
        conn.close()

        print(f"[+] Baseline successfully built and saved to database for User ID {self.user_id}! ({len(self.feature_buffer)} samples used)")
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

    def analyze_packet(self, packet):
        """Evaluates live packet against loaded baseline and DLP rules."""
        is_anomaly = False
        reasons = []

        # 1. Check Whitelist: Never flag or block whitelisted IPs
        source_ip = packet.get("source_ip")
        if database.get_ip_rule(source_ip) == "WHITELIST":
            return False, []

        # 2. DLP Check: Destination Blacklisted
        dest_ip = packet.get("dest_ip")
        if database.get_ip_rule(dest_ip) == "BLACKLIST":
            is_anomaly = True
            reasons.append("DESTINATION_BLACKLISTED")

        # 3. DLP Check: Large Outbound Payload
        if packet.get("payload_size", 0) > MAX_PAYLOAD_SIZE:
            is_anomaly = True
            reasons.append("EXCESSIVE_PAYLOAD_SIZE")

        # 4. UEBA Check: Compare against loaded baseline model
        if self.is_trained:
            features = self.extract_features(packet)
            prediction = self.model.predict([features])[0]
            if prediction == -1:
                is_anomaly = True
                reasons.append("BEHAVIORAL_ANOMALY")

        return is_anomaly, reasons

def main():
    parser = argparse.ArgumentParser(description="UTM Layer 2 UEBA & DLP Engine")
    parser.add_argument("--mode", choices=["train", "detect"], default="detect", help="Mode: 'train' to record baseline, 'detect' to evaluate live traffic")
    parser.add_argument("--samples", type=int, default=200, help="Number of packets to collect in training mode before saving baseline")
    parser.add_argument("--user_id", type=int, default=1, help="ID of the authenticated user")
    args = parser.parse_args()

    database.init_db()
    engine = UEBAEngine(user_id=args.user_id)

    if args.mode == "train":
        print(f"[+] TRAIN MODE ACTIVE for User ID {args.user_id}: Collecting {args.samples} packets to establish baseline...")
        count = 0
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
                engine.collect_sample(packet)
                count += 1
                database.log_packet(packet, is_anomaly=False, user_id=engine.user_id)
                print(f"[{count}/{args.samples}] Recording baseline packet...", end="\r")

                if count >= args.samples:
                    print()
                    engine.finalize_and_save_baseline()
                    break
            except json.JSONDecodeError:
                continue

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
                    
                    # Target dest_ip if blacklisted target, otherwise source_ip
                    if "DESTINATION_BLACKLISTED" in reasons:
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
                    print(f"[OK] Packet matches baseline: {packet['source_ip']} -> {packet['dest_ip']}:{packet['dest_port']}")
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main()
