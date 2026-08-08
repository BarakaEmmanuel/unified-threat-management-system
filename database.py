import sqlite3
import time
import os
import hashlib

# Import lookup engine for IP context mapping during 5-minute telemetry aggregation
try:
    import lookup_engine
except ImportError:
    lookup_engine = None

DB_NAME = "utm_security.db"

def get_connection():
    """Establishes and returns a database connection with WAL mode and busy timeouts."""
    conn = sqlite3.connect(DB_NAME, timeout=10.0)
    conn.execute("PRAGMA foreign_keys = ON;")
    # Enable Write-Ahead Logging for multi-process concurrency (GUI, Sniffer, Daemon)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 10000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db():
    """Initializes database tables, migrations, indexes, and performs log & rule cleanups."""
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. User Baselines
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_baselines (
            user_id INTEGER PRIMARY KEY,
            model_data BLOB,
            baseline_metrics TEXT,
            last_trained TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # 3. IP Management Rules
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_rules (
            ip_address TEXT PRIMARY KEY,
            dest_ip TEXT DEFAULT 'N/A',
            rule_type TEXT CHECK(rule_type IN ('WHITELIST', 'BLACKLIST', 'BLOCKED')),
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_at INTEGER,
            expires_at INTEGER,
            is_active INTEGER DEFAULT 0
        )
    ''')

    # Migration check for existing databases (adds missing columns safely)
    cursor.execute("PRAGMA table_info(ip_rules);")
    columns = [col[1] for col in cursor.fetchall()]
    if "dest_ip" not in columns:
        cursor.execute("ALTER TABLE ip_rules ADD COLUMN dest_ip TEXT DEFAULT 'N/A';")
    if "blocked_at" not in columns:
        cursor.execute("ALTER TABLE ip_rules ADD COLUMN blocked_at INTEGER;")
    if "expires_at" not in columns:
        cursor.execute("ALTER TABLE ip_rules ADD COLUMN expires_at INTEGER;")
    if "is_active" not in columns:
        cursor.execute("ALTER TABLE ip_rules ADD COLUMN is_active INTEGER DEFAULT 0;")

    # 4. Packet / Anomaly Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER DEFAULT 0,
            dest_port INTEGER DEFAULT 0,
            protocol TEXT,
            packet_size INTEGER DEFAULT 0,
            payload_size INTEGER DEFAULT 0,
            is_anomaly BOOLEAN DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Migration check for packet_logs
    cursor.execute("PRAGMA table_info(packet_logs);")
    p_cols = [col[1] for col in cursor.fetchall()]
    if "payload_size" not in p_cols:
        cursor.execute("ALTER TABLE packet_logs ADD COLUMN payload_size INTEGER DEFAULT 0;")
    if "source_port" not in p_cols:
        cursor.execute("ALTER TABLE packet_logs ADD COLUMN source_port INTEGER DEFAULT 0;")

    # Indexes to optimize subqueries and aggregation performance across packet logs
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packet_logs_source_ip ON packet_logs(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packet_logs_dest_ip ON packet_logs(dest_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packet_logs_timestamp ON packet_logs(timestamp);")

    # 5. Connected Devices Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connected_devices (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            hostname TEXT DEFAULT 'Unknown',
            detected_os TEXT DEFAULT 'Unknown',
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 6. MAC Vendor Lookup Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mac_vendors (
            oui TEXT PRIMARY KEY,
            vendor TEXT NOT NULL
        )
    ''')

    # Seed initial OUI records if table is empty
    cursor.execute("SELECT COUNT(*) FROM mac_vendors")
    if cursor.fetchone()[0] == 0:
        default_ouis = [
            ("5CC5D4", "Apple"), ("D260A4", "Apple"), ("90EC77", "Apple"), ("5C5B35", "Apple"),
            ("F4D488", "Apple"), ("A45E60", "Apple"), ("DCA904", "Apple"), ("BC8CCD", "Apple"),
            ("FC6B01", "Samsung"), ("2C1F23", "Samsung"), ("E4E705", "Samsung"), ("507705", "Samsung"),
            ("64A2F9", "Xiaomi"), ("185680", "Xiaomi"), ("047504", "Huawei"), ("A44519", "Xiaomi"),
            ("000C29", "VMware"), ("005056", "VMware"), ("080027", "VirtualBox"), ("525400", "QEMU/KVM"),
            ("00155D", "Hyper-V"), ("B827EB", "Raspberry Pi"), ("DCA632", "Raspberry Pi"), ("E45F01", "Raspberry Pi"),
            ("001A11", "Google"), ("3C5AB4", "Google"), ("503EA1", "TP-Link"), ("E848B8", "TP-Link"),
            ("0014D1", "TrendsNet"), ("C025E9", "TP-Link"), ("6045CB", "Espressif (IoT)"), ("240AC4", "Espressif (IoT)")
        ]
        cursor.executemany("INSERT OR IGNORE INTO mac_vendors (oui, vendor) VALUES (?, ?)", default_ouis)

    conn.commit()
    cleanup_expired_rules(conn)
    purge_old_logs(conn)
    conn.close()

def cleanup_expired_rules(conn=None):
    """Removes expired temporary BLOCKED rules from the database."""
    close_conn = False
    if conn is None:
        conn = get_connection()
        close_conn = True

    now = int(time.time())
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_rules WHERE rule_type = 'BLOCKED' AND expires_at IS NOT NULL AND expires_at <= ?", (now,))
    conn.commit()

    if close_conn:
        conn.close()

def purge_old_logs(conn=None):
    """Deletes packet logs older than 30 days (2,592,000 seconds)."""
    close_conn = False
    if conn is None:
        conn = get_connection()
        close_conn = True

    cutoff_time = int(time.time()) - (30 * 24 * 3600)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM packet_logs WHERE timestamp < ?", (cutoff_time,))
    conn.commit()

    if close_conn:
        conn.close()

def log_packet(packet, is_anomaly=False, user_id=1):
    """Inserts processed packet details and analysis flags into SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packet_logs 
        (timestamp, user_id, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, payload_size, is_anomaly)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        packet.get("timestamp", int(time.time())),
        user_id,
        packet.get("source_ip"),
        packet.get("dest_ip"),
        packet.get("source_port", 0),
        packet.get("dest_port", 0),
        packet.get("protocol", "UNKNOWN"),
        packet.get("packet_size", 0),
        packet.get("payload_size", 0),
        1 if is_anomaly else 0
    ))
    conn.commit()
    conn.close()

# --- AUTHENTICATION HELPERS ---

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def register_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return True, user_id
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already taken."
    except Exception as e:
        conn.close()
        return False, str(e)

def verify_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and row[1] == hash_password(password):
        return True, row[0]
    return False, None

# --- IP RULE & TTL MANAGEMENT HELPERS ---

def add_or_update_ip_rule(ip_address, rule_type, reason="User manual action", ttl_seconds=900, dest_ip="N/A"):
    """
    Adds or updates an IP rule.
    If rule_type is 'BLOCKED', sets a 15-minute TTL (default 900s).
    If 'BLACKLIST' or 'WHITELIST', expires_at is NULL (permanent).
    """
    conn = get_connection()
    cursor = conn.cursor()
    now = int(time.time())
    
    expires_at = (now + ttl_seconds) if rule_type == "BLOCKED" else None

    cursor.execute('''
        INSERT INTO ip_rules (ip_address, dest_ip, rule_type, reason, blocked_at, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(ip_address) DO UPDATE SET
            dest_ip=excluded.dest_ip,
            rule_type=excluded.rule_type,
            reason=excluded.reason,
            created_at=CURRENT_TIMESTAMP,
            blocked_at=excluded.blocked_at,
            expires_at=excluded.expires_at,
            is_active=0
    ''', (ip_address, dest_ip or "N/A", rule_type, reason, now, expires_at))
    conn.commit()
    conn.close()

def delete_ip_rule(ip_address, dest_ip=None):
    """Removes an IP rule from DB with optional dest_ip matching."""
    conn = get_connection()
    cursor = conn.cursor()
    if dest_ip and dest_ip != "N/A":
        cursor.execute("DELETE FROM ip_rules WHERE ip_address = ? AND dest_ip = ?", (ip_address, dest_ip))
    else:
        cursor.execute("DELETE FROM ip_rules WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()

def get_ip_rules(rule_type=None):
    """Fetches active/current IP rules, purging expired blocks beforehand."""
    cleanup_expired_rules()
    conn = get_connection()
    cursor = conn.cursor()
    if rule_type:
        cursor.execute("""
            SELECT ip_address, dest_ip, rule_type, reason, created_at, expires_at 
            FROM ip_rules WHERE rule_type = ? ORDER BY created_at DESC
        """, (rule_type,))
    else:
        cursor.execute("""
            SELECT ip_address, dest_ip, rule_type, reason, created_at, expires_at 
            FROM ip_rules ORDER BY created_at DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_ip_rule(ip_address):
    """Fetches the rule_type ('WHITELIST', 'BLACKLIST', 'BLOCKED') for a specific IP if present and unexpired."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT rule_type, expires_at FROM ip_rules WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    conn.close()

    if row:
        rule_type, expires_at = row[0], row[1]
        if expires_at and int(time.time()) > expires_at:
            cleanup_expired_rules()
            return None
        return rule_type
    return None

def get_unapplied_ip_rules():
    """Fetches rules that need to be synced to the firewall kernel by Layer 4 daemon."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, rule_type FROM ip_rules WHERE is_active = 0")
    rows = cursor.fetchall()
    conn.close()
    return rows

def mark_rule_as_active(ip_address):
    """Marks rule as applied in kernel firewall."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE ip_rules SET is_active = 1 WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()

def get_expired_blocked_ips():
    """Fetches temporary blocks that exceeded their 15-minute TTL."""
    conn = get_connection()
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute("""
        SELECT ip_address FROM ip_rules 
        WHERE rule_type = 'BLOCKED' AND expires_at IS NOT NULL AND expires_at <= ?
    """, (now,))
    rows = [r[0] for r in cursor.fetchall()]
    conn.close()
    return rows

def get_recent_packet_logs(limit=100):
    """Fetches recent packet logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, is_anomaly
        FROM packet_logs ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_dashboard_stats():
    """Queries current metrics for header status and dashboard cards."""
    cleanup_expired_rules()
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM packet_logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM packet_logs WHERE is_anomaly = 1")
    total_anomalies = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ip_rules WHERE rule_type = 'BLACKLIST'")
    blacklisted = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ip_rules WHERE rule_type = 'WHITELIST'")
    whitelisted = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ip_rules WHERE rule_type = 'BLOCKED'")
    blocked = cursor.fetchone()[0]
    
    conn.close()
    return {
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "blacklisted": blacklisted,
        "whitelisted": whitelisted,
        "blocked": blocked
    }

# --- CONNECTED DEVICES HELPERS ---

def upsert_connected_device(ip, mac="00:00:00:00:00:00", hostname="Unknown", detected_os="Unknown", bytes_in=0, bytes_out=0):
    """Inserts or updates an active network endpoint in the connected_devices table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO connected_devices (ip_address, mac_address, hostname, detected_os, bytes_in, bytes_out, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(ip_address) DO UPDATE SET
            mac_address=excluded.mac_address,
            hostname=excluded.hostname,
            detected_os=excluded.detected_os,
            bytes_in=connected_devices.bytes_in + excluded.bytes_in,
            bytes_out=connected_devices.bytes_out + excluded.bytes_out,
            last_seen=CURRENT_TIMESTAMP
    """, (ip, mac, hostname, detected_os, bytes_in, bytes_out))
    conn.commit()
    conn.close()

def get_connected_devices():
    """
    Fetches discovered endpoints while dynamically computing total traffic volume 
    (bytes_in and bytes_out) by aggregating packet_logs against device IP addresses.
    Includes local timezone conversion and active IP rule association.
    """
    cleanup_expired_rules()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            d.ip_address, 
            d.mac_address, 
            d.hostname, 
            d.detected_os,
            d.bytes_in + COALESCE((SELECT SUM(packet_size) FROM packet_logs WHERE dest_ip = d.ip_address), 0) AS total_bytes_in,
            d.bytes_out + COALESCE((SELECT SUM(packet_size) FROM packet_logs WHERE source_ip = d.ip_address), 0) AS total_bytes_out,
            datetime(d.last_seen, 'localtime') AS last_seen,
            r.rule_type
        FROM connected_devices d
        LEFT JOIN ip_rules r ON d.ip_address = r.ip_address
        ORDER BY d.last_seen DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "ip_address": r[0],
            "mac_address": r[1],
            "hostname": r[2],
            "detected_os": r[3],
            "bytes_in": r[4],
            "bytes_out": r[5],
            "last_seen": r[6],
            "rule_type": r[7]
        }
        for r in rows
    ]

def lookup_mac_vendor(mac):
    """Queries SQLite for MAC OUI vendor without holding full lookup table in memory."""
    if not mac or mac in ("LOCAL_HOST", "N/A"):
        return None
    clean_mac = mac.upper().replace(":", "").replace("-", "")[:6]
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT vendor FROM mac_vendors WHERE oui = ?", (clean_mac,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

# --- TIME-SERIES 5-MINUTE AGGREGATIONS FOR GUI PLOTTING ---

def get_traffic_context_stats_5min(num_buckets=12):
    """
    Groups packet logs into 5-minute (300s) time buckets.
    Returns x time values and metric arrays: (x, anomalies, unknown, google, cdn, local).
    """
    now = int(time.time())
    bucket_size = 300
    start_time = now - (num_buckets * bucket_size)
    
    x_buckets = [start_time + (i * bucket_size) for i in range(num_buckets)]
    anomalies = [0] * num_buckets
    unknown = [0] * num_buckets
    google = [0] * num_buckets
    cdn = [0] * num_buckets
    local = [0] * num_buckets

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, dest_ip, source_ip, is_anomaly
        FROM packet_logs
        WHERE timestamp >= ?
    """, (start_time,))
    logs = cursor.fetchall()
    conn.close()

    for ts, dest_ip, src_ip, is_anom in logs:
        idx = min(int((ts - start_time) / bucket_size), num_buckets - 1)
        if idx < 0:
            continue

        if is_anom:
            anomalies[idx] += 1

        target_ip = dest_ip if dest_ip not in ("N/A", "", None) else src_ip
        ctx = lookup_engine.lookup_ip_context(target_ip) if lookup_engine else "Unknown"

        if "Google" in ctx:
            google[idx] += 1
        elif "CDN" in ctx or "Cloudflare" in ctx or "Fastly" in ctx:
            cdn[idx] += 1
        elif "Local" in ctx or "Private Network" in ctx:
            local[idx] += 1
        else:
            unknown[idx] += 1

    return x_buckets, anomalies, unknown, google, cdn, local

def get_rule_hits_stats_5min(num_buckets=12):
    """
    Aggregates policy rule action occurrences into 5-minute (300s) buckets.
    Returns x time values and metric arrays: (x, whitelist_hits, blacklist_hits, blocked_hits).
    """
    cleanup_expired_rules()
    now = int(time.time())
    bucket_size = 300
    start_time = now - (num_buckets * bucket_size)

    x_buckets = [start_time + (i * bucket_size) for i in range(num_buckets)]
    white_hits = [0] * num_buckets
    black_hits = [0] * num_buckets
    block_hits = [0] * num_buckets

    conn = get_connection()
    cursor = conn.cursor()

    # Pre-fetch IP rule categories (maps both source_ip and dest_ip fields)
    cursor.execute("SELECT ip_address, dest_ip, rule_type FROM ip_rules")
    rule_map = {}
    for row in cursor.fetchall():
        if row[0]:
            rule_map[row[0]] = row[2]
        if row[1] and row[1] != 'N/A':
            rule_map[row[1]] = row[2]

    cursor.execute("""
        SELECT timestamp, source_ip, dest_ip
        FROM packet_logs
        WHERE timestamp >= ?
    """, (start_time,))
    logs = cursor.fetchall()
    conn.close()

    for ts, src_ip, dest_ip in logs:
        idx = min(int((ts - start_time) / bucket_size), num_buckets - 1)
        if idx < 0:
            continue

        rule_type = rule_map.get(src_ip) or rule_map.get(dest_ip)
        if rule_type == "WHITELIST":
            white_hits[idx] += 1
        elif rule_type == "BLACKLIST":
            black_hits[idx] += 1
        elif rule_type == "BLOCKED":
            block_hits[idx] += 1

    return x_buckets, white_hits, black_hits, block_hits

if __name__ == "__main__":
    init_db()
    print("[+] Database initialized with WAL mode, busy timeout (10s), and synchronous NORMAL mode.")
