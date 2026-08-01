import sqlite3
import time
import os
import hashlib

DB_NAME = "utm_security.db"

def get_connection():
    """Establishes and returns a database connection with WAL mode and busy timeouts."""
    conn = sqlite3.connect(DB_NAME, timeout=10.0)
    conn.execute("PRAGMA foreign_keys = ON;")
    # Enable Write-Ahead Logging for multi-process concurrency (GUI, Sniffer, Daemon)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def init_db():
    """Initializes database tables, migrations, and performs 30-day log cleanup."""
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
            rule_type TEXT CHECK(rule_type IN ('WHITELIST', 'BLACKLIST', 'BLOCKED')),
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_at INTEGER,
            expires_at INTEGER,
            is_active INTEGER DEFAULT 0
        )
    ''')

    # Migration check for existing databases (adds missing TTL columns safely)
    cursor.execute("PRAGMA table_info(ip_rules);")
    columns = [col[1] for col in cursor.fetchall()]
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
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            payload_size INTEGER,
            is_anomaly BOOLEAN DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    purge_old_logs(conn)
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

def add_or_update_ip_rule(ip_address, rule_type, reason="User manual action", ttl_seconds=900):
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
        INSERT INTO ip_rules (ip_address, rule_type, reason, blocked_at, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(ip_address) DO UPDATE SET
            rule_type=excluded.rule_type,
            reason=excluded.reason,
            created_at=CURRENT_TIMESTAMP,
            blocked_at=excluded.blocked_at,
            expires_at=excluded.expires_at,
            is_active=0
    ''', (ip_address, rule_type, reason, now, expires_at))
    conn.commit()
    conn.close()

def delete_ip_rule(ip_address):
    """Removes an IP rule from DB."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_rules WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()

def get_ip_rules(rule_type=None):
    """Fetches active/current IP rules."""
    conn = get_connection()
    cursor = conn.cursor()
    if rule_type:
        cursor.execute("""
            SELECT ip_address, rule_type, reason, created_at, expires_at 
            FROM ip_rules WHERE rule_type = ? ORDER BY created_at DESC
        """, (rule_type,))
    else:
        cursor.execute("""
            SELECT ip_address, rule_type, reason, created_at, expires_at 
            FROM ip_rules ORDER BY created_at DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_ip_rule(ip_address):
    """Fetches the rule_type ('WHITELIST', 'BLACKLIST', 'BLOCKED') for a specific IP if present."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT rule_type FROM ip_rules WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

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

if __name__ == "__main__":
    init_db()
    print("[+] Database initialized successfully with WAL mode and TTL schema extensions.")
