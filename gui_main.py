import sys
import time
import subprocess
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QStackedWidget, QFrame, QHeaderView, QMenu, QDialog, QFormLayout,
    QComboBox, QMessageBox, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, QPointF
from PyQt6.QtGui import QFont, QAction, QCursor, QPainter, QPainterPath, QPen, QColor

try:
    import pyqtgraph as pg
    pg.setConfigOption('background', '#1e293b')
    pg.setConfigOption('foreground', '#f8fafc')
    pg.setConfigOptions(antialias=True)
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False

import database
import lookup_engine

# --- ASYNC TELEMETRY WORKER THREAD ---
class TelemetryWorker(QThread):
    """
    Executes database queries & lookup engine context resolutions in a background thread.
    Prevents database locks & disk/I/O latency from blocking the Qt GUI event loop.
    """
    telemetry_updated = pyqtSignal(dict)

    def __init__(self, user_id, interval_ms=2000, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.interval_ms = interval_ms
        self._is_running = True

    def run(self):
        while self._is_running:
            try:
                stats = database.get_dashboard_stats() or {}
                logs = database.get_recent_packet_logs(50) or []
                
                # Pre-evaluate IP context resolutions off the main thread
                resolved_logs = []
                for log in logs:
                    dest_ip = str(log[3]) if len(log) > 3 else "N/A"
                    src_ip = str(log[2]) if len(log) > 2 else "N/A"
                    raw_ip = dest_ip.split(":")[0] if ":" in dest_ip else dest_ip
                    lookup_target = raw_ip if raw_ip not in ("N/A", "", "0.0.0.0") else src_ip
                    ctx = lookup_engine.lookup_ip_context(lookup_target)
                    resolved_logs.append((log, ctx))

                rules = {}
                resolved_rules = {}
                active_rules_map = {}

                for r_type in ["BLACKLIST", "WHITELIST", "BLOCKED"]:
                    r_data = database.get_ip_rules(r_type) or []
                    rules[r_type] = r_data
                    r_resolved = []
                    for rule in r_data:
                        ip_addr = rule[0] if len(rule) > 0 else "N/A"
                        d_ip = rule[1] if len(rule) > 1 and rule[1] else "N/A"
                        if ip_addr != "N/A":
                            active_rules_map[ip_addr] = r_type
                        ctx_target = d_ip if d_ip != "N/A" else ip_addr
                        r_ctx = lookup_engine.lookup_ip_context(ctx_target)
                        r_resolved.append((rule, r_ctx))
                    resolved_rules[r_type] = r_resolved

                ctx_stats = None
                if hasattr(database, "get_traffic_context_stats_5min"):
                    ctx_stats = database.get_traffic_context_stats_5min()

                rule_stats = None
                if hasattr(database, "get_rule_hits_stats_5min"):
                    rule_stats = database.get_rule_hits_stats_5min()

                devices = []
                if hasattr(database, "get_connected_devices"):
                    raw_devices = database.get_connected_devices() or []
                    for dev in raw_devices:
                        d_info = dict(dev) if isinstance(dev, dict) else {}
                        dev_ip = str(d_info.get("ip_address", "N/A"))
                        d_info["active_rule"] = active_rules_map.get(dev_ip, "NONE")
                        devices.append(d_info)

                payload = {
                    "stats": stats,
                    "logs": resolved_logs,
                    "rules": resolved_rules,
                    "ctx_stats": ctx_stats,
                    "rule_stats": rule_stats,
                    "devices": devices
                }
                self.telemetry_updated.emit(payload)
            except Exception as e:
                print(f"[-] Telemetry Worker fetch error: {e}")

            self.msleep(self.interval_ms)

    def stop(self):
        self._is_running = False
        self.quit()
        self.wait()


# --- CUSTOM PYQTGRAPH TIME AXIS ITEM ---
if PYQTGRAPH_AVAILABLE:
    class TimeAxisItem(pg.AxisItem):
        def tickStrings(self, values, scale, spacing):
            strings = []
            for v in values:
                if v > 1000000:  # Epoch timestamp
                    strings.append(time.strftime('%H:%M:%S', time.localtime(v)))
                else:
                    strings.append(f"T-{int(v)}m")
            return strings

# --- GLOBAL THEME STYLESHEETS ---
DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #0f172a;
}
QWidget {
    color: #f8fafc;
    font-family: 'Segoe UI', Inter, sans-serif;
}

QMessageBox {
    background-color: #1e293b;
}
QMessageBox QLabel {
    color: #f8fafc;
    font-size: 13px;
}
QMessageBox QPushButton {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    padding: 6px 14px;
    border-radius: 6px;
    font-weight: bold;
}
QMessageBox QPushButton:hover {
    background-color: #475569;
}

#HeaderBar {
    background-color: #1e293b;
    border-bottom: 1px solid #334155;
    padding: 8px 16px;
}
#ThemeToggleBtn {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 12px;
    padding: 5px 14px;
    font-weight: bold;
    font-size: 12px;
}
#ThemeToggleBtn:hover {
    background-color: #475569;
    border-color: #6366f1;
}

#UserMenuBtn {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 8px;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 13px;
}
#UserMenuBtn:hover {
    background-color: #475569;
    border-color: #6366f1;
}
#UserMenuBtn::menu-indicator {
    image: none;
    width: 0px;
}

#Sidebar {
    background-color: #1e293b;
    border-right: 1px solid #334155;
}
QPushButton.NavBtn {
    background-color: transparent;
    color: #94a3b8;
    border: none;
    text-align: left;
    padding: 12px 16px;
    font-size: 14px;
    font-weight: 500;
    border-radius: 8px;
}
QPushButton.NavBtn:hover {
    background-color: #334155;
    color: #f8fafc;
}

#ToggleBtn {
    background-color: #334155;
    color: #f8fafc;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    padding: 6px;
}
#ToggleBtn:hover {
    background-color: #475569;
}

#ActivityFrame, #GraphFrame {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 15px;
}

QTableWidget {
    background-color: #1e293b;
    border: 1px solid #334155;
    gridline-color: #334155;
    border-radius: 8px;
    color: #f8fafc;
    selection-background-color: #4f46e5;
}
QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 8px;
    border: none;
    font-weight: bold;
}

QScrollArea {
    border: none;
    background-color: transparent;
}

QMenu {
    background-color: #1e293b;
    border: 1px solid #475569;
    color: #f8fafc;
    padding: 5px;
}
QMenu::item {
    padding: 8px 16px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #6366f1;
    color: #ffffff;
}

QLineEdit {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 10px;
    color: #f8fafc;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #6366f1;
}

QPushButton.CsvBtn {
    background-color: #334155;
    color: #38bdf8;
    border: 1px solid #0284c7;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
    font-size: 12px;
}
QPushButton.CsvBtn:hover {
    background-color: #0284c7;
    color: #ffffff;
}
"""

LIGHT_STYLE = """
QMainWindow, QDialog {
    background-color: #f8fafc;
}
QWidget {
    color: #0f172a;
    font-family: 'Segoe UI', Inter, sans-serif;
}

QMessageBox {
    background-color: #ffffff;
}
QMessageBox QLabel {
    color: #0f172a;
    font-size: 13px;
}
QMessageBox QPushButton {
    background-color: #e2e8f0;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    padding: 6px 14px;
    border-radius: 6px;
    font-weight: bold;
}
QMessageBox QPushButton:hover {
    background-color: #cbd5e1;
}

#HeaderBar {
    background-color: #ffffff;
    border-bottom: 1px solid #e2e8f0;
    padding: 8px 16px;
}
#ThemeToggleBtn {
    background-color: #e0f2fe;
    color: #0369a1;
    border: 1px solid #7dd3fc;
    border-radius: 12px;
    padding: 5px 14px;
    font-weight: bold;
    font-size: 12px;
}
#ThemeToggleBtn:hover {
    background-color: #bae6fd;
    border-color: #0284c7;
}

#UserMenuBtn {
    background-color: #f1f5f9;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 5px 14px;
    font-weight: 600;
    font-size: 13px;
}
#UserMenuBtn:hover {
    background-color: #e2e8f0;
    border-color: #6366f1;
}
#UserMenuBtn::menu-indicator {
    image: none;
    width: 0px;
}

#Sidebar {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}
QPushButton.NavBtn {
    background-color: transparent;
    color: #64748b;
    border: none;
    text-align: left;
    padding: 12px 16px;
    font-size: 14px;
    font-weight: 500;
    border-radius: 8px;
}
QPushButton.NavBtn:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

#ToggleBtn {
    background-color: #e2e8f0;
    color: #0f172a;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    padding: 6px;
}
#ToggleBtn:hover {
    background-color: #cbd5e1;
}

#ActivityFrame, #GraphFrame {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 15px;
}

QTableWidget {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    gridline-color: #e2e8f0;
    border-radius: 8px;
    color: #0f172a;
    selection-background-color: #6366f1;
    selection-color: #ffffff;
}
QHeaderView::section {
    background-color: #f1f5f9;
    color: #475569;
    padding: 8px;
    border: none;
    font-weight: bold;
}

QScrollArea {
    border: none;
    background-color: transparent;
}

QMenu {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    color: #0f172a;
    padding: 5px;
}
QMenu::item {
    padding: 8px 16px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #6366f1;
    color: #ffffff;
}

QLineEdit {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 10px;
    color: #0f172a;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #6366f1;
}

QPushButton.CsvBtn {
    background-color: #e0f2fe;
    color: #0369a1;
    border: 1px solid #0284c7;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
    font-size: 12px;
}
QPushButton.CsvBtn:hover {
    background-color: #0284c7;
    color: #ffffff;
}
"""


# --- CONNECTED DEVICE CARD WIDGET ---
class DeviceCard(QFrame):
    def __init__(self, dev_info, on_action_callback, is_dark=True):
        super().__init__()
        self.dev_info = dev_info or {}
        self.on_action_callback = on_action_callback
        self.is_dark = is_dark
        self.active_rule = str(self.dev_info.get("active_rule", "NONE")).upper()
        
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        bg_color = "#1e293b" if is_dark else "#ffffff"
        hover_bg = "#24334a" if is_dark else "#f1f5f9"
        border_color = "#334155" if is_dark else "#cbd5e1"
        title_color = "#f8fafc" if is_dark else "#0f172a"
        sub_text_color = "#cbd5e1" if is_dark else "#334155"
        muted_text = "#94a3b8" if is_dark else "#64748b"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-left: 5px solid #6366f1;
                border-radius: 10px;
                padding: 14px;
            }}
            QFrame:hover {{
                background-color: {hover_bg};
                border-color: #818cf8;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(4)

        ip = str(self.dev_info.get("ip_address", "N/A"))
        mac = str(self.dev_info.get("mac_address", "N/A"))
        hostname = str(self.dev_info.get("hostname", "Unknown"))
        os_info = str(self.dev_info.get("detected_os", "Unknown"))
        bytes_in = self.dev_info.get("bytes_in", 0)
        bytes_out = self.dev_info.get("bytes_out", 0)
        last_seen = str(self.dev_info.get("last_seen", "N/A"))

        title_lbl = QLabel(f"💻 {hostname} ({ip})")
        title_lbl.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {title_color}; border: none; background: transparent;")

        details_lbl = QLabel(
            f"MAC: <span style='color:{sub_text_color};'>{mac}</span> &nbsp;|&nbsp; "
            f"OS: <span style='color:{sub_text_color};'>{os_info}</span> &nbsp;|&nbsp; "
            f"Traffic: <span style='color:#0284c7;'>{bytes_in} / {bytes_out} B</span> &nbsp;|&nbsp; "
            f"Last Seen: <span style='color:{muted_text};'>{last_seen}</span>"
        )
        details_lbl.setTextFormat(Qt.TextFormat.RichText)
        details_lbl.setStyleSheet(f"font-size: 12px; color: {muted_text}; border: none; background: transparent;")

        info_layout.addWidget(title_lbl)
        info_layout.addWidget(details_lbl)

        layout.addLayout(info_layout)
        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        # Blacklist Button State & Styling
        is_blacklisted = (self.active_rule == "BLACKLIST")
        black_btn = QPushButton("↩️ Undo" if is_blacklisted else "🚨 Blacklist")
        black_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        if is_blacklisted:
            black_btn.setStyleSheet("""
                QPushButton {
                    background-color: #334155;
                    color: #f8fafc;
                    border: 1px solid #475569;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #475569;
                }
            """)
            black_btn.clicked.connect(lambda: self.on_action_callback(ip, "CLEAR"))
        else:
            black_btn.setStyleSheet("""
                QPushButton {
                    background-color: #78350f;
                    color: #fef08a;
                    border: 1px solid #f59e0b;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #b45309;
                    color: #ffffff;
                }
            """)
            black_btn.clicked.connect(lambda: self.on_action_callback(ip, "BLACKLIST"))

        # Whitelist Button State & Styling
        is_whitelisted = (self.active_rule == "WHITELIST")
        white_btn = QPushButton("↩️ Undo" if is_whitelisted else "🛡️ Whitelist")
        white_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        if is_whitelisted:
            white_btn.setStyleSheet("""
                QPushButton {
                    background-color: #334155;
                    color: #f8fafc;
                    border: 1px solid #475569;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #475569;
                }
            """)
            white_btn.clicked.connect(lambda: self.on_action_callback(ip, "CLEAR"))
        else:
            white_btn.setStyleSheet("""
                QPushButton {
                    background-color: #064e3b;
                    color: #a7f3d0;
                    border: 1px solid #10b981;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #047857;
                    color: #ffffff;
                }
            """)
            white_btn.clicked.connect(lambda: self.on_action_callback(ip, "WHITELIST"))

        # Block Button State & Styling
        is_blocked = (self.active_rule == "BLOCKED")
        block_btn = QPushButton("✅ Unblock" if is_blocked else "⛔ Block")
        block_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        if is_blocked:
            block_btn.setStyleSheet("""
                QPushButton {
                    background-color: #064e3b;
                    color: #a7f3d0;
                    border: 1px solid #10b981;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #047857;
                    color: #ffffff;
                }
            """)
            block_btn.clicked.connect(lambda: self.on_action_callback(ip, "CLEAR"))
        else:
            block_btn.setStyleSheet("""
                QPushButton {
                    background-color: #7f1d1d;
                    color: #fca5a5;
                    border: 1px solid #ef4444;
                    border-radius: 6px;
                    padding: 6px 12px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #b91c1c;
                    color: #ffffff;
                }
            """)
            block_btn.clicked.connect(lambda: self.on_action_callback(ip, "BLOCKED"))

        btn_layout.addWidget(black_btn)
        btn_layout.addWidget(white_btn)
        btn_layout.addWidget(block_btn)

        layout.addLayout(btn_layout)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.show_action_menu(event.globalPosition().toPoint())
        super().mousePressEvent(event)

    def show_action_menu(self, pos):
        menu = QMenu(self)
        ip = str(self.dev_info.get("ip_address", "N/A"))
        menu.setTitle(f"Action for {ip}")

        act_black = QAction("🚨 Move to Blacklist", self)
        act_black.triggered.connect(lambda: self.on_action_callback(ip, "BLACKLIST"))

        act_white = QAction("🛡️ Move to Whitelist", self)
        act_white.triggered.connect(lambda: self.on_action_callback(ip, "WHITELIST"))

        act_block = QAction("⛔ Block IP", self)
        act_block.triggered.connect(lambda: self.on_action_callback(ip, "BLOCKED"))

        act_clear = QAction("❌ Clear Rule", self)
        act_clear.triggered.connect(lambda: self.on_action_callback(ip, "CLEAR"))

        menu.addAction(act_black)
        menu.addAction(act_white)
        menu.addAction(act_block)
        menu.addSeparator()
        menu.addAction(act_clear)

        menu.exec(pos)


# --- SYSTEM LANDING PAGE ---
class MainLandingPage(QWidget):
    def __init__(self, on_login_requested):
        super().__init__()
        self.on_login_requested = on_login_requested
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)

        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        center_layout.setSpacing(14)

        main_title = QLabel("Unified Threat Management System")
        main_title.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        main_title.setStyleSheet("background: transparent;")
        main_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Smart, Fast, Secure.")
        subtitle.setFont(QFont("Segoe UI", 18, QFont.Weight.Medium))
        subtitle.setStyleSheet("background: transparent; letter-spacing: 2px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        description = QLabel(
            "Incorporating machine learning for analysis of user behaviour and traffic "
            "to keep you safe from threats to your security and privacy."
        )
        description.setFont(QFont("Segoe UI", 13, QFont.Weight.Normal))
        description.setStyleSheet("background: transparent; margin-bottom: 10px;")
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description.setWordWrap(True)
        description.setMaximumWidth(700)

        get_started_btn = QPushButton("Get Started")
        get_started_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        get_started_btn.setStyleSheet("""
            QPushButton {
                background-color: #6366f1;
                color: #ffffff;
                border: none;
                padding: 12px 32px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 15px;
            }
            QPushButton:hover {
                background-color: #4f46e5;
            }
        """)
        get_started_btn.clicked.connect(self.on_login_requested)

        already_account_btn = QPushButton("Already have an account?")
        already_account_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        already_account_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #818cf8;
                border: none;
                font-size: 13px;
                font-weight: 500;
            }
            QPushButton:hover {
                color: #a5b4fc;
                text-decoration: underline;
            }
        """)
        already_account_btn.clicked.connect(self.on_login_requested)

        center_layout.addWidget(main_title)
        center_layout.addWidget(subtitle)
        center_layout.addWidget(description)
        center_layout.addSpacing(10)
        center_layout.addWidget(get_started_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        center_layout.addWidget(already_account_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        main_layout.addStretch()
        main_layout.addLayout(center_layout)
        main_layout.addStretch()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        center_x = self.width() / 2
        center_y = self.height() / 2
        shield_w = 360
        shield_h = 440

        blue_color = QColor(51, 65, 85, 120)
        blue_dim_color = QColor(51, 65, 85, 50)

        top_left = QPointF(center_x - shield_w / 2, center_y - shield_h / 2 + 25)
        top_center = QPointF(center_x, center_y - shield_h / 2)
        top_right = QPointF(center_x + shield_w / 2, center_y - shield_h / 2 + 25)
        mid_right = QPointF(center_x + shield_w / 2, center_y + shield_h / 8)
        bottom = QPointF(center_x, center_y + shield_h / 2)
        mid_left = QPointF(center_x - shield_w / 2, center_y + shield_h / 8)

        shield_path = QPainterPath()
        shield_path.moveTo(top_left)
        shield_path.quadTo(QPointF(center_x - shield_w / 4, center_y - shield_h / 2 - 15), top_center)
        shield_path.quadTo(QPointF(center_x + shield_w / 4, center_y - shield_h / 2 - 15), top_right)
        shield_path.lineTo(mid_right)
        shield_path.quadTo(QPointF(center_x + shield_w / 2, center_y + shield_h / 2.2), bottom)
        shield_path.quadTo(QPointF(center_x - shield_w / 2, center_y + shield_h / 2.2), mid_left)
        shield_path.lineTo(top_left)

        painter.save()
        painter.setClipPath(shield_path)
        painter.setPen(QPen(blue_dim_color))
        painter.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

        binary_lines = [
            "101010101010101010101010",
            "010101010101010101010101",
            "110010101100101011001010",
            "001101010011010100110101",
            "101101101011011010110110",
            "010010010100100101001001",
            "111000111110001111100011",
            "000111000001110000011100",
            "101010101010101010101010",
            "010101010101010101010101",
            "110011001100110011001100",
            "001100110011001100110011",
            "101010101010101010101010",
            "010101010101010101010101",
            "110100101101001011010010",
            "001011010010110100101101",
            "101010101010101010101010",
            "010101010101010101010101"
        ]

        start_x = center_x - shield_w / 2 + 10
        start_y = center_y - shield_h / 2 + 35
        row_height = 22
        col_width = 15

        for r_idx, row in enumerate(binary_lines):
            y_pos = start_y + r_idx * row_height
            for c_idx, char in enumerate(row):
                x_pos = start_x + c_idx * col_width
                painter.drawText(int(x_pos), int(y_pos), char)

        painter.restore()

        shield_pen = QPen(blue_color, 3)
        painter.setPen(shield_pen)
        painter.drawPath(shield_path)

        lock_pen = QPen(blue_color, 3)
        painter.setPen(lock_pen)

        pw, ph = 70, 60
        px = center_x - pw / 2
        py = center_y - ph / 2 + 15

        painter.drawRoundedRect(int(px), int(py), int(pw), int(ph), 8, 8)

        shackle_path = QPainterPath()
        shackle_w, shackle_h = 40, 42
        sx = center_x - shackle_w / 2
        sy = py - shackle_h + 8

        shackle_path.moveTo(sx, py + 2)
        shackle_path.lineTo(sx, sy + 18)
        shackle_path.quadTo(QPointF(sx, sy), QPointF(center_x, sy))
        shackle_path.quadTo(QPointF(sx + shackle_w, sy), QPointF(sx + shackle_w, sy + 18))
        shackle_path.lineTo(sx + shackle_w, py + 2)
        painter.drawPath(shackle_path)

        painter.drawEllipse(QPointF(center_x, py + ph / 2 - 4), 4, 4)
        key_path = QPainterPath()
        key_path.moveTo(center_x - 3, py + ph / 2 - 2)
        key_path.lineTo(center_x - 5, py + ph / 2 + 12)
        key_path.lineTo(center_x + 5, py + ph / 2 + 12)
        key_path.lineTo(center_x + 3, py + ph / 2 - 2)
        painter.drawPath(key_path)


# --- FULLSCREEN AUTH SCREEN ---
class AuthLandingWidget(QWidget):
    def __init__(self, on_auth_success, on_back_landing=None):
        super().__init__()
        self.on_auth_success = on_auth_success
        self.on_back_landing = on_back_landing
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setFixedSize(420, 500)
        card.setObjectName("ActivityFrame")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(30, 35, 30, 35)
        layout.setSpacing(14)

        title = QLabel("🛡️ UTM SECURITY")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("border: none;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Unified Threat Gateway Control Center")
        subtitle.setStyleSheet("border: none; font-size: 13px; margin-bottom: 10px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        layout.addSpacing(6)

        self.login_btn = QPushButton("Login to Gateway")
        self.login_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #6366f1;
                color: #ffffff;
                border: none;
                padding: 12px 16px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #4f46e5;
            }
        """)
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        self.register_btn = QPushButton("Create New Account")
        self.register_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.register_btn.setStyleSheet("background-color: transparent; color: #818cf8; border: none; margin-top: 4px; font-weight: 500;")
        self.register_btn.clicked.connect(self.handle_register)
        layout.addWidget(self.register_btn)

        if self.on_back_landing:
            self.back_btn = QPushButton("← Back to Overview")
            self.back_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            self.back_btn.setStyleSheet("background-color: transparent; color: #64748b; border: none; margin-top: 2px; font-size: 12px;")
            self.back_btn.clicked.connect(self.on_back_landing)
            layout.addWidget(self.back_btn)

        main_layout.addWidget(card)

    def handle_login(self):
        user = self.username_input.text().strip()
        pwd = self.password_input.text().strip()
        if not user or not pwd:
            QMessageBox.warning(self, "Validation Error", "Please fill in all credentials.")
            return

        success, uid = database.verify_user(user, pwd)
        if success:
            self.username_input.clear()
            self.password_input.clear()
            self.on_auth_success(uid, user)
        else:
            QMessageBox.critical(self, "Auth Failed", "Invalid username or password.")

    def handle_register(self):
        user = self.username_input.text().strip()
        pwd = self.password_input.text().strip()
        if not user or not pwd:
            QMessageBox.warning(self, "Validation Error", "Please fill in all fields.")
            return

        success, res = database.register_user(user, pwd)
        if success:
            QMessageBox.information(self, "Success", "Account created successfully! Authorizing...")
            self.username_input.clear()
            self.password_input.clear()
            self.on_auth_success(res, user)
        else:
            QMessageBox.critical(self, "Registration Error", f"Failed: {res}")


# --- INTERACTIVE DASHBOARD CARD WIDGET ---
class InteractiveCard(QFrame):
    def __init__(self, title, count_text, subtext, color="#6366f1", callback=None, is_dark=True):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setProperty("class", "DashboardCard")
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.callback = callback
        self.accent_color = color

        layout = QVBoxLayout(self)

        self.title_lbl = QLabel(title)
        self.count_lbl = QLabel(count_text)
        self.sub_lbl = QLabel(subtext)

        layout.addWidget(self.title_lbl)
        layout.addWidget(self.count_lbl)
        layout.addWidget(self.sub_lbl)

        self.update_theme(is_dark)

    def mousePressEvent(self, event):
        if self.callback:
            self.callback()

    def update_data(self, count_text, subtext=""):
        self.count_lbl.setText(str(count_text))
        if subtext:
            self.sub_lbl.setText(subtext)

    def update_theme(self, is_dark):
        bg_color = "#1e293b" if is_dark else "#ffffff"
        hover_bg = "#24334a" if is_dark else "#f1f5f9"
        border_color = "#334155" if is_dark else "#cbd5e1"
        title_color = "#94a3b8" if is_dark else "#475569"
        count_color = "#f8fafc" if is_dark else "#0f172a"
        sub_color = "#64748b" if is_dark else "#64748b"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-left: 5px solid {self.accent_color};
                border-radius: 10px;
                padding: 12px;
            }}
            QFrame:hover {{
                background-color: {hover_bg};
                border-color: {self.accent_color};
            }}
        """)
        self.title_lbl.setStyleSheet(f"color: {title_color}; font-size: 13px; font-weight: bold; border: none; background: transparent;")
        self.count_lbl.setStyleSheet(f"color: {count_color}; font-size: 26px; font-weight: bold; margin: 4px 0px; border: none; background: transparent;")
        self.sub_lbl.setStyleSheet(f"color: {sub_color}; font-size: 11px; border: none; background: transparent;")


# --- MANUAL ADD RULE DIALOG ---
class AddRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add IP Security Rule")
        self.setFixedSize(360, 290)

        layout = QFormLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.50")

        self.dest_ip_input = QLineEdit()
        self.dest_ip_input.setPlaceholderText("e.g., 8.8.8.8 (Optional)")

        self.rule_type_combo = QComboBox()
        self.rule_type_combo.addItems(["BLACKLIST", "WHITELIST", "BLOCK"])

        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("e.g., Suspicious port scanning")

        layout.addRow("Source IP:", self.ip_input)
        layout.addRow("Dest IP:", self.dest_ip_input)
        layout.addRow("Rule Type:", self.rule_type_combo)
        layout.addRow("Reason:", self.reason_input)

        self.save_btn = QPushButton("Save Rule")
        self.save_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #1e40af;
                color: #ffffff;
                border: none;
                padding: 10px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
        """)
        self.save_btn.clicked.connect(self.save)
        layout.addRow(self.save_btn)

    def save(self):
        ip = self.ip_input.text().strip()
        dest_ip = self.dest_ip_input.text().strip() or "N/A"
        selected_rule = self.rule_type_combo.currentText()

        rule = "BLOCKED" if selected_rule == "BLOCK" else selected_rule
        reason = self.reason_input.text().strip() or "Manual Rule Entry"

        if not ip:
            QMessageBox.warning(self, "Error", "IP address required.")
            return

        try:
            database.add_or_update_ip_rule(ip, rule, reason, dest_ip=dest_ip)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save rule: {e}")
            return

        self.accept()


# --- DASHBOARD CONTAINER WIDGET ---
class DashboardWidget(QWidget):
    def __init__(self, user_id, username, theme_callback, logout_callback=None):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.theme_callback = theme_callback
        self.logout_callback = logout_callback
        self.is_dark_mode = True
        self._last_dev_signature = None

        self.sidebar_expanded = True
        self.init_ui()

        # Offload database polling to async QThread worker
        self.telemetry_worker = TelemetryWorker(user_id=self.user_id, interval_ms=2000)
        self.telemetry_worker.telemetry_updated.connect(self.handle_telemetry_payload)
        self.telemetry_worker.start()

    def closeEvent(self, event):
        if hasattr(self, 'telemetry_worker') and self.telemetry_worker.isRunning():
            self.telemetry_worker.stop()
        super().closeEvent(event)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header)

        self.toggle_btn = QPushButton("☰")
        self.toggle_btn.setObjectName("ToggleBtn")
        self.toggle_btn.setFixedWidth(36)
        self.toggle_btn.clicked.connect(self.toggle_sidebar)
        header_layout.addWidget(self.toggle_btn)

        brand_title = QLabel("🛡️ UTM SECURITY GATEWAY")
        brand_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        brand_title.setStyleSheet("margin-left: 10px;")
        header_layout.addWidget(brand_title)

        header_layout.addStretch()

        self.theme_toggle_btn = QPushButton("🌙 Dark Mode")
        self.theme_toggle_btn.setObjectName("ThemeToggleBtn")
        self.theme_toggle_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.theme_toggle_btn.clicked.connect(self.handle_theme_toggle)
        header_layout.addWidget(self.theme_toggle_btn)

        self.user_btn = QPushButton(f"👤 {self.username} ▾")
        self.user_btn.setObjectName("UserMenuBtn")
        self.user_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        user_menu = QMenu(self)

        action_new_training = QAction("🔄 New Training Cycle", self)
        action_new_training.triggered.connect(self.handle_new_training_cycle)

        action_switch_acc = QAction("👤 Switch Accounts", self)
        action_switch_acc.triggered.connect(self.handle_switch_accounts)

        action_exit = QAction("❌ Exit System", self)
        action_exit.triggered.connect(self.handle_exit_system)

        user_menu.addAction(action_new_training)
        user_menu.addSeparator()
        user_menu.addAction(action_switch_acc)
        user_menu.addAction(action_exit)

        self.user_btn.setMenu(user_menu)
        header_layout.addWidget(self.user_btn)

        main_layout.addWidget(header)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(210)

        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 15, 10, 15)
        self.sidebar_layout.setSpacing(8)

        self.nav_buttons = []
        pages_info = [
            ("🏠 Home Dashboard", 0),
            ("📊 Live Packet Logs", 1),
            ("🚨 Blacklisted IPs", 2),
            ("🛡️ Whitelisted IPs", 3),
            ("⛔ Blocked IPs", 4),
            ("📈 Statistics", 5),
            ("💻 Connected Devices", 6)
        ]

        for text, page_idx in pages_info:
            btn = QPushButton(text)
            btn.setProperty("page_index", page_idx)
            btn.setProperty("full_text", text)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.setStyleSheet("background-color: #6366f1; color: white; font-weight: bold; border-radius: 8px; padding: 12px 16px; text-align: left;" if page_idx == 0 else "background-color: transparent; border: none; padding: 12px 16px; font-size: 14px; text-align: left;")

            btn.clicked.connect(lambda _, idx=page_idx: self.switch_page(idx))
            self.sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        self.sidebar_layout.addStretch()

        add_rule_btn = QPushButton("➕ Quick Rule")
        add_rule_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        add_rule_btn.setStyleSheet("background-color: #334155; color: #a7f3d0; border: 1px dashed #10b981; padding: 10px; border-radius: 8px; font-weight: bold;")
        add_rule_btn.clicked.connect(self.open_add_rule_dialog)
        self.sidebar_layout.addWidget(add_rule_btn)

        body_layout.addWidget(self.sidebar)

        self.stacked_widget = QStackedWidget()

        self.page_home = self.create_home_page()
        self.stacked_widget.addWidget(self.page_home)

        self.page_logs = self.create_logs_page()
        self.stacked_widget.addWidget(self.page_logs)

        self.page_blacklist = self.create_rules_table_page("Blacklisted IPs", "BLACKLIST")
        self.stacked_widget.addWidget(self.page_blacklist)

        self.page_whitelist = self.create_rules_table_page("Whitelisted IPs", "WHITELIST")
        self.stacked_widget.addWidget(self.page_whitelist)

        self.page_blocked = self.create_rules_table_page("Blocked IPs", "BLOCKED")
        self.stacked_widget.addWidget(self.page_blocked)

        self.page_stats = self.create_statistics_page()
        self.stacked_widget.addWidget(self.page_stats)

        self.page_devices = self.create_devices_page()
        self.stacked_widget.addWidget(self.page_devices)

        body_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(body)

    def handle_new_training_cycle(self):
        python_bin = sys.executable
        cmd = f"./collector | {python_bin} ueba_engine.py --mode train --duration 3600 --user_id {self.user_id} --username {self.username}"
        try:
            subprocess.Popen(cmd, shell=True)
            QMessageBox.information(
                self,
                "Training Initiated",
                f"1-hour training cycle initiated for user baseline: '{self.username}' (User ID: {self.user_id}).\n\n"
                f"The UEBA engine will collect live traffic data and update the model baseline."
            )
        except Exception as e:
            QMessageBox.critical(self, "Execution Error", f"Failed to start training cycle: {e}")

    def handle_switch_accounts(self):
        if hasattr(self, 'telemetry_worker'):
            self.telemetry_worker.stop()
        if self.logout_callback:
            self.logout_callback()

    def handle_exit_system(self):
        if hasattr(self, 'telemetry_worker'):
            self.telemetry_worker.stop()
        QApplication.quit()

    def handle_theme_toggle(self):
        self.is_dark_mode = not self.is_dark_mode
        self.theme_toggle_btn.setText("🌙 Dark Mode" if self.is_dark_mode else "☀️ Light Mode")
        
        self.card_logs.update_theme(self.is_dark_mode)
        self.card_black.update_theme(self.is_dark_mode)
        self.card_white.update_theme(self.is_dark_mode)
        self.card_block.update_theme(self.is_dark_mode)

        if PYQTGRAPH_AVAILABLE:
            bg_col = '#1e293b' if self.is_dark_mode else '#ffffff'
            fg_col = '#f8fafc' if self.is_dark_mode else '#0f172a'
            if hasattr(self, 'graph_context'):
                self.graph_context.setBackground(bg_col)
                self.graph_context.getAxis('left').setTextPen(fg_col)
                self.graph_context.getAxis('bottom').setTextPen(fg_col)
            if hasattr(self, 'graph_rules'):
                self.graph_rules.setBackground(bg_col)
                self.graph_rules.getAxis('left').setTextPen(fg_col)
                self.graph_rules.getAxis('bottom').setTextPen(fg_col)

        self._last_dev_signature = None
        self.theme_callback(self.is_dark_mode)

    def toggle_sidebar(self):
        target_width = 60 if self.sidebar_expanded else 210

        self.anim = QPropertyAnimation(self.sidebar, b"minimumWidth")
        self.anim.setDuration(200)
        self.anim.setStartValue(self.sidebar.width())
        self.anim.setEndValue(target_width)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.sidebar.setMaximumWidth(target_width)
        self.anim.start()

        self.sidebar_expanded = not self.sidebar_expanded

        for btn in self.nav_buttons:
            full_text = btn.property("full_text")
            if not self.sidebar_expanded:
                btn.setText(full_text.split()[0])
            else:
                btn.setText(full_text)

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for btn in self.nav_buttons:
            if btn.property("page_index") == index:
                btn.setStyleSheet("background-color: #6366f1; color: white; font-weight: bold; border-radius: 8px; padding: 12px 16px; text-align: left;")
            else:
                btn.setStyleSheet("background-color: transparent; border: none; padding: 12px 16px; font-size: 14px; text-align: left;")

    def create_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)

        welcome = QLabel(f"Welcome back, {self.username} 👋")
        welcome.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(welcome)

        sub = QLabel("Layer 3/4 Threat Gateway — Sub-microsecond CIDR Lookup & Real-Time Anomaly Mitigation")
        sub.setProperty("class", "SubText")
        layout.addWidget(sub)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)

        self.card_logs = InteractiveCard("LIVE PACKETS", "0", "0 Anomalies Flagged", "#0284c7", lambda: self.switch_page(1), self.is_dark_mode)
        self.card_black = InteractiveCard("BLACKLISTED", "0", "Flagged for Inspection", "#f59e0b", lambda: self.switch_page(2), self.is_dark_mode)
        self.card_white = InteractiveCard("WHITELISTED", "0", "Trusted IPs", "#10b981", lambda: self.switch_page(3), self.is_dark_mode)
        self.card_block = InteractiveCard("BLOCKED", "0", "Active Drops", "#ef4444", lambda: self.switch_page(4), self.is_dark_mode)

        cards_layout.addWidget(self.card_logs)
        cards_layout.addWidget(self.card_black)
        cards_layout.addWidget(self.card_white)
        cards_layout.addWidget(self.card_block)

        layout.addLayout(cards_layout)

        activity_frame = QFrame()
        activity_frame.setObjectName("ActivityFrame")
        act_layout = QVBoxLayout(activity_frame)

        act_title = QLabel("🛡️ Threat Prevention Engine Status")
        act_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        act_layout.addWidget(act_title)

        self.act_desc = QLabel("Active SQLite WAL database sync active. Machine Learning Baseline ready for real-time traffic context mapping.")
        self.act_desc.setProperty("class", "SubText")
        self.act_desc.setStyleSheet("margin-top: 5px;")
        act_layout.addWidget(self.act_desc)

        layout.addWidget(activity_frame)
        layout.addStretch()
        return page

    def create_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)

        header_lbl = QLabel("📊 Live Packet & Anomaly Logs")
        header_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(header_lbl)

        self.logs_table = QTableWidget(0, 8)
        self.logs_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Source IP", "Dest IP", "Protocol", "Size", "Status", "Service Context"])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.logs_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.logs_table.customContextMenuRequested.connect(self.show_logs_context_menu)

        layout.addWidget(self.logs_table)

        btn_logs_report = QPushButton("📄 Generate Report")
        btn_logs_report.setProperty("class", "CsvBtn")
        btn_logs_report.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_logs_report.clicked.connect(lambda: self.generate_report_signal("live_packet_logs"))
        layout.addWidget(btn_logs_report, alignment=Qt.AlignmentFlag.AlignRight)

        return page

    def create_rules_table_page(self, title_text, rule_type):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)

        header = QLabel(title_text)
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(header)

        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["IP Address", "Dest IP", "Service Context", "Reason", "Added Date"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.setProperty("rule_type", rule_type)
        table.customContextMenuRequested.connect(lambda pos, t=table, r=rule_type: self.show_rules_context_menu(pos, t, r))

        layout.addWidget(table)
        setattr(self, f"table_{rule_type.lower()}", table)
        return page

    def create_statistics_page(self):
        page = QWidget()
        main_layout = QVBoxLayout(page)
        main_layout.setContentsMargins(25, 25, 25, 25)

        header = QLabel("📈 Security Telemetry & Dynamic Aggregated Statistics")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        main_layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(20)

        g1_frame = QFrame()
        g1_frame.setObjectName("GraphFrame")
        g1_layout = QVBoxLayout(g1_frame)

        g1_title = QLabel("📊 Traffic Context Volume Distribution (Bytes Over Time)")
        g1_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        g1_layout.addWidget(g1_title)

        if PYQTGRAPH_AVAILABLE:
            self.graph_context = pg.PlotWidget(axisItems={'bottom': TimeAxisItem(orientation='bottom')})
            self.graph_context.setMinimumHeight(280)
            self.graph_context.addLegend(offset=(-10, 10))
            self.graph_context.showGrid(x=True, y=True, alpha=0.3)

            self.plot_anomalies = self.graph_context.plot(pen=pg.mkPen('#ef4444', width=2), name="Anomalies / Threats")
            self.plot_unknown = self.graph_context.plot(pen=pg.mkPen('#f97316', width=2), name="External Hosts (Unknown)")
            self.plot_google = self.graph_context.plot(pen=pg.mkPen('#10b981', width=2), name="Google Infra / DNS")
            self.plot_cdn = self.graph_context.plot(pen=pg.mkPen('#818cf8', width=2), name="Cloudflare / Fastly CDN")
            self.plot_local = self.graph_context.plot(pen=pg.mkPen('#06b6d4', width=2), name="Local Subnets / LAN")

            g1_layout.addWidget(self.graph_context)
        else:
            fallback = QLabel("PyQtGraph not installed.")
            g1_layout.addWidget(fallback)

        btn_g1_csv = QPushButton("📄 Generate Report")
        btn_g1_csv.setProperty("class", "CsvBtn")
        btn_g1_csv.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_g1_csv.clicked.connect(lambda: self.generate_report_signal("traffic_context_graph"))
        g1_layout.addWidget(btn_g1_csv, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addWidget(g1_frame)

        g2_frame = QFrame()
        g2_frame.setObjectName("GraphFrame")
        g2_layout = QVBoxLayout(g2_frame)

        g2_title = QLabel("🛡️ Policy Rule Activity & Action Hits")
        g2_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        g2_layout.addWidget(g2_title)

        if PYQTGRAPH_AVAILABLE:
            self.graph_rules = pg.PlotWidget(axisItems={'bottom': TimeAxisItem(orientation='bottom')})
            self.graph_rules.setMinimumHeight(280)
            self.graph_rules.addLegend(offset=(-10, 10))
            self.graph_rules.showGrid(x=True, y=True, alpha=0.3)

            self.plot_whitelist_hits = self.graph_rules.plot(pen=pg.mkPen('#10b981', width=2), name="Whitelisted Hits")
            self.plot_blacklist_hits = self.graph_rules.plot(pen=pg.mkPen('#f59e0b', width=2), name="Blacklisted Hits")
            self.plot_blocked_hits = self.graph_rules.plot(pen=pg.mkPen('#ef4444', width=2), name="Active Dropped Hits")

            g2_layout.addWidget(self.graph_rules)

        btn_g2_csv = QPushButton("📄 Generate Report")
        btn_g2_csv.setProperty("class", "CsvBtn")
        btn_g2_csv.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_g2_csv.clicked.connect(lambda: self.generate_report_signal("policy_hits_graph"))
        g2_layout.addWidget(btn_g2_csv, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addWidget(g2_frame)

        scroll.setWidget(content)
        main_layout.addWidget(scroll)
        return page

    def create_devices_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)

        header_lbl = QLabel("💻 Network Devices & Endpoint Telemetry")
        header_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(header_lbl)

        sub_lbl = QLabel("Live endpoint discovery via ARP and active OS fingerprinting engines. Click a device card or action buttons to apply security rules.")
        sub_lbl.setProperty("class", "SubText")
        sub_lbl.setStyleSheet("margin-bottom: 10px;")
        layout.addWidget(sub_lbl)

        self.devices_scroll = QScrollArea()
        self.devices_scroll.setWidgetResizable(True)
        self.devices_scroll.setStyleSheet("""
            QScrollArea, QWidget#qt_scrollarea_viewport {
                border: none;
                background-color: transparent;
            }
        """)

        self.devices_container = QWidget()
        self.devices_container.setStyleSheet("background-color: transparent;")
        self.devices_layout = QVBoxLayout(self.devices_container)
        self.devices_layout.setContentsMargins(0, 0, 0, 0)
        self.devices_layout.setSpacing(12)
        self.devices_layout.addStretch()

        self.devices_scroll.setWidget(self.devices_container)
        layout.addWidget(self.devices_scroll)

        btn_dev_csv = QPushButton("📄 Generate Report")
        btn_dev_csv.setProperty("class", "CsvBtn")
        btn_dev_csv.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_dev_csv.clicked.connect(lambda: self.generate_report_signal("connected_devices"))
        layout.addWidget(btn_dev_csv, alignment=Qt.AlignmentFlag.AlignRight)

        return page

    def handle_device_action(self, ip, rule_type):
        try:
            if rule_type == "CLEAR":
                try:
                    database.delete_ip_rule(ip)
                except TypeError:
                    database.delete_ip_rule(ip, dest_ip="N/A")
                msg = f"Successfully removed rule for IP: {ip}"
            else:
                reason = f"Applied rule from Connected Devices view ({rule_type})"
                database.add_or_update_ip_rule(ip, rule_type, reason)
                msg = f"Successfully added policy rule for IP: {ip}\nRule Type: {rule_type}"

            QMessageBox.information(
                self,
                "Rule Updated",
                msg
            )
        except Exception as e:
            QMessageBox.critical(self, "Execution Error", f"Failed to modify rule for IP {ip}: {e}")

        self._last_dev_signature = None

    def generate_report_signal(self, section_name):
        generated_files = []
        try:
            python_bin = sys.executable
            script_path = os.path.join(os.path.dirname(__file__), "report_generation.py")
            res = subprocess.run(
                [python_bin, script_path, "--section", section_name],
                capture_output=True,
                text=True,
                check=True
            )
            for line in res.stdout.splitlines():
                if "[+]" in line and "generated:" in line:
                    path = line.split("generated:", 1)[1].strip()
                    generated_files.append(path)
        except Exception as e:
            print(f"[-] Subprocess report execution failed: {e}")

        if generated_files:
            display_path = "\n".join(f"• {p}" for p in generated_files)
        else:
            display_path = f"Reports/ directory (Section: {section_name})"

        QMessageBox.information(
            self,
            "Report Generated Successfully",
            f"Report generated successfully in both CSV and PDF formats!\n\nSaved to:\n{display_path}"
        )

    def show_logs_context_menu(self, pos):
        item = self.logs_table.itemAt(pos)
        if not item:
            return

        row = item.row()
        src_item = self.logs_table.item(row, 2)
        dest_item = self.logs_table.item(row, 3)

        if not src_item or not dest_item:
            return

        src_ip = src_item.text()
        dest_ip_port = dest_item.text()
        dest_ip = dest_ip_port.split(":")[0] if ":" in dest_ip_port else dest_ip_port

        menu = QMenu(self)
        menu.setTitle(f"Action for {src_ip}")

        action_black = QAction("🚨 Move to Blacklist", self)
        action_black.triggered.connect(lambda: self.safe_add_or_update_rule(src_ip, "BLACKLIST", "Flagged from live logs", dest_ip=dest_ip))

        action_white = QAction("🛡️ Move to Whitelist", self)
        action_white.triggered.connect(lambda: self.safe_add_or_update_rule(src_ip, "WHITELIST", "Verified safe in live logs", dest_ip=dest_ip))

        action_block = QAction("⛔ Block IP", self)
        action_block.triggered.connect(lambda: self.safe_add_or_update_rule(src_ip, "BLOCKED", "Blocked from live logs", dest_ip=dest_ip))

        menu.addAction(action_black)
        menu.addAction(action_white)
        menu.addAction(action_block)

        menu.exec(self.logs_table.viewport().mapToGlobal(pos))

    def safe_add_or_update_rule(self, ip, rule_type, reason, dest_ip="N/A"):
        try:
            database.add_or_update_ip_rule(ip, rule_type, reason, dest_ip=dest_ip)
        except Exception as e:
            QMessageBox.critical(self, "Rule Execution Error", f"Failed to update rule for {ip}: {e}")

    def show_rules_context_menu(self, pos, table, current_rule_type):
        item = table.itemAt(pos)
        if not item:
            return

        row = item.row()
        ip_item = table.item(row, 0)
        dest_item = table.item(row, 1)

        if not ip_item:
            return

        ip_addr = ip_item.text()
        dest_ip = dest_item.text() if dest_item else "N/A"

        menu = QMenu(self)

        if current_rule_type != "WHITELIST":
            act_white = QAction("🛡️ Move to Whitelist", self)
            act_white.triggered.connect(lambda: self.set_ip_rule(ip_addr, "WHITELIST", "Moved to Whitelist", dest_ip))
            menu.addAction(act_white)

        if current_rule_type != "BLACKLIST":
            act_black = QAction("🚨 Move to Blacklist", self)
            act_black.triggered.connect(lambda: self.set_ip_rule(ip_addr, "BLACKLIST", "Moved to Blacklist", dest_ip))
            menu.addAction(act_black)

        if current_rule_type != "BLOCKED":
            act_block = QAction("⛔ Move to Blocked", self)
            act_block.triggered.connect(lambda: self.set_ip_rule(ip_addr, "BLOCKED", "Moved to Blocked", dest_ip))
            menu.addAction(act_block)

        act_delete = QAction("❌ Remove / Clear Rule", self)
        act_delete.triggered.connect(lambda: self.remove_ip_rule(ip_addr, dest_ip))
        menu.addAction(act_delete)

        menu.exec(table.viewport().mapToGlobal(pos))

    def set_ip_rule(self, ip, rule_type, reason, dest_ip="N/A"):
        try:
            database.add_or_update_ip_rule(ip, rule_type, reason, dest_ip=dest_ip)
        except Exception as e:
            QMessageBox.critical(self, "Rule Execution Error", f"Failed to update rule: {e}")

    def remove_ip_rule(self, ip, dest_ip="N/A"):
        try:
            try:
                database.delete_ip_rule(ip, dest_ip=dest_ip)
            except TypeError:
                database.delete_ip_rule(ip)
        except Exception as e:
            QMessageBox.critical(self, "Rule Execution Error", f"Failed to delete rule: {e}")

    def open_add_rule_dialog(self):
        AddRuleDialog(self).exec()

    # --- ASYNC SLOT & BATCHED TABLE UPDATE ---
    def handle_telemetry_payload(self, payload):
        """Receives pre-fetched payload from TelemetryWorker and updates UI with zero UI thread blocking."""
        stats = payload.get("stats", {})
        self.card_logs.update_data(stats.get("total_logs", 0), f"{stats.get('total_anomalies', 0)} Anomalies Flagged")
        self.card_black.update_data(stats.get("blacklisted", 0), "Requires Analysis")
        self.card_white.update_data(stats.get("whitelisted", 0), "Trusted Devices")
        self.card_block.update_data(stats.get("blocked", 0), "Dropping Packets")

        # 1. Update Logs Table with Repaint Batching
        resolved_logs = payload.get("logs", [])
        self.logs_table.setUpdatesEnabled(False)
        self.logs_table.setRowCount(len(resolved_logs))
        for row_idx, (log, service_context) in enumerate(resolved_logs):
            src_ip = str(log[2]) if len(log) > 2 else "N/A"
            dest_ip = str(log[3]) if len(log) > 3 else "N/A"
            port = str(log[5]) if len(log) > 5 else "N/A"
            protocol = str(log[6]) if len(log) > 6 else "N/A"
            size = str(log[7]) if len(log) > 7 else "0"
            is_anomaly = log[8] if len(log) > 8 else False

            self.logs_table.setItem(row_idx, 0, QTableWidgetItem(str(log[0])))
            self.logs_table.setItem(row_idx, 1, QTableWidgetItem(time.strftime('%H:%M:%S', time.localtime(log[1]))))
            self.logs_table.setItem(row_idx, 2, QTableWidgetItem(src_ip))
            self.logs_table.setItem(row_idx, 3, QTableWidgetItem(f"{dest_ip}:{port}"))
            self.logs_table.setItem(row_idx, 4, QTableWidgetItem(protocol))
            self.logs_table.setItem(row_idx, 5, QTableWidgetItem(f"{size} B"))

            status_item = QTableWidgetItem("⚠️ ANOMALY" if is_anomaly else "NORMAL")
            status_item.setForeground(Qt.GlobalColor.red if is_anomaly else Qt.GlobalColor.green)
            self.logs_table.setItem(row_idx, 6, status_item)
            self.logs_table.setItem(row_idx, 7, QTableWidgetItem(service_context))
        self.logs_table.setUpdatesEnabled(True)

        # 2. Update Security Rules Tables with Repaint Batching
        resolved_rules = payload.get("rules", {})
        for rule_type in ["BLACKLIST", "WHITELIST", "BLOCKED"]:
            table = getattr(self, f"table_{rule_type.lower()}")
            rules = resolved_rules.get(rule_type, [])
            table.setUpdatesEnabled(False)
            table.setRowCount(len(rules))
            for r_idx, (rule, ctx) in enumerate(rules):
                ip_addr = rule[0] if len(rule) > 0 else "N/A"
                dest_ip = rule[1] if len(rule) > 1 and rule[1] else "N/A"
                reason = rule[3] if len(rule) > 3 else "N/A"
                created_at = str(rule[4]) if len(rule) > 4 else "N/A"

                table.setItem(r_idx, 0, QTableWidgetItem(ip_addr))
                table.setItem(r_idx, 1, QTableWidgetItem(dest_ip))
                table.setItem(r_idx, 2, QTableWidgetItem(ctx))
                table.setItem(r_idx, 3, QTableWidgetItem(reason))
                table.setItem(r_idx, 4, QTableWidgetItem(created_at))
            table.setUpdatesEnabled(True)

        # 3. Update PyQtGraph Plots
        if PYQTGRAPH_AVAILABLE:
            res_ctx = payload.get("ctx_stats")
            if res_ctx and len(res_ctx) == 6:
                x, anomalies, unknown, google, cdn, local = res_ctx
                self.plot_anomalies.setData(x, anomalies)
                self.plot_unknown.setData(x, unknown)
                self.plot_google.setData(x, google)
                self.plot_cdn.setData(x, cdn)
                self.plot_local.setData(x, local)

            res_rules = payload.get("rule_stats")
            if res_rules and len(res_rules) == 4:
                rx, white_hits, black_hits, block_hits = res_rules
                self.plot_whitelist_hits.setData(rx, white_hits)
                self.plot_blacklist_hits.setData(rx, black_hits)
                self.plot_blocked_hits.setData(rx, block_hits)

        # 4. Render Connected Device Cards with State Tracking
        devices = payload.get("devices", [])
        dev_signature = repr(devices)
        if self._last_dev_signature != dev_signature:
            self._last_dev_signature = dev_signature

            while self.devices_layout.count() > 1:
                item = self.devices_layout.takeAt(0)
                if item and item.widget():
                    item.widget().deleteLater()

            for dev in devices:
                card = DeviceCard(dev, self.handle_device_action, is_dark=self.is_dark_mode)
                self.devices_layout.insertWidget(self.devices_layout.count() - 1, card)


# --- MAIN APPLICATION WINDOW ---
class UTMMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UTM Threat Control Center")
        self.resize(1280, 800)
        
        self.is_dark_mode = True
        self.setStyleSheet(DARK_STYLE)

        self.app_stack = QStackedWidget()
        self.setCentralWidget(self.app_stack)

        self.landing_page = MainLandingPage(self.show_login_screen)
        self.app_stack.addWidget(self.landing_page)

        self.auth_landing = AuthLandingWidget(
            on_auth_success=self.handle_authenticated,
            on_back_landing=self.show_landing_screen
        )
        self.app_stack.addWidget(self.auth_landing)

        self.dashboard = None
        self.show_landing_screen()

    def set_theme(self, is_dark):
        self.is_dark_mode = is_dark
        if is_dark:
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)

    def show_landing_screen(self):
        self.app_stack.setCurrentIndex(0)

    def show_login_screen(self):
        self.app_stack.setCurrentIndex(1)

    def handle_authenticated(self, user_id, username):
        start_pipeline(user_id)
        if self.dashboard:
            self.app_stack.removeWidget(self.dashboard)
            self.dashboard.deleteLater()

        self.dashboard = DashboardWidget(
            user_id=user_id,
            username=username,
            theme_callback=self.set_theme,
            logout_callback=self.show_login_screen
        )
        self.app_stack.addWidget(self.dashboard)
        self.app_stack.setCurrentIndex(2)


def start_pipeline(user_id):
    has_baseline = False
    try:
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM user_baselines WHERE user_id = ? AND model_data IS NOT NULL", (user_id,))
        row = cursor.fetchone()
        has_baseline = (row[0] > 0) if row else False
        conn.close()
    except Exception as e:
        print(f"[-] Database query error during pipeline initiation: {e}")

    python_bin = sys.executable

    if not has_baseline:
        cmd = f"./collector | {python_bin} ueba_engine.py --mode train --samples 200 --user_id {user_id}"
        print(f"[+] New baseline required for User ID {user_id}. Starting training pipeline (200 samples)...")
    else:
        cmd = f"./collector | {python_bin} ueba_engine.py --mode detect --user_id {user_id}"
        print(f"[+] Baseline loaded for User ID {user_id}. Starting live detection pipeline...")

    try:
        subprocess.Popen(cmd, shell=True)
    except Exception as e:
        print(f"[-] Failed to execute pipeline subprocess: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    database.init_db()

    main_win = UTMMainWindow()
    main_win.showMaximized()
    sys.exit(app.exec())
