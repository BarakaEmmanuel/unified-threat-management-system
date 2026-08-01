import sys
import time
import random
import subprocess
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QStackedWidget, QFrame, QHeaderView, QMenu, QDialog, QFormLayout,
    QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QAction, QCursor

import database

# Global Application Stylesheet (Dark Slate & Neon Accents)
STYLE_SHEET = """
QMainWindow, QDialog {
    background-color: #0f172a;
}
QWidget {
    color: #f8fafc;
    font-family: 'Segoe UI', Inter, sans-serif;
}

/* Fix Dialog Popups (QMessageBox) text and background readability */
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

/* Header Styling */
#HeaderBar {
    background-color: #1e293b;
    border-bottom: 1px solid #334155;
    padding: 8px 16px;
}
#StatusPillNormal {
    background-color: #064e3b;
    color: #34d399;
    border: 1px solid #10b981;
    border-radius: 12px;
    padding: 4px 12px;
    font-weight: bold;
    font-size: 12px;
}
#StatusPillAbnormal {
    background-color: #7f1d1d;
    color: #fca5a5;
    border: 1px solid #ef4444;
    border-radius: 12px;
    padding: 4px 12px;
    font-weight: bold;
    font-size: 12px;
}

/* Sidebar Styling */
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
QPushButton.NavBtnSelected {
    background-color: #6366f1;
    color: #ffffff;
    font-weight: bold;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
}

/* Toggle Button */
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

/* Cards Styling */
.DashboardCard {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
}
.DashboardCard:hover {
    border: 1px solid #6366f1;
    background-color: #24334a;
}

/* Table Styling */
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

/* Context Menu */
QMenu {
    background-color: #1e293b;
    border: 1px solid #475569;
    color: #f8fafc;
}
QMenu::item:selected {
    background-color: #6366f1;
}

/* Dialog & Input Styling */
QLineEdit, QComboBox {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 10px;
    color: #f8fafc;
    font-size: 13px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #6366f1;
}
QPushButton.PrimaryBtn {
    background-color: #6366f1;
    color: white;
    border: none;
    padding: 10px 16px;
    border-radius: 6px;
    font-weight: bold;
    font-size: 13px;
}
QPushButton.PrimaryBtn:hover {
    background-color: #4f46e5;
}
"""

# --- RESTORED DARK LOGIN DIALOG ---
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UTM Security - Authentication")
        self.setFixedSize(400, 460)
        self.setStyleSheet(STYLE_SHEET)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Central Dark Card Container
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(25, 30, 25, 30)
        layout.setSpacing(12)
        
        title = QLabel("🛡️ UTM Login")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #f8fafc; border: none;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("Unified Threat Management System")
        subtitle.setStyleSheet("color: #94a3b8; border: none; margin-bottom: 10px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)
        
        layout.addSpacing(5)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.setObjectName("PrimaryBtn")
        self.login_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        # Text color changed specifically to black (#000000)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #6366f1;
                color: #000000;
                border: none;
                padding: 10px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
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
        
        main_layout.addWidget(card)
        
        self.user_id = None
        self.username = None

    def handle_login(self):
        user = self.username_input.text().strip()
        pwd = self.password_input.text().strip()
        if not user or not pwd:
            QMessageBox.warning(self, "Validation Error", "Please fill in all fields.")
            return
        
        success, uid = database.verify_user(user, pwd)
        if success:
            self.user_id = uid
            self.username = user
            self.accept()
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
            QMessageBox.information(self, "Success", "Account created successfully! Logging in...")
            self.user_id = res
            self.username = user
            self.accept()
        else:
            QMessageBox.critical(self, "Registration Error", f"Failed: {res}")


# --- INTERACTIVE DASHBOARD CARD WIDGET ---
class InteractiveCard(QFrame):
    def __init__(self, title, count_text, subtext, color="#6366f1", callback=None):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setProperty("class", "DashboardCard")
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #1e293b;
                border: 1px solid #334155;
                border-left: 5px solid {color};
                border-radius: 10px;
                padding: 12px;
            }}
            QFrame:hover {{
                background-color: #24334a;
                border-color: {color};
            }}
        """)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.callback = callback
        
        layout = QVBoxLayout(self)
        
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("color: #94a3b8; font-size: 13px; font-weight: bold; border: none;")
        
        self.count_lbl = QLabel(count_text)
        self.count_lbl.setStyleSheet("color: #f8fafc; font-size: 26px; font-weight: bold; margin: 4px 0px; border: none;")
        
        self.sub_lbl = QLabel(subtext)
        self.sub_lbl.setStyleSheet("color: #64748b; font-size: 11px; border: none;")
        
        layout.addWidget(self.title_lbl)
        layout.addWidget(self.count_lbl)
        layout.addWidget(self.sub_lbl)

    def mousePressEvent(self, event):
        if self.callback:
            self.callback()

    def update_data(self, count_text, subtext=""):
        self.count_lbl.setText(str(count_text))
        if subtext:
            self.sub_lbl.setText(subtext)


# --- MANUAL ADD RULE DIALOG ---
class AddRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add IP Rule")
        self.setFixedSize(340, 250)
        self.setStyleSheet(STYLE_SHEET)
        
        layout = QFormLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.50")
        
        self.rule_type_combo = QComboBox()
        self.rule_type_combo.addItems(["BLACKLIST", "WHITELIST", "BLOCKED"])
        # Set text color to black for both the combo box and its drop-down menu items
        self.rule_type_combo.setStyleSheet("""
            QComboBox {
                color: #000000;
                background-color: #ffffff;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px;
                font-size: 13px;
                font-weight: 500;
            }
            QComboBox QAbstractItemView {
                color: #000000;
                background-color: #ffffff;
                selection-background-color: #6366f1;
                selection-color: #ffffff;
            }
        """)
        
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("e.g., Suspicious port scanning")
        
        layout.addRow("IP Address:", self.ip_input)
        layout.addRow("Rule Type:", self.rule_type_combo)
        layout.addRow("Reason:", self.reason_input)
        
        self.save_btn = QPushButton("Save Rule")
        self.save_btn.setObjectName("PrimaryBtn")
        self.save_btn.clicked.connect(self.save)
        layout.addRow(self.save_btn)

    def save(self):
        ip = self.ip_input.text().strip()
        rule = self.rule_type_combo.currentText()
        reason = self.reason_input.text().strip() or "Manual Rule Entry"
        
        if not ip:
            QMessageBox.warning(self, "Error", "IP address required.")
            return
            
        database.add_or_update_ip_rule(ip, rule, reason)
        self.accept()


# --- MAIN DASHBOARD WINDOW ---
class MainWindow(QMainWindow):
    def __init__(self, user_id, username):
        super().__init__()
        self.user_id = user_id
        self.username = username
        
        self.setWindowTitle("UTM Threat Control Center")
        self.resize(1100, 700)
        self.setStyleSheet(STYLE_SHEET)
        
        self.sidebar_expanded = True
        
        self.init_ui()
        
        # Auto-refresh timer for live statistics & table synchronization
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(2000) # Every 2 seconds
        
        self.refresh_data()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 1. TOP HEADER BAR
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
        brand_title.setStyleSheet("margin-left: 10px; color: #f8fafc;")
        header_layout.addWidget(brand_title)
        
        header_layout.addStretch()
        
        # Status Pill
        self.status_pill = QLabel("● SYSTEM NORMAL")
        self.status_pill.setObjectName("StatusPillNormal")
        header_layout.addWidget(self.status_pill)
        
        # Simulator Inject Button
        sim_btn = QPushButton("⚡ Simulate Traffic")
        sim_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        sim_btn.setStyleSheet("background-color: #334155; color: #38bdf8; border: 1px solid #0284c7; padding: 4px 10px; border-radius: 6px; font-weight: bold;")
        sim_btn.clicked.connect(self.simulate_packet_burst)
        header_layout.addWidget(sim_btn)
        
        user_lbl = QLabel(f"👤 {self.username}")
        user_lbl.setStyleSheet("color: #cbd5e1; font-weight: 500; margin-left: 15px;")
        header_layout.addWidget(user_lbl)
        
        main_layout.addWidget(header)
        
        # 2. BODY SPLIT (Sidebar + Content Area)
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        
        # --- LEFT SIDEBAR ---
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
            ("⛔ Blocked IPs", 4)
        ]
        
        for text, page_idx in pages_info:
            btn = QPushButton(text)
            btn.setProperty("page_index", page_idx)
            btn.setProperty("full_text", text)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            if page_idx == 0:
                btn.setProperty("class", "NavBtnSelected")
            else:
                btn.setProperty("class", "NavBtn")
            
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
        
        # --- MAIN STACKED CONTENT PAGES ---
        self.stacked_widget = QStackedWidget()
        
        # Page 0: Home Overview
        self.page_home = self.create_home_page()
        self.stacked_widget.addWidget(self.page_home)
        
        # Page 1: Live Logs
        self.page_logs = self.create_logs_page()
        self.stacked_widget.addWidget(self.page_logs)
        
        # Page 2: Blacklist
        self.page_blacklist = self.create_rules_table_page("Blacklisted IPs", "BLACKLIST")
        self.stacked_widget.addWidget(self.page_blacklist)
        
        # Page 3: Whitelist
        self.page_whitelist = self.create_rules_table_page("Whitelisted IPs", "WHITELIST")
        self.stacked_widget.addWidget(self.page_whitelist)
        
        # Page 4: Blocked
        self.page_blocked = self.create_rules_table_page("Blocked IPs", "BLOCKED")
        self.stacked_widget.addWidget(self.page_blocked)
        
        body_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(body)

    # --- SIDEBAR COLLAPSE TOGGLE ---
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

    # --- PAGE SWITCHING ---
    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for btn in self.nav_buttons:
            if btn.property("page_index") == index:
                btn.setStyleSheet("background-color: #6366f1; color: white; font-weight: bold; border-radius: 8px; padding: 12px 16px; text-align: left;")
            else:
                btn.setStyleSheet("background-color: transparent; color: #94a3b8; border: none; padding: 12px 16px; font-size: 14px; text-align: left;")
        self.refresh_data()

    # --- PAGE 0: HOME PAGE BUILDER ---
    def create_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        welcome = QLabel(f"Welcome back, {self.username} 👋")
        welcome.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(welcome)
        
        sub = QLabel("Layer 3 Control Dashboard — Real-time Anomaly Detection & Traffic Filtering")
        sub.setStyleSheet("color: #94a3b8;")
        layout.addWidget(sub)
        
        # CARDS GRID
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)
        
        self.card_logs = InteractiveCard("LIVE PACKETS", "0", "0 Anomalies Flagged", "#0284c7", lambda: self.switch_page(1))
        self.card_black = InteractiveCard("BLACKLISTED", "0", "Flagged for Inspection", "#f59e0b", lambda: self.switch_page(2))
        self.card_white = InteractiveCard("WHITELISTED", "0", "Trusted IPs", "#10b981", lambda: self.switch_page(3))
        self.card_block = InteractiveCard("BLOCKED", "0", "Active Drops", "#ef4444", lambda: self.switch_page(4))
        
        cards_layout.addWidget(self.card_logs)
        cards_layout.addWidget(self.card_black)
        cards_layout.addWidget(self.card_white)
        cards_layout.addWidget(self.card_block)
        
        layout.addLayout(cards_layout)
        
        activity_frame = QFrame()
        activity_frame.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 15px;")
        act_layout = QVBoxLayout(activity_frame)
        
        act_title = QLabel("🛡️ Threat Prevention Engine Status")
        act_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        act_layout.addWidget(act_title)
        
        self.act_desc = QLabel("Active SQLite Database rule sync active. Machine Learning Baseline ready for real-time inference.")
        self.act_desc.setStyleSheet("color: #cbd5e1; margin-top: 5px;")
        act_layout.addWidget(self.act_desc)
        
        layout.addWidget(activity_frame)
        layout.addStretch()
        return page

    # --- PAGE 1: LIVE PACKET LOGS BUILDER ---
    def create_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)
        
        header_lbl = QLabel("📊 Live Packet & Anomaly Logs")
        header_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(header_lbl)
        
        self.logs_table = QTableWidget(0, 7)
        self.logs_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Source IP", "Dest IP", "Protocol", "Size", "Status"])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.logs_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.logs_table.customContextMenuRequested.connect(self.show_logs_context_menu)
        
        layout.addWidget(self.logs_table)
        return page

    # --- PAGE 2, 3, 4: RULES TABLE BUILDER ---
    def create_rules_table_page(self, title_text, rule_type):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 25, 25, 25)
        
        header = QLabel(title_text)
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(header)
        
        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["IP Address", "Reason", "Added Date"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.setProperty("rule_type", rule_type)
        table.customContextMenuRequested.connect(lambda pos, t=table, r=rule_type: self.show_rules_context_menu(pos, t, r))
        
        layout.addWidget(table)
        setattr(self, f"table_{rule_type.lower()}", table)
        return page

    # --- CONTEXT MENU FOR LIVE LOGS ---
    def show_logs_context_menu(self, pos):
        item = self.logs_table.itemAt(pos)
        if not item:
            return
            
        row = item.row()
        src_ip = self.logs_table.item(row, 2).text()
        
        menu = QMenu(self)
        menu.setTitle(f"Action for {src_ip}")
        
        action_black = QAction("🚨 Move to Blacklist", self)
        action_black.triggered.connect(lambda: self.set_ip_rule(src_ip, "BLACKLIST", "Flagged from live logs"))
        
        action_white = QAction("🛡️ Move to Whitelist", self)
        action_white.triggered.connect(lambda: self.set_ip_rule(src_ip, "WHITELIST", "Verified safe in live logs"))
        
        action_block = QAction("⛔ Block IP", self)
        action_block.triggered.connect(lambda: self.set_ip_rule(src_ip, "BLOCKED", "Blocked from live logs"))
        
        menu.addAction(action_black)
        menu.addAction(action_white)
        menu.addAction(action_block)
        
        menu.exec(self.logs_table.viewport().mapToGlobal(pos))

    # --- CONTEXT MENU FOR RULES TABLES ---
    def show_rules_context_menu(self, pos, table, current_rule_type):
        item = table.itemAt(pos)
        if not item:
            return
            
        row = item.row()
        ip_addr = table.item(row, 0).text()
        
        menu = QMenu(self)
        
        if current_rule_type != "WHITELIST":
            act_white = QAction("🛡️ Move to Whitelist", self)
            act_white.triggered.connect(lambda: self.set_ip_rule(ip_addr, "WHITELIST", "Moved to Whitelist"))
            menu.addAction(act_white)
            
        if current_rule_type != "BLACKLIST":
            act_black = QAction("🚨 Move to Blacklist", self)
            act_black.triggered.connect(lambda: self.set_ip_rule(ip_addr, "BLACKLIST", "Moved to Blacklist"))
            menu.addAction(act_black)
            
        if current_rule_type != "BLOCKED":
            act_block = QAction("⛔ Move to Blocked", self)
            act_block.triggered.connect(lambda: self.set_ip_rule(ip_addr, "BLOCKED", "Moved to Blocked"))
            menu.addAction(act_block)
            
        act_delete = QAction("❌ Remove / Clear Rule", self)
        act_delete.triggered.connect(lambda: self.remove_ip_rule(ip_addr))
        menu.addAction(act_delete)
        
        menu.exec(table.viewport().mapToGlobal(pos))

    # --- RULE ACTIONS ---
    def set_ip_rule(self, ip, rule_type, reason):
        database.add_or_update_ip_rule(ip, rule_type, reason)
        self.refresh_data()

    def remove_ip_rule(self, ip):
        database.delete_ip_rule(ip)
        self.refresh_data()

    def open_add_rule_dialog(self):
        dlg = AddRuleDialog(self)
        if dlg.exec():
            self.refresh_data()

    # --- SIMULATE PACKETS FOR LIVE DEMO ---
    def simulate_packet_burst(self):
        dummy_ips = ["192.168.1.10", "10.0.0.45", "172.16.0.88", "198.51.100.14"]
        protos = ["TCP", "UDP", "ICMP"]
        
        for _ in range(3):
            ip = random.choice(dummy_ips)
            is_anomaly = random.choice([False, False, True])
            
            packet = {
                "timestamp": int(time.time()),
                "source_ip": ip,
                "dest_ip": "192.168.1.1",
                "source_port": random.randint(1024, 65535),
                "dest_port": random.choice([80, 443, 22, 53]),
                "protocol": random.choice(protos),
                "packet_size": random.randint(64, 1500),
                "payload_size": random.randint(0, 1400)
            }
            database.log_packet(packet, is_anomaly=is_anomaly, user_id=self.user_id)
            
            if is_anomaly:
                database.add_or_update_ip_rule(
                    ip_address=ip, 
                    rule_type="BLOCKED", 
                    reason="Automated Anomaly Detection Flag (Simulated)", 
                    ttl_seconds=900
                )
                
        self.refresh_data()
    # --- DATA REFRESH CYCLE ---
    def refresh_data(self):
        stats = database.get_dashboard_stats()
        
        # Update Status Pill in Header
        if stats["total_anomalies"] > 0:
            self.status_pill.setText(f"⚠️ ABNORMALITY DETECTED ({stats['total_anomalies']} Flags)")
            self.status_pill.setObjectName("StatusPillAbnormal")
            self.status_pill.setStyleSheet("background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; border-radius: 12px; padding: 4px 12px; font-weight: bold;")
        else:
            self.status_pill.setText("● SYSTEM NORMAL")
            self.status_pill.setObjectName("StatusPillNormal")
            self.status_pill.setStyleSheet("background-color: #064e3b; color: #34d399; border: 1px solid #10b981; border-radius: 12px; padding: 4px 12px; font-weight: bold;")
            
        # Update Cards
        self.card_logs.update_data(stats["total_logs"], f"{stats['total_anomalies']} Anomalies Flagged")
        self.card_black.update_data(stats["blacklisted"], "Requires Analysis")
        self.card_white.update_data(stats["whitelisted"], "Trusted Devices")
        self.card_block.update_data(stats["blocked"], "Dropping Packets")
        
        # Populate Live Logs Table
        logs = database.get_recent_packet_logs(50)
        self.logs_table.setRowCount(len(logs))
        for row_idx, log in enumerate(logs):
            self.logs_table.setItem(row_idx, 0, QTableWidgetItem(str(log[0])))
            self.logs_table.setItem(row_idx, 1, QTableWidgetItem(time.strftime('%H:%M:%S', time.localtime(log[1]))))
            self.logs_table.setItem(row_idx, 2, QTableWidgetItem(str(log[2])))
            self.logs_table.setItem(row_idx, 3, QTableWidgetItem(f"{log[3]}:{log[5]}"))
            self.logs_table.setItem(row_idx, 4, QTableWidgetItem(str(log[6])))
            self.logs_table.setItem(row_idx, 5, QTableWidgetItem(f"{log[7]} B"))
            
            status_item = QTableWidgetItem("⚠️ ANOMALY" if log[8] else "NORMAL")
            if log[8]:
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.green)
            self.logs_table.setItem(row_idx, 6, status_item)
            
        # Refresh Rule Tables
        for rule_type in ["BLACKLIST", "WHITELIST", "BLOCKED"]:
            table = getattr(self, f"table_{rule_type.lower()}")
            rules = database.get_ip_rules(rule_type)
            table.setRowCount(len(rules))
            for r_idx, rule in enumerate(rules):
                table.setItem(r_idx, 0, QTableWidgetItem(rule[0]))
                table.setItem(r_idx, 1, QTableWidgetItem(rule[2]))
                table.setItem(r_idx, 2, QTableWidgetItem(str(rule[3])))


def start_pipeline(user_id):
    """Launches the collector sniffer piped into ueba_engine in TRAIN or DETECT mode based on user baseline status."""
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM user_baselines WHERE user_id = ? AND model_data IS NOT NULL", (user_id,))
    has_baseline = cursor.fetchone()[0] > 0
    conn.close()

    python_bin = sys.executable

    if not has_baseline:
        cmd = f"./collector | {python_bin} ueba_engine.py --mode train --samples 200 --user_id {user_id}"
        print(f"[+] New baseline required for User ID {user_id}. Starting training pipeline (200 samples)...")
    else:
        cmd = f"./collector | {python_bin} ueba_engine.py --mode detect --user_id {user_id}"
        print(f"[+] Baseline loaded for User ID {user_id}. Starting live detection pipeline...")

    subprocess.Popen(cmd, shell=True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    database.init_db()
    
    login = LoginDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        start_pipeline(login.user_id)
        main_win = MainWindow(login.user_id, login.username)
        main_win.show()
        sys.exit(app.exec())
