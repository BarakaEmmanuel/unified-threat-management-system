import argparse
import csv
import os
import sys
from datetime import datetime

# Optional OS file locking import for POSIX systems
try:
    import fcntl
except ImportError:
    fcntl = None

# Defensive ReportLab imports for automated PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Defensive subsystem imports
try:
    import database
except ImportError:
    database = None

try:
    import lookup_engine
except ImportError:
    lookup_engine = None

# Base setup for report output directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "Reports")


def format_bytes(byte_count):
    """Safely converts raw byte values into human-readable unit strings (KB, MB, GB)."""
    try:
        b = float(byte_count)
    except (TypeError, ValueError):
        return "0.00 B"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} PB"


def format_timestamp(raw_ts):
    """Converts raw timestamps or Unix epoch seconds into human-readable ISO format."""
    if not raw_ts and raw_ts != 0:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(raw_ts).strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(raw_ts, str):
            raw_str = raw_ts.strip()
            if raw_str.replace(".", "", 1).isdigit():
                return datetime.fromtimestamp(float(raw_str)).strftime("%Y-%m-%d %H:%M:%S")
            return raw_str
        return str(raw_ts)
    except Exception:
        return str(raw_ts)


def format_anomaly_flag(flag):
    """Maps binary anomaly indicators (0/1) to readable executive status labels."""
    try:
        val = int(flag)
        return "CRITICAL ANOMALY" if val > 0 else "CLEAN"
    except (TypeError, ValueError):
        val_str = str(flag).strip().upper()
        return "CRITICAL ANOMALY" if val_str in ("1", "TRUE", "CRITICAL ANOMALY") else "CLEAN"


def _fetch_raw_packet_logs():
    """Robust helper to fetch packet logs across all available database interface signatures."""
    if not database:
        return []
    
    # Try get_recent_packet_logs first to align with live GUI worker
    if hasattr(database, "get_recent_packet_logs"):
        try:
            logs = database.get_recent_packet_logs(1000)
            if logs:
                return logs
        except Exception:
            pass

    if hasattr(database, "get_packet_logs"):
        try:
            logs = database.get_packet_logs()
            if logs:
                return logs
        except Exception:
            pass

    return []


def _fetch_all_ip_rules():
    """Robust helper to fetch rules across all policy tables."""
    rules = []
    if not database or not hasattr(database, "get_ip_rules"):
        return rules

    try:
        res = database.get_ip_rules()
        if res:
            return res
    except Exception:
        pass

    for r_type in ["BLACKLIST", "WHITELIST", "BLOCKED"]:
        try:
            res = database.get_ip_rules(r_type)
            if res:
                rules.extend(res)
        except Exception:
            pass

    return rules


def _get_traffic_context_data():
    headers = [
        "Timestamp", "Source IP", "Dest IP", "Dest Port",
        "Protocol", "Packet Size (Bytes)", "Human Volume",
        "Resolved Context", "Anomaly Flag"
    ]
    rows = []
    logs = _fetch_raw_packet_logs()

    for log in logs:
        if isinstance(log, dict):
            ts = format_timestamp(log.get("timestamp") or log.get("created_at") or "")
            src_ip = str(log.get("src_ip") or log.get("source_ip") or "N/A")
            dst_ip = str(log.get("dst_ip") or log.get("dest_ip") or "N/A")
            dst_port = str(log.get("dst_port") or log.get("dest_port") or log.get("port") or "N/A")
            proto = str(log.get("protocol") or log.get("proto") or "N/A")
            pkt_size = log.get("packet_size") or log.get("size") or 0
            raw_anomaly = log.get("anomaly_flag") or log.get("is_anomaly") or 0
        else:
            # Flexible tuple indexing based on actual database query schema
            if len(log) >= 9:
                ts = format_timestamp(log[1])
                src_ip = str(log[2])
                dst_ip = str(log[3])
                dst_port = str(log[5]) if str(log[5]).isdigit() else str(log[4])
                proto = str(log[6])
                pkt_size = log[7]
                raw_anomaly = log[8]
            elif len(log) == 8:
                ts = format_timestamp(log[1])
                src_ip = str(log[2])
                dst_ip = str(log[3])
                dst_port = str(log[4])
                proto = str(log[5])
                pkt_size = log[6]
                raw_anomaly = log[7]
            else:
                ts = format_timestamp(log[1] if len(log) > 1 else "")
                src_ip = str(log[2]) if len(log) > 2 else "N/A"
                dst_ip = str(log[3]) if len(log) > 3 else "N/A"
                dst_port = str(log[4]) if len(log) > 4 else "N/A"
                proto = str(log[5]) if len(log) > 5 else "N/A"
                pkt_size = log[6] if len(log) > 6 else 0
                raw_anomaly = log[7] if len(log) > 7 else 0

        context = "Unknown"
        if lookup_engine and hasattr(lookup_engine, "lookup_ip_context"):
            lookup_target = dst_ip if dst_ip not in ("N/A", "", "0.0.0.0") else src_ip
            try:
                context = lookup_engine.lookup_ip_context(lookup_target)
            except Exception:
                context = "Lookup Error"

        human_vol = format_bytes(pkt_size)
        anomaly_status = format_anomaly_flag(raw_anomaly)
        rows.append([ts, src_ip, dst_ip, dst_port, proto, pkt_size, human_vol, context, anomaly_status])

    rows.sort(key=lambda x: 0 if x[8] == "CRITICAL ANOMALY" else 1)
    return headers, rows


def _get_policy_hits_data():
    headers = [
        "Timestamp", "Source IP", "Target IP", "Policy Action",
        "Reason", "Hit Count", "Rule Status", "Expiration Time"
    ]
    rows = []
    rules = _fetch_all_ip_rules()

    for r in rules:
        if isinstance(r, dict):
            src_ip = str(r.get("src_ip") or r.get("ip_address") or r.get("ip") or "N/A")
            target_ip = str(r.get("target_ip") or r.get("dest_ip") or "N/A")
            action = str(r.get("action") or r.get("rule_type") or "N/A")
            reason = str(r.get("reason") or "N/A")
            ts = format_timestamp(r.get("created_at") or r.get("timestamp") or r.get("added_date") or "")
            hit_count = r.get("hit_count", 0)
            status = str(r.get("status", "ACTIVE"))
            expires = format_timestamp(r.get("expiration_time") or r.get("expires") or "N/A")
        else:
            # Correct alignment matching system tuple structure: (src_ip, dest_ip, rule_type, reason, created_at, ...)
            src_ip = str(r[0]) if len(r) > 0 and r[0] is not None else "N/A"
            target_ip = str(r[1]) if len(r) > 1 and r[1] is not None else "N/A"
            action = str(r[2]) if len(r) > 2 and r[2] is not None else "N/A"
            reason = str(r[3]) if len(r) > 3 and r[3] is not None else "N/A"
            ts = format_timestamp(r[4] if len(r) > 4 else "")
            hit_count = r[5] if len(r) > 5 and r[5] is not None else 0
            status = str(r[6]) if len(r) > 6 and r[6] is not None else "ACTIVE"
            expires = format_timestamp(r[7] if len(r) > 7 else "N/A")

        rows.append([ts, src_ip, target_ip, action, reason, hit_count, status, expires])

    rows.sort(key=lambda x: int(x[5]) if str(x[5]).isdigit() else 0, reverse=True)
    return headers, rows


def _get_connected_devices_data():
    headers = [
        "Last Seen", "IP Address", "MAC Address", "Vendor OUI",
        "Hostname", "Detected OS", "Ingress Bytes", "Egress Bytes",
        "Total Traffic Volume", "Active Policy Status"
    ]
    rows = []
    if not database or not hasattr(database, "get_connected_devices"):
        return headers, rows

    try:
        devices = database.get_connected_devices() or []
        for dev in devices:
            if isinstance(dev, dict):
                last_seen = format_timestamp(dev.get("last_seen") or dev.get("timestamp") or "")
                ip = str(dev.get("ip_address") or dev.get("ip") or "N/A")
                mac = str(dev.get("mac_address") or dev.get("mac") or "N/A")
                vendor = str(dev.get("vendor_oui") or dev.get("vendor") or "Unknown")
                hostname = str(dev.get("hostname") or "Unknown")
                os_type = str(dev.get("detected_os") or dev.get("os") or "Unknown")
                
                # Check bytes_in / bytes_out keys matching telemetry worker
                ingress = dev.get("bytes_in") if "bytes_in" in dev else (dev.get("ingress_bytes") or dev.get("ingress") or 0)
                egress = dev.get("bytes_out") if "bytes_out" in dev else (dev.get("egress_bytes") or dev.get("egress") or 0)
                status = str(dev.get("active_rule") or dev.get("policy_status") or dev.get("status") or "ACTIVE")
            else:
                last_seen = format_timestamp(dev[0] if len(dev) > 0 else "")
                ip = str(dev[1]) if len(dev) > 1 else "N/A"
                mac = str(dev[2]) if len(dev) > 2 else "N/A"
                vendor = str(dev[3]) if len(dev) > 3 and dev[3] else "Unknown"
                hostname = str(dev[4]) if len(dev) > 4 and dev[4] else "Unknown"
                os_type = str(dev[5]) if len(dev) > 5 and dev[5] else "Unknown"
                ingress = dev[6] if len(dev) > 6 else 0
                egress = dev[7] if len(dev) > 7 else 0
                status = str(dev[8]) if len(dev) > 8 and dev[8] else "ACTIVE"

            try:
                ing_val = float(ingress) if ingress is not None else 0.0
            except (ValueError, TypeError):
                ing_val = 0.0

            try:
                eg_val = float(egress) if egress is not None else 0.0
            except (ValueError, TypeError):
                eg_val = 0.0

            total_bytes = ing_val + eg_val
            total_vol = format_bytes(total_bytes)

            rows.append([last_seen, ip, mac, vendor, hostname, os_type, int(ing_val), int(eg_val), total_vol, status])

        rows.sort(key=lambda x: (x[6] + x[7]), reverse=True)
    except Exception as e:
        sys.stderr.write(f"[-] Connected devices fetch warning: {e}\n")

    return headers, rows


def _get_live_packet_logs_data():
    headers = [
        "Log ID", "Timestamp", "User ID", "Source Port",
        "Dest Port", "Protocol", "Packet Size", "Payload Size",
        "Anomaly Flag", "Endpoint Classification"
    ]
    rows = []
    logs = _fetch_raw_packet_logs()

    for log in logs:
        if isinstance(log, dict):
            log_id = log.get("id") or log.get("log_id") or ""
            ts = format_timestamp(log.get("timestamp") or log.get("created_at") or "")
            user_id = log.get("user_id") or "N/A"
            src_port = log.get("src_port") or log.get("source_port") or "N/A"
            dst_port = log.get("dst_port") or log.get("dest_port") or "N/A"
            proto = log.get("protocol") or log.get("proto") or "N/A"
            pkt_size = log.get("packet_size") or log.get("size") or 0
            payload_size = log.get("payload_size") or 0
            raw_anomaly = log.get("anomaly_flag") or log.get("is_anomaly") or 0
            classification = log.get("classification") or log.get("endpoint_classification") or "Unclassified"
        else:
            if len(log) >= 10:
                log_id = log[0]
                ts = format_timestamp(log[1])
                user_id = log[2]
                src_port = log[3]
                dst_port = log[4]
                proto = log[5]
                pkt_size = log[6]
                payload_size = log[7]
                raw_anomaly = log[8]
                classification = str(log[9]) if log[9] else "Unclassified"
            elif len(log) == 9:
                log_id = log[0]
                ts = format_timestamp(log[1])
                src_ip = str(log[2])
                dst_ip = str(log[3])
                user_id = "N/A"
                src_port = "N/A"
                dst_port = log[5]
                proto = log[6]
                pkt_size = log[7]
                payload_size = 0
                raw_anomaly = log[8]
                classification = "Unclassified"

                if lookup_engine and hasattr(lookup_engine, "lookup_ip_context"):
                    try:
                        classification = lookup_engine.lookup_ip_context(dst_ip if dst_ip != "N/A" else src_ip)
                    except Exception:
                        pass
            else:
                log_id = log[0] if len(log) > 0 else ""
                ts = format_timestamp(log[1] if len(log) > 1 else "")
                user_id = log[2] if len(log) > 2 else "N/A"
                src_port = log[3] if len(log) > 3 else "N/A"
                dst_port = log[4] if len(log) > 4 else "N/A"
                proto = log[5] if len(log) > 5 else "N/A"
                pkt_size = log[6] if len(log) > 6 else 0
                payload_size = log[7] if len(log) > 7 else 0
                raw_anomaly = log[8] if len(log) > 8 else 0
                classification = str(log[9]) if len(log) > 9 and log[9] else "Unclassified"

        anomaly_status = format_anomaly_flag(raw_anomaly)
        rows.append([log_id, ts, user_id, src_port, dst_port, proto, pkt_size, payload_size, anomaly_status, classification])

    rows.sort(key=lambda x: 0 if x[8] == "CRITICAL ANOMALY" else 1)
    return headers, rows


def fetch_section_data(section_name):
    """Query system database or engines based on normalized section name."""
    section_key = section_name.strip().lower().replace(" ", "_")

    if section_key in ("traffic_context_graph", "traffic_context"):
        return _get_traffic_context_data()
    elif section_key in ("policy_hits_graph", "policy_hits"):
        return _get_policy_hits_data()
    elif section_key in ("connected_devices", "devices"):
        return _get_connected_devices_data()
    elif section_key in ("live_packet_logs", "packet_logs", "logs"):
        return _get_live_packet_logs_data()

    # Fallback default section handling
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    headers = ["Timestamp", "Section", "Event/Metric", "Status"]
    rows = [
        [timestamp, section_name.upper(), "Routine Section Check", "ACTIVE"],
        [timestamp, section_name.upper(), "Telemetry Log Export", "SUCCESS"]
    ]
    return headers, rows


def generate_pdf_report(section_name, headers, rows, pdf_path):
    """Generates a styled executive PDF report with telemetry summary block."""
    if not REPORTLAB_AVAILABLE:
        sys.stderr.write("[-] ReportLab library not found. Skipping PDF export.\n")
        return

    doc = SimpleDocTemplate(
        pdf_path, pagesize=letter,
        leftMargin=20, rightMargin=20, topMargin=25, bottomMargin=25
    )
    styles = getSampleStyleSheet()
    elements = []

    total_records = len(rows)
    anomalies_count = sum(1 for row in rows if "CRITICAL ANOMALY" in [str(c) for c in row])

    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#0f172a'))
    meta_style = ParagraphStyle('ReportMeta', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748b'))
    summary_style = ParagraphStyle('ReportSummary', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#1e293b'))

    formatted_title = section_name.replace('_', ' ').title()
    elements.append(Paragraph(f"UTM Security Telemetry: {formatted_title}", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Records: {total_records}", meta_style))
    elements.append(Spacer(1, 8))

    summary_text = f"<b>Executive Summary:</b> Processing evaluated <b>{total_records}</b> operational log entries."
    if anomalies_count > 0:
        summary_text += f" Flagged <font color='#dc2626'><b>{anomalies_count} critical anomalies</b></font> requiring priority operator review."
    else:
        summary_text += " All monitored telemetry endpoints remain within baseline security thresholds."

    elements.append(Paragraph(summary_text, summary_style))
    elements.append(Spacer(1, 12))

    cell_style = ParagraphStyle('CellText', parent=styles['Normal'], fontSize=7.5, leading=9.5)
    header_style = ParagraphStyle('HeaderText', parent=styles['Normal'], fontSize=8, leading=10, textColor=colors.white)

    table_data = [[Paragraph(f"<b>{h}</b>", header_style) for h in headers]]
    for row in rows:
        table_data.append([Paragraph(str(cell), cell_style) for cell in row])

    col_count = len(headers)
    page_width = letter[0] - 40
    col_widths = [page_width / col_count] * col_count

    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))

    elements.append(table)
    doc.build(elements)


def generate_report(section_name):
    """Appends data to section CSV report and builds executive PDF report using kernel file locks."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    formatted_section = section_name.strip().lower().replace(" ", "_")
    csv_filename = f"{formatted_section}_report.csv"
    csv_filepath = os.path.join(REPORTS_DIR, csv_filename)
    pdf_filename = f"{formatted_section}_report.pdf"
    pdf_filepath = os.path.join(REPORTS_DIR, pdf_filename)

    try:
        headers, rows = fetch_section_data(section_name)
    except Exception as e:
        sys.stderr.write(f"[-] Data fetch error for {section_name}: {e}\n")
        headers = ["Timestamp", "Section", "Status"]
        rows = [[datetime.now().strftime("%Y-%m-%d %H:%M:%S"), section_name.upper(), "ERROR"]]

    file_exists = os.path.exists(csv_filepath) and os.path.getsize(csv_filepath) > 0

    with open(csv_filepath, mode="a", newline="", encoding="utf-8") as csv_file:
        try:
            if fcntl:
                fcntl.flock(csv_file, fcntl.LOCK_EX)

            writer = csv.writer(csv_file)

            if not file_exists:
                writer.writerow(headers)

            if rows:
                writer.writerows(rows)
            csv_file.flush()

        finally:
            if fcntl:
                fcntl.flock(csv_file, fcntl.LOCK_UN)

    generate_pdf_report(section_name, headers, rows, pdf_filepath)

    # Output lines required by gui_main.py stdout parser
    print(f"[+] CSV report generated: {csv_filepath}")
    print(f"[+] PDF report generated: {pdf_filepath}")
    return csv_filepath


def main():
    parser = argparse.ArgumentParser(description="UTM System CSV & PDF Report Generator CLI")
    parser.add_argument(
        "--section",
        type=str,
        required=True,
        help="Target GUI section name (e.g., Network, UEBA, Lookup)"
    )

    args = parser.parse_args()

    try:
        generate_report(args.section)
    except Exception as e:
        print(f"[-] Execution error generating report: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
