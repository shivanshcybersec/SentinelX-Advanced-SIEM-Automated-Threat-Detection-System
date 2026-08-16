"""
SENTINELX - PHASE 5
Advanced SIEM & Automated Threat Detection Platform
Defensive / Educational Security Project
Standard Python library only.
"""

import os
import re
import csv
import json
import time
import argparse
import hashlib
from collections import Counter, defaultdict
from datetime import datetime

APP_NAME = "SENTINELX"
VERSION = "5.0"

FAILED_LOGIN_THRESHOLD = 3
ACCESS_DENIED_THRESHOLD = 3
HIGH_ACTIVITY_THRESHOLD = 8
ANOMALY_MULTIPLIER = 2.0

SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv"}

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10
}

PRIORITY_MAP = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4"
}

MITRE_MAP = {
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force"},
    "ACCESS_DENIED_SPIKE": {"id": "T1078", "name": "Valid Accounts"},
    "PRIVILEGE_ESCALATION": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation"
    },
    "MALWARE": {"id": "T1204", "name": "User Execution"},
    "HIGH_ACTIVITY": {"id": "T1110", "name": "Brute Force"},
    "ATTACK_CHAIN": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter"
    },
    "ANOMALY": {
        "id": "T1071",
        "name": "Application Layer Protocol"
    }
}

audit_events = []
trusted_ips = set()
baseline = {}


def banner():
    print("\n" + "=" * 78)
    print("                         SENTINELX")
    print("             ADVANCED SIEM & THREAT DETECTION")
    print("                         PHASE 5")
    print("                  FINAL CAPSTONE VERSION")
    print("                  Educational / Authorized Use")
    print("=" * 78)


def section(title):
    print("\n" + "-" * 78)
    print(f" {title}")
    print("-" * 78)


def audit(action, details=""):
    audit_events.append({
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details
    })


def validate_file(path):
    path = path.strip().strip('"')

    if not path:
        print("[-] No file path provided.")
        return False

    if not os.path.isfile(path):
        print("[-] File does not exist.")
        return False

    extension = os.path.splitext(path)[1].lower()

    if extension not in SUPPORTED_EXTENSIONS:
        print("[-] Unsupported file type.")
        print("[+] Supported: .log .txt .csv")
        return False

    return True


def load_logs(path):
    path = path.strip().strip('"')

    if not validate_file(path):
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            logs = [
                line.rstrip("\r\n")
                for line in file
                if line.strip()
            ]

        audit("LOG_LOAD", f"{len(logs)} entries loaded")
        print(f"[+] Loaded {len(logs)} log entries.")
        return logs

    except OSError as error:
        print(f"[-] Read error: {error}")
        return []


def extract_ips(text):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(pattern, text)
    results = []

    for ip in candidates:
        parts = ip.split(".")
        try:
            if all(0 <= int(part) <= 255 for part in parts):
                results.append(ip)
        except ValueError:
            pass

    return list(dict.fromkeys(results))


def extract_domains(text):
    pattern = r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"
    domains = re.findall(pattern, text)
    ignored = {"localhost.localdomain"}

    return list(dict.fromkeys(
        d for d in domains if d.lower() not in ignored
    ))


def extract_hashes(text):
    pattern = (
        r"\b(?:"
        r"[A-Fa-f0-9]{32}|"
        r"[A-Fa-f0-9]{40}|"
        r"[A-Fa-f0-9]{64}"
        r")\b"
    )
    return list(dict.fromkeys(re.findall(pattern, text)))


def extract_iocs(text):
    return {
        "ips": extract_ips(text),
        "domains": extract_domains(text),
        "hashes": extract_hashes(text)
    }


def extract_timestamp(text):
    patterns = [
        r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
        r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b"
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)

    return "Unknown"


def classify_event(log):
    text = log.lower()

    critical = [
        "ransomware",
        "malware detected",
        "rootkit",
        "privilege escalation",
        "account takeover",
        "critical security event"
    ]

    if any(keyword in text for keyword in critical):
        return "CRITICAL"

    high = [
        "brute force",
        "intrusion detected",
        "unauthorized access",
        "attack detected",
        "multiple authentication failures"
    ]

    if any(keyword in text for keyword in high):
        return "HIGH"

    medium = [
        "failed login",
        "login failed",
        "authentication failed",
        "invalid password",
        "access denied",
        "permission denied",
        "warning",
        "suspicious",
        "blocked",
        "error",
        "exception",
        "failure"
    ]

    if any(keyword in text for keyword in medium):
        return "MEDIUM"

    return "LOW"


def is_failed_login(log):
    text = log.lower()
    return any(word in text for word in [
        "failed login",
        "login failed",
        "authentication failed",
        "invalid password"
    ])


def is_access_denied(log):
    text = log.lower()
    return any(word in text for word in [
        "access denied",
        "unauthorized access",
        "permission denied",
        "blocked"
    ])


def is_privilege_escalation(log):
    text = log.lower()
    return any(word in text for word in [
        "privilege escalation",
        "elevated privileges",
        "administrator privileges",
        "root access",
        "sudo"
    ])


def is_malware(log):
    text = log.lower()
    return any(word in text for word in [
        "malware",
        "ransomware",
        "trojan",
        "virus detected",
        "rootkit"
    ])


def parse_log(log):
    iocs = extract_iocs(log)

    return {
        "raw": log,
        "timestamp": extract_timestamp(log),
        "ip": iocs["ips"][0] if iocs["ips"] else None,
        "iocs": iocs,
        "severity": classify_event(log)
    }


def analyze_ip_activity(events):
    activity = defaultdict(lambda: {
        "total": 0,
        "failed": 0,
        "denied": 0,
        "high": 0,
        "critical": 0
    })

    for event in events:
        ip = event["ip"]

        if not ip:
            continue

        activity[ip]["total"] += 1

        if is_failed_login(event["raw"]):
            activity[ip]["failed"] += 1

        if is_access_denied(event["raw"]):
            activity[ip]["denied"] += 1

        if event["severity"] == "HIGH":
            activity[ip]["high"] += 1

        if event["severity"] == "CRITICAL":
            activity[ip]["critical"] += 1

    return dict(activity)


def mitre(alert_type):
    return MITRE_MAP.get(
        alert_type,
        {"id": "N/A", "name": "No mapped technique"}
    )


def confidence_for_alert(alert_type, count=1, anomaly=False):
    score = 50

    if alert_type == "BRUTE_FORCE":
        score += min(count * 8, 30)
    elif alert_type == "ACCESS_DENIED_SPIKE":
        score += min(count * 6, 25)
    elif alert_type == "PRIVILEGE_ESCALATION":
        score += 30
    elif alert_type == "MALWARE":
        score += 35
    elif alert_type == "ATTACK_CHAIN":
        score += 30
    elif alert_type == "ANOMALY":
        score += 15

    if anomaly:
        score += 10

    return min(score, 100)


def make_alert(alert_type, severity, ip, count, description, anomaly=False):
    mapping = mitre(alert_type)
    confidence = confidence_for_alert(alert_type, count, anomaly)

    return {
        "alert_id": "ALT-" + hashlib.sha1(
            (
                alert_type + str(ip) + str(count) + str(time.time())
            ).encode()
        ).hexdigest()[:10].upper(),
        "type": alert_type,
        "severity": severity,
        "priority": PRIORITY_MAP.get(severity, "P4"),
        "ip": ip or "UNKNOWN",
        "count": count,
        "confidence": confidence,
        "mitre_id": mapping["id"],
        "mitre_name": mapping["name"],
        "description": description,
        "created": datetime.now().isoformat()
    }


def deduplicate_alerts(alerts):
    unique = {}

    for alert in alerts:
        key = (alert["type"], alert["ip"])

        if key not in unique:
            unique[key] = alert
        elif alert["confidence"] > unique[key]["confidence"]:
            unique[key] = alert

    return list(unique.values())


def detect_attack_chain(events):
    activity = analyze_ip_activity(events)
    alerts = []

    for ip, data in activity.items():
        stages = 0

        if data["failed"] >= FAILED_LOGIN_THRESHOLD:
            stages += 1
        if data["denied"] >= ACCESS_DENIED_THRESHOLD:
            stages += 1
        if data["high"] > 0:
            stages += 1
        if data["critical"] > 0:
            stages += 1

        if stages >= 3:
            alerts.append(
                make_alert(
                    "ATTACK_CHAIN",
                    "CRITICAL",
                    ip,
                    stages,
                    (
                        "Multiple suspicious activity stages "
                        "were correlated for the same source IP."
                    )
                )
            )

    return alerts


def build_baseline(events):
    counts = Counter(
        event["ip"] for event in events if event["ip"]
    )
    return dict(counts)


def detect_anomalies(events, baseline_data):
    alerts = []

    if not baseline_data:
        return alerts

    average = sum(baseline_data.values()) / len(baseline_data)
    threshold = max(
        average * ANOMALY_MULTIPLIER,
        HIGH_ACTIVITY_THRESHOLD
    )

    current = Counter(
        event["ip"] for event in events if event["ip"]
    )

    for ip, count in current.items():
        if count > threshold:
            alerts.append(
                make_alert(
                    "ANOMALY",
                    "MEDIUM",
                    ip,
                    count,
                    (
                        "Source IP generated significantly more "
                        "events than the observed baseline."
                    ),
                    anomaly=True
                )
            )

    return alerts


def generate_alerts(events, baseline_data=None):
    activity = analyze_ip_activity(events)
    alerts = []

    for ip, data in activity.items():
        if ip in trusted_ips:
            continue

        if data["failed"] >= FAILED_LOGIN_THRESHOLD:
            alerts.append(
                make_alert(
                    "BRUTE_FORCE",
                    "HIGH",
                    ip,
                    data["failed"],
                    (
                        "Multiple failed authentication attempts "
                        "detected from the same source IP."
                    )
                )
            )

        if data["denied"] >= ACCESS_DENIED_THRESHOLD:
            alerts.append(
                make_alert(
                    "ACCESS_DENIED_SPIKE",
                    "HIGH",
                    ip,
                    data["denied"],
                    "Repeated access-denied events detected."
                )
            )

        if data["total"] >= HIGH_ACTIVITY_THRESHOLD:
            alerts.append(
                make_alert(
                    "HIGH_ACTIVITY",
                    "MEDIUM",
                    ip,
                    data["total"],
                    (
                        "Unusually high number of events observed "
                        "from this source IP."
                    )
                )
            )

        if data["critical"] > 0:
            alerts.append(
                make_alert(
                    "MALWARE",
                    "CRITICAL",
                    ip,
                    data["critical"],
                    (
                        "Critical or potentially malicious "
                        "security activity detected."
                    )
                )
            )

    for event in events:
        ip = event["ip"]

        if ip in trusted_ips:
            continue

        if is_privilege_escalation(event["raw"]):
            alerts.append(
                make_alert(
                    "PRIVILEGE_ESCALATION",
                    "CRITICAL",
                    ip,
                    1,
                    "Potential privilege escalation activity detected."
                )
            )

        if is_malware(event["raw"]):
            alerts.append(
                make_alert(
                    "MALWARE",
                    "CRITICAL",
                    ip,
                    1,
                    "Potential malware-related event detected."
                )
            )

    alerts.extend(detect_attack_chain(events))

    if baseline_data:
        alerts.extend(
            detect_anomalies(events, baseline_data)
        )

    return deduplicate_alerts(alerts)


def create_incidents(alerts):
    incidents = []

    for index, alert in enumerate(alerts, start=1):
        incidents.append({
            "incident_id": (
                "INC-"
                + datetime.now().strftime("%Y%m%d%H%M%S")
                + "-"
                + str(index)
            ),
            "status": "OPEN",
            "priority": alert["priority"],
            "severity": alert["severity"],
            "alert_id": alert["alert_id"],
            "alert_type": alert["type"],
            "source_ip": alert["ip"],
            "confidence": alert["confidence"],
            "mitre_id": alert["mitre_id"],
            "mitre_name": alert["mitre_name"],
            "description": alert["description"],
            "created": datetime.now().isoformat()
        })

    return incidents


def update_incident_status(incidents, incident_id, status):
    valid = {"OPEN", "INVESTIGATING", "CLOSED"}
    status = status.upper()

    if status not in valid:
        return False

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            incident["status"] = status
            audit("INCIDENT_STATUS", f"{incident_id} -> {status}")
            return True

    return False


def calculate_risk(events, alerts, incidents):
    score = 0

    for event in events:
        score += SEVERITY_WEIGHT.get(event["severity"], 0)

    for alert in alerts:
        weight = SEVERITY_WEIGHT.get(alert["severity"], 0)
        score += weight * 2
        score += int(alert["confidence"] / 20)

    for incident in incidents:
        if incident["priority"] == "P1":
            score += 8
        elif incident["priority"] == "P2":
            score += 5
        else:
            score += 2

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def collect_iocs(events):
    ips = set()
    domains = set()
    hashes = set()

    for event in events:
        iocs = event["iocs"]
        ips.update(iocs["ips"])
        domains.update(iocs["domains"])
        hashes.update(iocs["hashes"])

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": sorted(hashes)
    }


def show_statistics(events, alerts, incidents):
    section("SECURITY STATISTICS")

    severity = Counter(event["severity"] for event in events)
    ips = Counter(event["ip"] for event in events if event["ip"])

    print(f"Total Events       : {len(events)}")
    print(f"Alerts             : {len(alerts)}")
    print(f"Incidents          : {len(incidents)}")

    print("\nSeverity:")
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        print(f"  {level:<10}: {severity.get(level, 0)}")

    print("\nTop Source IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {ip:<18} {count} events")


def show_alerts(alerts):
    section("SECURITY ALERTS")

    if not alerts:
        print("[+] No alerts detected.")
        return

    for number, alert in enumerate(alerts, start=1):
        print(f"\nALERT #{number}")
        print(f"ID         : {alert['alert_id']}")
        print(f"Type       : {alert['type']}")
        print(f"Severity   : {alert['severity']}")
        print(f"Priority   : {alert['priority']}")
        print(f"Source IP  : {alert['ip']}")
        print(f"Count      : {alert['count']}")
        print(f"Confidence : {alert['confidence']}%")
        print(
            f"MITRE      : {alert['mitre_id']} - "
            f"{alert['mitre_name']}"
        )
        print(f"Description: {alert['description']}")


def show_incidents(incidents):
    section("INCIDENT MANAGEMENT")

    if not incidents:
        print("[+] No incidents.")
        return

    for incident in incidents:
        print(f"\nIncident ID : {incident['incident_id']}")
        print(f"Status      : {incident['status']}")
        print(f"Priority    : {incident['priority']}")
        print(f"Severity    : {incident['severity']}")
        print(f"Source IP   : {incident['source_ip']}")
        print(f"Confidence  : {incident['confidence']}%")
        print(
            f"MITRE       : {incident['mitre_id']} - "
            f"{incident['mitre_name']}"
        )


def show_iocs(events):
    section("IOC INTELLIGENCE")

    iocs = collect_iocs(events)

    print(f"IP Addresses : {len(iocs['ips'])}")
    for item in iocs["ips"]:
        print(f"  - {item}")

    print(f"\nDomains      : {len(iocs['domains'])}")
    for item in iocs["domains"]:
        print(f"  - {item}")

    print(f"\nHashes       : {len(iocs['hashes'])}")
    for item in iocs["hashes"]:
        print(f"  - {item}")


def search_logs(events):
    section("LOG SEARCH")

    keyword = input("Enter keyword: ").strip()

    if not keyword:
        print("[-] Keyword cannot be empty.")
        return

    results = [
        event for event in events
        if keyword.lower() in event["raw"].lower()
    ]

    print(f"\n[+] Matches: {len(results)}")

    for index, event in enumerate(results, start=1):
        print(
            f"{index}. [{event['severity']}] "
            f"{event['raw']}"
        )


def report_folder():
    folder = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "reports"
    )
    os.makedirs(folder, exist_ok=True)
    return folder


def generate_txt_report(source, events, alerts, incidents):
    score, level = calculate_risk(events, alerts, incidents)

    path = os.path.join(
        report_folder(),
        "sentinelx_phase5_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".txt"
    )

    with open(path, "w", encoding="utf-8") as file:
        file.write("SENTINELX PHASE 5 SECURITY REPORT\n")
        file.write("=" * 70 + "\n\n")
        file.write(f"Generated : {datetime.now()}\n")
        file.write(f"Source    : {source}\n")
        file.write(f"Events    : {len(events)}\n")
        file.write(f"Alerts    : {len(alerts)}\n")
        file.write(f"Incidents : {len(incidents)}\n")
        file.write(f"Risk      : {score}/100 ({level})\n\n")

        file.write("ALERTS\n")
        file.write("-" * 70 + "\n")

        for alert in alerts:
            file.write(f"\n{alert['alert_id']}\n")
            file.write(f"Type: {alert['type']}\n")
            file.write(f"Severity: {alert['severity']}\n")
            file.write(f"Priority: {alert['priority']}\n")
            file.write(f"IP: {alert['ip']}\n")
            file.write(f"Confidence: {alert['confidence']}%\n")
            file.write(
                f"MITRE: {alert['mitre_id']} - "
                f"{alert['mitre_name']}\n"
            )
            file.write(
                f"Description: {alert['description']}\n"
            )

        file.write("\nINCIDENTS\n")
        file.write("-" * 70 + "\n")

        for incident in incidents:
            file.write(f"\n{incident['incident_id']}\n")
            file.write(f"Status: {incident['status']}\n")
            file.write(f"Priority: {incident['priority']}\n")
            file.write(f"Severity: {incident['severity']}\n")
            file.write(f"IP: {incident['source_ip']}\n")

    return path


def generate_json_report(source, events, alerts, incidents):
    score, level = calculate_risk(events, alerts, incidents)

    data = {
        "application": APP_NAME,
        "version": VERSION,
        "generated": datetime.now().isoformat(),
        "source": source,
        "risk": {
            "score": score,
            "level": level
        },
        "statistics": {
            "events": len(events),
            "alerts": len(alerts),
            "incidents": len(incidents)
        },
        "iocs": collect_iocs(events),
        "alerts": alerts,
        "incidents": incidents,
        "audit": audit_events
    }

    path = os.path.join(
        report_folder(),
        "sentinelx_phase5_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".json"
    )

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return path


def generate_csv_report(alerts):
    path = os.path.join(
        report_folder(),
        "sentinelx_alerts_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".csv"
    )

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
            "Alert ID",
            "Type",
            "Severity",
            "Priority",
            "Source IP",
            "Count",
            "Confidence",
            "MITRE ID",
            "MITRE Technique",
            "Description"
        ])

        for alert in alerts:
            writer.writerow([
                alert["alert_id"],
                alert["type"],
                alert["severity"],
                alert["priority"],
                alert["ip"],
                alert["count"],
                alert["confidence"],
                alert["mitre_id"],
                alert["mitre_name"],
                alert["description"]
            ])

    return path


def generate_html_report(source, events, alerts, incidents):
    score, level = calculate_risk(events, alerts, incidents)

    path = os.path.join(
        report_folder(),
        "sentinelx_phase5_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".html"
    )

    with open(path, "w", encoding="utf-8") as file:
        file.write("<!DOCTYPE html><html><head>")
        file.write("<meta charset='UTF-8'>")
        file.write("<title>SentinelX Report</title>")
        file.write(
            "<style>"
            "body{font-family:Arial;margin:40px;}"
            "table{border-collapse:collapse;width:100%;}"
            "th,td{border:1px solid #ccc;padding:8px;}"
            "th{background:#eee;}"
            "</style>"
        )
        file.write("</head><body>")
        file.write("<h1>SENTINELX Phase 5</h1>")
        file.write("<h2>Security Report</h2>")
        file.write(f"<p><b>Source:</b> {source}</p>")
        file.write(
            f"<p><b>Risk:</b> {score}/100 ({level})</p>"
        )
        file.write(f"<p><b>Events:</b> {len(events)}</p>")
        file.write(f"<p><b>Alerts:</b> {len(alerts)}</p>")

        file.write("<h2>Alerts</h2><table>")
        file.write(
            "<tr><th>Type</th><th>Severity</th>"
            "<th>IP</th><th>Confidence</th>"
            "<th>MITRE</th></tr>"
        )

        for alert in alerts:
            file.write(
                "<tr>"
                f"<td>{alert['type']}</td>"
                f"<td>{alert['severity']}</td>"
                f"<td>{alert['ip']}</td>"
                f"<td>{alert['confidence']}%</td>"
                f"<td>{alert['mitre_id']}</td>"
                "</tr>"
            )

        file.write("</table>")
        file.write("<h2>Incidents</h2><table>")
        file.write(
            "<tr><th>ID</th><th>Status</th>"
            "<th>Priority</th><th>Severity</th>"
            "<th>IP</th></tr>"
        )

        for incident in incidents:
            file.write(
                "<tr>"
                f"<td>{incident['incident_id']}</td>"
                f"<td>{incident['status']}</td>"
                f"<td>{incident['priority']}</td>"
                f"<td>{incident['severity']}</td>"
                f"<td>{incident['source_ip']}</td>"
                "</tr>"
            )

        file.write("</table></body></html>")

    return path


def generate_reports(source, events, alerts, incidents):
    section("REPORT GENERATION")

    try:
        txt = generate_txt_report(
            source, events, alerts, incidents
        )
        js = generate_json_report(
            source, events, alerts, incidents
        )
        csv_file = generate_csv_report(alerts)
        html = generate_html_report(
            source, events, alerts, incidents
        )

        print(f"[+] TXT  : {txt}")
        print(f"[+] JSON : {js}")
        print(f"[+] CSV  : {csv_file}")
        print(f"[+] HTML : {html}")

        audit(
            "REPORT_GENERATION",
            "TXT/JSON/CSV/HTML"
        )

    except OSError as error:
        print(f"[-] Report error: {error}")


def show_performance(event_count, elapsed):
    section("PERFORMANCE")

    print(f"Events Processed : {event_count}")
    print(f"Processing Time  : {elapsed:.6f} seconds")

    rate = event_count / elapsed if elapsed > 0 else 0

    print(f"Processing Rate  : {rate:.2f} events/sec")


def dashboard(events, alerts, incidents, elapsed):
    section("SENTINELX SECURITY DASHBOARD")

    score, level = calculate_risk(
        events, alerts, incidents
    )

    iocs = collect_iocs(events)

    print(f"Risk Level       : {level}")
    print(f"Risk Score       : {score}/100")
    print(f"Events           : {len(events)}")
    print(f"Alerts           : {len(alerts)}")
    print(f"Incidents        : {len(incidents)}")
    print(f"IP IOCs          : {len(iocs['ips'])}")
    print(f"Domain IOCs      : {len(iocs['domains'])}")
    print(f"Hash IOCs        : {len(iocs['hashes'])}")
    print(f"Processing Time  : {elapsed:.6f}s")


def manage_whitelist():
    section("TRUSTED IP MANAGEMENT")

    print("Current trusted IPs:")

    if trusted_ips:
        for ip in sorted(trusted_ips):
            print(f"  - {ip}")
    else:
        print("  None")

    print("\n1. Add IP")
    print("2. Remove IP")
    print("3. Back")

    choice = input("Choose: ").strip()

    if choice == "1":
        ip = input("Enter trusted IP: ").strip()

        if re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            ip
        ):
            trusted_ips.add(ip)
            audit("WHITELIST_ADD", ip)
            print("[+] IP added.")
        else:
            print("[-] Invalid IPv4 address.")

    elif choice == "2":
        ip = input("Enter IP to remove: ").strip()

        if ip in trusted_ips:
            trusted_ips.remove(ip)
            audit("WHITELIST_REMOVE", ip)
            print("[+] IP removed.")
        else:
            print("[-] IP not found.")


def incident_menu(incidents):
    section("INCIDENT STATUS")

    if not incidents:
        print("[+] No incidents.")
        return

    for incident in incidents:
        print(
            f"{incident['incident_id']} "
            f"[{incident['status']}]"
        )

    incident_id = input("\nIncident ID: ").strip()
    status = input(
        "New status (OPEN/INVESTIGATING/CLOSED): "
    ).strip()

    if update_incident_status(
        incidents,
        incident_id,
        status
    ):
        print("[+] Incident updated.")
    else:
        print("[-] Incident/status not found.")


def watch_file(path):
    section("REAL-TIME LOG MONITOR")

    if not os.path.isfile(path):
        print("[-] File does not exist.")
        return

    print("[+] Monitoring file.")
    print("[+] Press CTRL+C to stop.")

    events = []

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:
            file.seek(0, os.SEEK_END)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                line = line.strip()

                if not line:
                    continue

                event = parse_log(line)
                events.append(event)

                alerts = generate_alerts(events)

                if alerts:
                    latest = alerts[-1]

                    print("\n[!] ALERT")
                    print(f"Type       : {latest['type']}")
                    print(f"Severity   : {latest['severity']}")
                    print(f"IP         : {latest['ip']}")
                    print(
                        f"Confidence : "
                        f"{latest['confidence']}%"
                    )
                    print(
                        f"MITRE      : "
                        f"{latest['mitre_id']}"
                    )

    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped.")
        audit("WATCH_STOP", path)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "SentinelX Phase 5 "
            "SIEM & Threat Detection"
        )
    )

    parser.add_argument(
        "file",
        nargs="?",
        help="Path to log file"
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Monitor log file in real time"
    )

    return parser.parse_args()


def main():
    global baseline

    args = parse_arguments()
    banner()

    if args.watch:
        if not args.file:
            print("[-] --watch requires a file.")
            print(
                "Example: "
                "python main.py logs.txt --watch"
            )
            return

        watch_file(args.file)
        return

    path = args.file

    if not path:
        path = input(
            "\nEnter log file path: "
        ).strip().strip('"')

    logs = load_logs(path)

    if not logs:
        print("[-] No logs to analyze.")
        return

    start = time.perf_counter()

    events = [parse_log(log) for log in logs]
    baseline = build_baseline(events)

    alerts = generate_alerts(
        events,
        baseline
    )

    incidents = create_incidents(alerts)

    elapsed = time.perf_counter() - start

    audit(
        "ANALYSIS_COMPLETE",
        f"{len(events)} events"
    )

    print("\n[+] Analysis completed.")
    print(f"[+] Events: {len(events)}")
    print(f"[+] Alerts: {len(alerts)}")
    print(f"[+] Incidents: {len(incidents)}")

    while True:
        print("\n" + "=" * 70)
        print("                    SENTINELX MENU")
        print("=" * 70)

        print("1. Security Dashboard")
        print("2. Statistics")
        print("3. Alerts")
        print("4. Incidents")
        print("5. IOC Intelligence")
        print("6. Search Logs")
        print("7. Risk Assessment")
        print("8. Performance")
        print("9. Incident Status")
        print("10. Trusted IP Management")
        print("11. Generate Reports")
        print("12. Audit Trail")
        print("13. Exit")

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":
            dashboard(
                events,
                alerts,
                incidents,
                elapsed
            )

        elif choice == "2":
            show_statistics(
                events,
                alerts,
                incidents
            )

        elif choice == "3":
            show_alerts(alerts)

        elif choice == "4":
            show_incidents(incidents)

        elif choice == "5":
            show_iocs(events)

        elif choice == "6":
            search_logs(events)

        elif choice == "7":
            score, level = calculate_risk(
                events,
                alerts,
                incidents
            )
            section("RISK ASSESSMENT")
            print(f"Risk Score : {score}/100")
            print(f"Risk Level : {level}")

        elif choice == "8":
            show_performance(
                len(events),
                elapsed
            )

        elif choice == "9":
            incident_menu(incidents)

        elif choice == "10":
            manage_whitelist()

        elif choice == "11":
            generate_reports(
                path,
                events,
                alerts,
                incidents
            )

        elif choice == "12":
            section("AUDIT TRAIL")

            if not audit_events:
                print("[+] No audit events.")
            else:
                for item in audit_events:
                    print(
                        f"{item['timestamp']} | "
                        f"{item['action']} | "
                        f"{item['details']}"
                    )

        elif choice == "13":
            print(
                "\n[+] SentinelX Phase 5 "
                "terminated safely."
            )
            break

        else:
            print("[-] Invalid option.")


if __name__ == "__main__":
    main()
