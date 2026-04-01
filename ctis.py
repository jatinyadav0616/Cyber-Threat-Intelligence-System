"""
╔══════════════════════════════════════════════════════════════════════════╗
║         AI-POWERED CYBER THREAT INTELLIGENCE SYSTEM (CTIS)              ║
║         Developer  : Jatin Yadav                                         ║
║         University : Shri Vishwakarma Skill University, Palwal, Haryana  ║
║         Stack      : Python · Scikit-learn · Pandas · NumPy · Rich UI    ║
║         Purpose    : Threat Detection · Risk Scoring · Intel Reports     ║
╚══════════════════════════════════════════════════════════════════════════╝

  WHAT THIS SYSTEM DOES:
  ─────────────────────
  1. Ingests simulated network + system event logs
  2. AI engine classifies each event into threat categories
  3. Assigns real-time Risk Score (0–100) to every IP / entity
  4. Detects attack campaigns by correlating multiple events
  5. Generates a full Threat Intelligence Report (TIR)
  6. Simulates a live SOC (Security Operations Center) dashboard

  THREAT CATEGORIES DETECTED:
  ────────────────────────────
  • Brute Force Attack       • SQL Injection
  • DDoS / DoS               • Malware C2 Beacon
  • Port Scan / Recon        • Data Exfiltration
  • Privilege Escalation     • Zero-Day Exploit Attempt
"""

import numpy as np
import pandas as pd
import random
import time
import hashlib
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# ══════════════════════════════════════════════════════════════════
#  TERMINAL COLORS
# ══════════════════════════════════════════════════════════════════
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗████████╗██╗███████╗
 ██╔════╝╚══██╔══╝██║██╔════╝
 ██║        ██║   ██║███████╗
 ██║        ██║   ██║╚════██║
 ╚██████╗   ██║   ██║███████║
  ╚═════╝   ╚═╝   ╚═╝╚══════╝
{C.RESET}
{C.BOLD}  Cyber Threat Intelligence System  v1.0{C.RESET}
{C.DIM}  Jatin Yadav | SVSU Palwal | Python + AI{C.RESET}
{C.DIM}  ─────────────────────────────────────{C.RESET}
""")

# ══════════════════════════════════════════════════════════════════
#  SECTION 1 — SYNTHETIC LOG GENERATION
# ══════════════════════════════════════════════════════════════════

THREAT_TYPES = [
    "brute_force", "sql_injection", "ddos", "malware_c2",
    "port_scan", "data_exfil", "privilege_esc", "zero_day", "normal"
]

SERVICES = ["SSH", "HTTP", "HTTPS", "FTP", "SMTP", "RDP", "DNS", "TELNET", "MYSQL"]
COUNTRIES = ["India", "China", "Russia", "USA", "Unknown", "Germany", "Brazil", "Iran"]

def random_ip(malicious=False):
    if malicious:
        suspicious_ranges = ["185.220", "45.155", "192.42", "198.98", "23.129"]
        prefix = random.choice(suspicious_ranges)
        return f"{prefix}.{random.randint(1,255)}.{random.randint(1,255)}"
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_logs(n=3000):
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    threat_profiles = {
        "brute_force":    dict(failed_logins=(10,200), bytes_sent=(100,500),   bytes_recv=(50,200),   duration=(1,30),   port=[22,3389,21]),
        "sql_injection":  dict(failed_logins=(0,2),   bytes_sent=(500,5000),  bytes_recv=(100,2000), duration=(1,10),   port=[80,443,3306]),
        "ddos":           dict(failed_logins=(0,1),   bytes_sent=(10000,100000), bytes_recv=(0,100), duration=(0,2),    port=[80,443,53]),
        "malware_c2":     dict(failed_logins=(0,1),   bytes_sent=(200,2000),  bytes_recv=(500,5000), duration=(60,600), port=[443,8080,4444]),
        "port_scan":      dict(failed_logins=(0,1),   bytes_sent=(40,200),    bytes_recv=(0,100),    duration=(0,1),    port=list(range(20,1025))),
        "data_exfil":     dict(failed_logins=(0,1),   bytes_sent=(50000,500000), bytes_recv=(100,500), duration=(30,300), port=[443,80,21]),
        "privilege_esc":  dict(failed_logins=(1,5),   bytes_sent=(100,1000),  bytes_recv=(200,2000), duration=(5,60),   port=[22,80,445]),
        "zero_day":       dict(failed_logins=(0,3),   bytes_sent=(300,3000),  bytes_recv=(300,3000), duration=(1,20),   port=[80,443,8443]),
        "normal":         dict(failed_logins=(0,1),   bytes_sent=(100,10000), bytes_recv=(100,10000),duration=(1,300),  port=[80,443,22,53]),
    }

    weights = [0.10, 0.10, 0.10, 0.10, 0.10, 0.08, 0.07, 0.05, 0.30]

    for i in range(n):
        threat = random.choices(THREAT_TYPES, weights=weights)[0]
        p = threat_profiles[threat]
        is_malicious = threat != "normal"
        src_ip = random_ip(malicious=is_malicious)
        dst_ip = random_ip(malicious=False)
        ts = base_time + timedelta(seconds=random.randint(0, 86400))

        logs.append({
            "timestamp":      ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "src_port":       random.randint(1024, 65535),
            "dst_port":       random.choice(p["port"]),
            "service":        random.choice(SERVICES),
            "protocol":       random.choice(["TCP", "UDP", "ICMP"]),
            "bytes_sent":     random.randint(*p["bytes_sent"]),
            "bytes_recv":     random.randint(*p["bytes_recv"]),
            "duration_sec":   random.randint(*p["duration"]),
            "failed_logins":  random.randint(*p["failed_logins"]),
            "country":        random.choice(COUNTRIES),
            "is_encrypted":   random.choice([0, 1]),
            "packet_count":   random.randint(1, 500),
            "label":          threat
        })

    return pd.DataFrame(logs)

# ══════════════════════════════════════════════════════════════════
#  SECTION 2 — RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════════

RISK_WEIGHTS = {
    "zero_day":      95,
    "data_exfil":    90,
    "privilege_esc": 85,
    "malware_c2":    80,
    "ddos":          70,
    "brute_force":   65,
    "sql_injection": 60,
    "port_scan":     40,
    "normal":        5
}

THREAT_COLORS = {
    "zero_day":      C.RED + C.BOLD,
    "data_exfil":    C.RED + C.BOLD,
    "privilege_esc": C.RED,
    "malware_c2":    C.RED,
    "ddos":          C.YELLOW + C.BOLD,
    "brute_force":   C.YELLOW,
    "sql_injection": C.YELLOW,
    "port_scan":     C.CYAN,
    "normal":        C.GREEN
}

def risk_label(score):
    if score >= 80: return f"{C.RED}{C.BOLD}CRITICAL{C.RESET}"
    if score >= 60: return f"{C.RED}HIGH{C.RESET}"
    if score >= 40: return f"{C.YELLOW}MEDIUM{C.RESET}"
    if score >= 20: return f"{C.CYAN}LOW{C.RESET}"
    return f"{C.GREEN}SAFE{C.RESET}"

def compute_ip_risk(df):
    """Aggregate risk score per source IP."""
    ip_risk = defaultdict(lambda: {"score": 0, "events": 0, "threats": set(), "country": "Unknown"})
    for _, row in df.iterrows():
        threat = row["predicted_label"] if "predicted_label" in row else row["label"]
        base   = RISK_WEIGHTS.get(threat, 5)
        bonus  = min(row["failed_logins"] * 2, 20)
        exfil_bonus = 15 if row["bytes_sent"] > 50000 else 0
        score  = min(base + bonus + exfil_bonus, 100)
        ip     = row["src_ip"]
        ip_risk[ip]["score"]   = max(ip_risk[ip]["score"], score)
        ip_risk[ip]["events"] += 1
        ip_risk[ip]["threats"].add(threat)
        ip_risk[ip]["country"] = row["country"]
    return ip_risk

# ══════════════════════════════════════════════════════════════════
#  SECTION 3 — ANOMALY DETECTION (UNSUPERVISED)
# ══════════════════════════════════════════════════════════════════

def run_anomaly_detection(df):
    features = ["bytes_sent", "bytes_recv", "duration_sec", "failed_logins", "packet_count"]
    X = df[features].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    iso = IsolationForest(contamination=0.15, random_state=42, n_jobs=-1)
    preds = iso.fit_predict(X_scaled)
    df["anomaly"] = (preds == -1).astype(int)
    n_anomalies = df["anomaly"].sum()
    return df, n_anomalies

# ══════════════════════════════════════════════════════════════════
#  SECTION 4 — SUPERVISED CLASSIFIER
# ══════════════════════════════════════════════════════════════════

def train_classifier(df):
    le_svc  = LabelEncoder()
    le_proto= LabelEncoder()
    le_ctry = LabelEncoder()
    le_lbl  = LabelEncoder()

    df2 = df.copy()
    df2["service_enc"]  = le_svc.fit_transform(df2["service"])
    df2["protocol_enc"] = le_proto.fit_transform(df2["protocol"])
    df2["country_enc"]  = le_ctry.fit_transform(df2["country"])
    df2["label_enc"]    = le_lbl.fit_transform(df2["label"])

    features = ["dst_port", "bytes_sent", "bytes_recv", "duration_sec",
                "failed_logins", "is_encrypted", "packet_count",
                "service_enc", "protocol_enc", "country_enc", "anomaly"]

    X = df2[features].values
    y = df2["label_enc"].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=le_lbl.classes_, output_dict=True)

    # Predict on full dataset
    X_all = scaler.transform(X)
    df["predicted_label"] = le_lbl.inverse_transform(clf.predict(X_all))

    return df, acc, report, clf, le_lbl

# ══════════════════════════════════════════════════════════════════
#  SECTION 5 — CAMPAIGN DETECTION
# ══════════════════════════════════════════════════════════════════

def detect_campaigns(df):
    """Detect coordinated attack campaigns from multiple IPs."""
    campaigns = []
    threat_groups = df[df["predicted_label"] != "normal"].groupby("predicted_label")

    for threat, group in threat_groups:
        unique_ips = group["src_ip"].nunique()
        if unique_ips >= 3:
            campaigns.append({
                "type":       threat,
                "src_ips":    unique_ips,
                "events":     len(group),
                "avg_bytes":  int(group["bytes_sent"].mean()),
                "top_country":group["country"].mode()[0],
                "severity":   risk_label(RISK_WEIGHTS.get(threat, 50))
            })
    return sorted(campaigns, key=lambda x: RISK_WEIGHTS.get(x["type"], 0), reverse=True)

# ══════════════════════════════════════════════════════════════════
#  SECTION 6 — THREAT INTELLIGENCE REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════

def generate_tir(df, ip_risk, campaigns, acc, report):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = hashlib.md5(now.encode()).hexdigest()[:8].upper()

    tir = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              THREAT INTELLIGENCE REPORT (TIR)                              ║
║              Report ID : TIR-{report_id}                                      ║
║              Generated : {now}                           ║
║              Analyst   : AI Engine v1.0 | Jatin Yadav, SVSU               ║
╚══════════════════════════════════════════════════════════════════════════════╝

1. EXECUTIVE SUMMARY
───────────────────────────────────────────────────────────────────────────────
   Total Events Analyzed  : {len(df):,}
   Malicious Events       : {len(df[df['predicted_label'] != 'normal']):,} ({len(df[df['predicted_label'] != 'normal'])/len(df)*100:.1f}%)
   Unique Attacker IPs    : {df[df['predicted_label'] != 'normal']['src_ip'].nunique()}
   Active Campaigns       : {len(campaigns)}
   AI Model Accuracy      : {acc*100:.2f}%
   Analysis Period        : Last 24 Hours

2. THREAT BREAKDOWN
───────────────────────────────────────────────────────────────────────────────
"""
    threat_counts = df[df["predicted_label"] != "normal"]["predicted_label"].value_counts()
    for threat, count in threat_counts.items():
        pct   = count / len(df) * 100
        bar   = "█" * int(pct * 2)
        score = RISK_WEIGHTS.get(threat, 0)
        tir  += f"   {threat:<20} {count:>5} events  ({pct:4.1f}%)  Risk:{score:>3}  {bar}\n"

    tir += f"""
3. TOP 10 HIGH-RISK IP ADDRESSES
───────────────────────────────────────────────────────────────────────────────
   {'IP Address':<20} {'Risk':>5}  {'Level':<10} {'Events':>7}  {'Country':<12}  Threats
"""
    sorted_ips = sorted(ip_risk.items(), key=lambda x: x[1]["score"], reverse=True)[:10]
    for ip, data in sorted_ips:
        threats = ", ".join(list(data["threats"])[:2])
        tir += f"   {ip:<20} {data['score']:>5}  {data['score']:>3}/100   {data['events']:>6}  {data['country']:<12}  {threats}\n"

    tir += f"""
4. ATTACK CAMPAIGNS DETECTED
───────────────────────────────────────────────────────────────────────────────
"""
    if campaigns:
        for i, c in enumerate(campaigns, 1):
            tir += f"""   Campaign #{i}: {c['type'].upper().replace('_',' ')}
   ├── Participating IPs : {c['src_ips']}
   ├── Total Events      : {c['events']}
   ├── Avg Bytes Sent    : {c['avg_bytes']:,}
   ├── Origin Country    : {c['top_country']}
   └── Severity          : {c['type'].upper()} ({RISK_WEIGHTS.get(c['type'],0)}/100)\n\n"""
    else:
        tir += "   No coordinated campaigns detected.\n"

    tir += f"""
5. RECOMMENDATIONS
───────────────────────────────────────────────────────────────────────────────
   [CRITICAL] Block top 10 high-risk IPs at firewall immediately.
   [HIGH]     Enable MFA on all SSH, RDP, and admin portals.
   [HIGH]     Deploy WAF rules to counter SQL injection attempts.
   [MEDIUM]   Increase log retention to 90 days for forensic analysis.
   [MEDIUM]   Enable geo-blocking for high-risk origin countries.
   [LOW]      Schedule penetration testing within next 30 days.

6. AI MODEL PERFORMANCE
───────────────────────────────────────────────────────────────────────────────
   Algorithm    : Random Forest (150 estimators)
   Accuracy     : {acc*100:.2f}%
   Features     : 11 (network + behavioral)
   Anomaly Det. : Isolation Forest (unsupervised layer)

───────────────────────────────────────────────────────────────────────────────
   END OF REPORT | TIR-{report_id} | CONFIDENTIAL — FOR AUTHORIZED USE ONLY
───────────────────────────────────────────────────────────────────────────────
"""
    return tir

# ══════════════════════════════════════════════════════════════════
#  SECTION 7 — LIVE SOC DASHBOARD
# ══════════════════════════════════════════════════════════════════

def live_soc_dashboard(df, ip_risk, duration=20):
    threats_seen = list(df[df["predicted_label"] != "normal"]["src_ip"].unique())
    normal_ips   = list(df[df["predicted_label"] == "normal"]["src_ip"].unique())

    print(f"\n{C.BOLD}{C.CYAN}{'═'*75}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}   🖥️  LIVE SOC DASHBOARD — REAL-TIME THREAT MONITOR{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*75}{C.RESET}")
    print(f"  {'TIME':<10} {'SRC IP':<20} {'DST PORT':<10} {'THREAT':<22} {'RISK':<6} {'STATUS'}")
    print(f"  {'─'*70}")

    alert_count = 0
    for i in range(duration):
        ts = datetime.now().strftime("%H:%M:%S")

        # 60% chance of picking a threat IP
        if random.random() < 0.60 and threats_seen:
            src_ip = random.choice(threats_seen)
            # find this IP's most common threat
            ip_rows = df[df["src_ip"] == src_ip]
            threat = ip_rows["predicted_label"].mode()[0] if len(ip_rows) > 0 else "port_scan"
        else:
            src_ip = random_ip(malicious=False)
            threat = "normal"

        score = ip_risk.get(src_ip, {}).get("score", RISK_WEIGHTS.get(threat, 5))
        dst_port = random.choice([22, 80, 443, 3306, 3389, 8080, 21, 53])
        color = THREAT_COLORS.get(threat, C.GREEN)
        rlabel = risk_label(score)

        if threat != "normal":
            alert_count += 1
            icon = "🚨" if score >= 70 else "⚠️ "
        else:
            icon = "✅"

        threat_display = threat.replace("_", " ").upper()
        print(f"  {ts:<10} {src_ip:<20} {dst_port:<10} {color}{threat_display:<22}{C.RESET} {score:<6} {icon} {rlabel}")
        time.sleep(0.4)

    print(f"\n  {C.BOLD}Session: {duration} events | Alerts fired: {alert_count} | Safe: {duration - alert_count}{C.RESET}\n")

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    banner()
    time.sleep(0.5)

    # Step 1: Generate logs
    print(f"{C.BOLD}[1/6] Ingesting network event logs...{C.RESET}")
    df = generate_logs(3000)
    print(f"      {C.GREEN}✓ {len(df):,} log entries loaded{C.RESET}\n")
    time.sleep(0.3)

    # Step 2: Anomaly detection
    print(f"{C.BOLD}[2/6] Running unsupervised anomaly detection (Isolation Forest)...{C.RESET}")
    df, n_anomalies = run_anomaly_detection(df)
    print(f"      {C.YELLOW}✓ {n_anomalies} anomalies flagged ({n_anomalies/len(df)*100:.1f}%){C.RESET}\n")
    time.sleep(0.3)

    # Step 3: Train classifier
    print(f"{C.BOLD}[3/6] Training AI threat classifier (Random Forest)...{C.RESET}")
    df, acc, report, clf, le_lbl = train_classifier(df)
    print(f"      {C.GREEN}✓ Model accuracy: {acc*100:.2f}%{C.RESET}\n")
    time.sleep(0.3)

    # Step 4: Risk scoring
    print(f"{C.BOLD}[4/6] Computing IP risk scores...{C.RESET}")
    ip_risk = compute_ip_risk(df)
    critical = sum(1 for v in ip_risk.values() if v["score"] >= 80)
    print(f"      {C.RED}✓ {critical} critical IPs identified out of {len(ip_risk)}{C.RESET}\n")
    time.sleep(0.3)

    # Step 5: Campaign detection
    print(f"{C.BOLD}[5/6] Detecting coordinated attack campaigns...{C.RESET}")
    campaigns = detect_campaigns(df)
    print(f"      {C.YELLOW}✓ {len(campaigns)} active campaigns detected{C.RESET}\n")
    time.sleep(0.3)

    # Step 6: Generate TIR
    print(f"{C.BOLD}[6/6] Generating Threat Intelligence Report...{C.RESET}")
    tir = generate_tir(df, ip_risk, campaigns, acc, report)
    time.sleep(0.5)
    print(f"      {C.GREEN}✓ Report ready{C.RESET}\n")

    # Print TIR
    print(tir)

    # Save report
    report_path = "threat_report.txt"
    with open(report_path, "w") as f:
        f.write(tir)
    print(f"{C.GREEN}  [+] Report saved to: {report_path}{C.RESET}\n")

    # Live SOC dashboard
    input(f"  {C.CYAN}Press ENTER to launch Live SOC Dashboard...{C.RESET}")
    live_soc_dashboard(df, ip_risk, duration=25)

    print(f"{C.BOLD}{C.GREEN}  ✅ CTIS session complete. Stay secure.{C.RESET}\n")

if __name__ == "__main__":
    main()
