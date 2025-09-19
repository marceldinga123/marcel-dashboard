from typing import Dict, Tuple
import pandas as pd

# 📌 Incident Response Playbook (per attack type)
PLAYBOOK: Dict[str, str] = {
    "BENIGN": "No action required. Continue routine monitoring.",
    "DoS": "Block offending IP(s), enable rate limiting on affected ports, and review logs.",
    "DDoS": "Engage ISP/DDoS protection, activate filtering, and isolate impacted servers.",
    "PortScan": "Monitor for repeated scans, raise IDS sensitivity, and block source if persistent.",
    "Bot": "Quarantine the host, run malware scans, and investigate command-and-control (C2) traffic.",
    "WebAttack": "Review WAF/web server logs, patch endpoints, and block malicious IP addresses.",
    "FTP-Patator": "Block source IP, enforce strong FTP authentication, and review brute-force attempts.",
    "SSH-Patator": "Block source IP, enforce SSH key authentication/fail2ban, and review authentication logs.",
}


# 🔹 Generate plain-language summaries
def _rules_summary(attack_type: str, severity: str, confidence: float,
                   src_ip: str = None, dst_ip: str = None) -> str:
    conf_txt = f"{confidence:.2f}" if confidence else "N/A"
    src_txt = f" from {src_ip}" if src_ip and str(src_ip).lower() != "nan" else ""
    dst_txt = f" targeting {dst_ip}" if dst_ip and str(dst_ip).lower() != "nan" else ""

    if attack_type == "BENIGN":
        return f"Traffic classified as BENIGN with confidence {conf_txt}. No malicious activity detected."
    elif attack_type == "DoS":
        return f"Denial of Service (DoS) detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "DDoS":
        return f"Distributed Denial of Service (DDoS) detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "PortScan":
        return f"Port scanning detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "Bot":
        return f"Bot-like behavior detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type == "WebAttack":
        return f"Web application attack detected with confidence {conf_txt}{src_txt}{dst_txt}."
    elif attack_type in ("FTP-Patator", "SSH-Patator"):
        proto = "FTP" if "FTP" in attack_type else "SSH"
        return f"{proto} brute-force activity detected with confidence {conf_txt}{src_txt}{dst_txt}."
    else:
        return f"{attack_type} detected with confidence {conf_txt}{src_txt}{dst_txt}."


# 🔹 Fetch proposed solution from playbook
def _rules_solution(attack_type: str) -> str:
    return PLAYBOOK.get(
        attack_type,
        "Investigate in SIEM, review IDS/firewall logs, and escalate per incident response playbook."
    )


# 🔹 Main function: returns (summary, proposed_action)
def generate_summary_and_solution(
    attack_type: str,
    severity: str,
    confidence: float,
    src_ip: str = None,
    dst_ip: str = None,
) -> Tuple[str, str]:
    return (
        _rules_summary(attack_type, severity, confidence, src_ip, dst_ip),
        _rules_solution(attack_type),
    )


# 🔹 Enrich a whole DataFrame with summaries + actions
def enrich_df_with_ai(df: pd.DataFrame) -> pd.DataFrame:
    summaries, actions = [], []
    for _, r in df.iterrows():
        s, a = generate_summary_and_solution(
            str(r.get("attack_type", "")),
            str(r.get("severity", "")),
            float(r.get("confidence", 0) or 0),
            r.get("src_ip"),
            r.get("dst_ip"),
        )
        summaries.append(s)
        actions.append(a)

    df = df.copy()
    df["summary"] = summaries
    df["proposed_action"] = actions
    return df
