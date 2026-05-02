def classify_attack_type(events: list) -> dict:
    rules_all   = []
    risk_levels = []

    for ev in events:
        rules_all.extend(ev.get("rules_fired", []))
        risk_levels.append(ev.get("risk_level", "LOW"))

    rules_str = " ".join(rules_all).lower()

    attack_types  = []
    mitre_tactics = []

    # ── Detectare atacuri cunoscute ───────────────────────────────

    has_lsass   = any("lsass"        in r.lower() for r in rules_all)
    has_brute   = any("auth_failure" in r.lower() or
                      "brute"        in r.lower() for r in rules_all)
    has_lateral = any("lateral"      in r.lower() for r in rules_all)
    has_sudo    = any("sudo"         in r.lower() or
                      "escalad"      in r.lower() for r in rules_all)
    has_exfil   = any("exfiltr"      in r.lower() or
                      "dlp"          in r.lower() or
                      "upload"       in r.lower() for r in rules_all)
    has_exec    = any("lolbin"       in r.lower() or
                      "download_exec" in r.lower() or
                      "reverse_shell" in r.lower() for r in rules_all)
    has_recon   = any("recon"        in r.lower() or
                      "debug"        in r.lower() for r in rules_all)
    has_ids     = any("ids_alert"    in r.lower() for r in rules_all)
    has_av      = any("av_alert"     in r.lower() for r in rules_all)
    has_siem    = any("siem"         in r.lower() for r in rules_all)
    has_dlp     = any("dlp"          in r.lower() for r in rules_all)
    has_edr     = any("edr"          in r.lower() for r in rules_all)
    has_dns     = any("dns"          in r.lower() for r in rules_all)

    # ── Atacuri cunoscute specifice ───────────────────────────────

    # Pass-the-Hash — LSASS + Lateral Movement
    if has_lsass and has_lateral:
        attack_types.append("Pass-the-Hash")
        mitre_tactics.append("T1550.002 — Pass the Hash")

    # Mimikatz / Credential Dumping
    if has_lsass:
        attack_types.append("Mimikatz / Credential Dumping")
        mitre_tactics.append("T1003.001 — LSASS Memory")

    # Password Spraying / Brute Force
    if has_brute and not has_lsass:
        attack_types.append("Password Spraying / Brute Force")
        mitre_tactics.append("T1110.003 — Password Spraying")
    elif has_brute:
        attack_types.append("Brute Force")
        mitre_tactics.append("T1110.001 — Password Guessing")

    # PsExec / Lateral Movement
    if has_lateral:
        attack_types.append("PsExec / Lateral Movement")
        mitre_tactics.append("T1021.002 — SMB/Windows Admin Shares")

    # Sudo Privilege Escalation
    if has_sudo and not has_lsass:
        attack_types.append("Sudo Privilege Escalation")
        mitre_tactics.append("T1548.003 — Sudo and Sudo Caching")

    # Living off the Land (LOLBins)
    if has_exec and "lolbin" in rules_str:
        attack_types.append("Living off the Land (LOLBins)")
        mitre_tactics.append("T1218 — System Binary Proxy Execution")

    # Reverse Shell / C2
    if has_exec and "reverse_shell" in rules_str:
        attack_types.append("Reverse Shell / C2 Beacon")
        mitre_tactics.append("T1059.004 — Unix Shell")

    # Dropper / Downloader
    if has_exec and "download_exec" in rules_str:
        attack_types.append("Dropper / Downloader")
        mitre_tactics.append("T1105 — Ingress Tool Transfer")

    # Data Exfiltration
    if has_exfil and has_lateral:
        attack_types.append("Data Exfiltration post-compromise")
        mitre_tactics.append("T1041 — Exfiltration Over C2 Channel")
    elif has_exfil:
        attack_types.append("Data Exfiltration")
        mitre_tactics.append("T1048 — Exfiltration Over Alternative Protocol")

    # Ransomware indicator
    if has_av and has_exfil:
        attack_types.append("Ransomware / Malware cu Exfiltrare")
        mitre_tactics.append("T1486 — Data Encrypted for Impact")
    elif has_av:
        attack_types.append("Malware / Virus")
        mitre_tactics.append("T1204 — User Execution")

    # Network Intrusion (IDS)
    if has_ids:
        attack_types.append("Network Intrusion (IDS Alert)")
        mitre_tactics.append("T1190 — Exploit Public-Facing Application")

    # DLP — Data Loss Prevention trigger
    if has_dlp and not has_exfil:
        attack_types.append("Data Loss Prevention Alert")
        mitre_tactics.append("T1567 — Exfiltration Over Web Service")

    # DNS C2 / Tunneling
    if has_dns:
        attack_types.append("DNS C2 / Tunneling")
        mitre_tactics.append("T1071.004 — DNS")

    # Reconnaissance
    if has_recon:
        attack_types.append("Reconnaissance / Discovery")
        mitre_tactics.append("T1082 — System Information Discovery")

    # ── Severitate globală ────────────────────────────────────────
    if "HIGH" in risk_levels:
        severity = "CRITICAL" if len(attack_types) >= 3 else "HIGH"
    else:
        severity = "MEDIUM"

    # ── Pattern APT compus ────────────────────────────────────────
    apt_pattern = None

    if has_brute and has_lsass and has_lateral and has_exfil:
        apt_pattern = "APT Full Chain: Brute Force → Mimikatz → PsExec → Exfiltrare"
    elif has_brute and has_lsass and has_lateral:
        apt_pattern = "Credential-based Lateral Movement: Brute Force → Mimikatz → PsExec"
    elif has_lsass and has_lateral and has_exfil:
        apt_pattern = "Pass-the-Hash → Lateral Movement → Data Exfiltration"
    elif has_brute and has_sudo and has_exfil:
        apt_pattern = "Linux Privilege Escalation: Brute Force → Sudo Escalation → Exfiltrare"
    elif has_exec and has_lateral and has_exfil:
        apt_pattern = "Dropper → Lateral Movement → Exfiltrare"
    elif has_lsass and has_lateral:
        apt_pattern = "Pass-the-Hash Attack"
    elif has_brute and has_lsass:
        apt_pattern = "Brute Force → Credential Dumping (Mimikatz)"
    elif has_brute and has_sudo:
        apt_pattern = "Brute Force → Sudo Privilege Escalation"
    elif has_lateral and has_exfil:
        apt_pattern = "Lateral Movement → Data Exfiltration"
    elif has_exec and has_exfil:
        apt_pattern = "Dropper / LOLBin → Data Exfiltration"
    elif has_brute:
        apt_pattern = "Password Attack (Brute Force / Spraying)"
    elif has_lsass:
        apt_pattern = "Credential Dumping izolat (Mimikatz)"

    return {
        "attack_types":  attack_types if attack_types else ["Behavioral Anomaly"],
        "mitre_tactics": list(set(mitre_tactics)),
        "apt_pattern":   apt_pattern,
        "severity":      severity,
        "multi_stage":   len(attack_types) >= 2,
    }