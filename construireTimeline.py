def calculate_confidence(ev: dict) -> float:
    """
    Calculează confidence score per eveniment bazat pe numărul
    de surse care confirmă evenimentul.

    Metodologie DFRWS TER-Model Q3:
    - Fiecare sursă de confirmare adaugă la încredere
    - Shortcut Rule Engine = certitudine maximă
    - Combinația IF + RF + LSTM = încredere ridicată
    """
    score = 0.0

    # Rule Engine shortcut → certitudine maximă (expert rules)
    if ev.get("rule_shortcut"):
        return 1.0

    # Rule Engine triggered → confirmare parțială
    if ev.get("rule_triggered"):
        score += 0.30

    # Random Forest confirmă → model supervised antrenat
    rf = ev.get("rf_score") or 0.0
    if rf > 0.8:
        score += 0.25
    elif rf > 0.6:
        score += 0.15

    # LSTM confirmă → pattern temporal
    lstm = ev.get("lstm_score") or 0.0
    if lstm > 0.8:
        score += 0.20
    elif lstm > 0.6:
        score += 0.10

    # Isolation Forest confirmă → anomalie statistică
    stat = ev.get("stat_score") or 0.0
    if stat > 0.8:
        score += 0.15
    elif stat > 0.6:
        score += 0.08

    # Context entitate ridicat → confirmare contextuală
    ctx = ev.get("entity_context", {})
    if ctx.get("lsass", 0) >= 1:
        score += 0.10
    if ctx.get("failed_auth", 0) >= 5:
        score += 0.05

    return min(round(score, 2), 1.0)


def get_confidence_label(confidence: float) -> str:
    """Etichetă textuală pentru confidence score."""
    if confidence >= 0.9:
        return "CERT"  # Cert — shortcut sau confirmare multiplă
    elif confidence >= 0.7:
        return "HIGH"  # Înaltă — confirmare din cel puțin 2 surse
    elif confidence >= 0.5:
        return "MEDIUM"  # Medie — o singură sursă puternică
    elif confidence >= 0.3:
        return "LOW"  # Scăzută — deviere statistică slabă
    else:
        return "UNCERTAIN"  # Incert — bazat doar pe rarity/burst


def build_timeline(events: list) -> list:
    """
    Construiește cronologia evenimentelor cu adnotări cauzale
    și confidence score per eveniment.

    Bazat pe DFRWS TER-Model Q2 + Q3:
    - Q2: sortare cronologică + normalizare timestamp
    - Q3: detectare tranziții + analiză cauză-efect + confidence
    """
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
    timeline = []

    prev_risk = "LOW"
    prev_score = 0.0

    for i, ev in enumerate(sorted_events):
        risk = ev.get("risk_level", "LOW")
        score = ev.get("final_risk", 0.0)
        rules = ev.get("rules_fired", [])
        ctx = ev.get("entity_context", {})

        # ── Confidence score (DFRWS Q3 — uncertainty handling) ───
        confidence = calculate_confidence(ev)
        confidence_label = get_confidence_label(confidence)

        # ── Detectează tranziții și escaladări ────────────────────
        transition = None
        if prev_risk == "LOW" and risk == "MEDIUM":
            transition = "escalation_low_medium"
        elif prev_risk == "LOW" and risk == "HIGH":
            transition = "escalation_low_high"
        elif prev_risk == "MEDIUM" and risk == "HIGH":
            transition = "escalation_medium_high"
        elif score > prev_score + 0.3:
            transition = "score_jump"

        # ── Adnotare cauză (DFRWS Q4 — cauză-efect) ──────────────
        cause_note = None
        if any("lsass" in r.lower() for r in rules):
            cause_note = "Credential dump (Mimikatz/LSASS)"
        elif any("lateral" in r.lower() for r in rules):
            cause_note = "Lateral movement (PsExec/SMB)"
        elif any("brute" in r.lower() or
                 "auth_failure" in r.lower() for r in rules):
            cause_note = f"Brute force ({ctx.get('failed_auth', 0)}x eșecuri)"
        elif any("sudo" in r.lower() for r in rules):
            cause_note = f"Privilege escalation ({ctx.get('sudo_count', 0)}x sudo)"
        elif any("exfiltr" in r.lower() or
                 "dlp" in r.lower() for r in rules):
            cause_note = "Exfiltrare date"
        elif any("lolbin" in r.lower() for r in rules):
            cause_note = "LOLBin execution (Living off the Land)"
        elif any("reverse_shell" in r.lower() for r in rules):
            cause_note = "Reverse shell / C2 beacon"
        elif any("download_exec" in r.lower() for r in rules):
            cause_note = "Dropper / Download & Execute"
        elif any("av_alert" in r.lower() for r in rules):
            cause_note = "Malware detectat de AV"
        elif any("ids_alert" in r.lower() for r in rules):
            cause_note = "Intruziune detectată de IDS"
        elif any("dlp_alert" in r.lower() for r in rules):
            cause_note = "DLP alert — exfiltrare blocată"
        elif any("edr_alert" in r.lower() for r in rules):
            cause_note = "EDR alert — activitate malițioasă"
        elif any("siem" in r.lower() for r in rules):
            cause_note = "SIEM corelație — pattern multi-sursă"

        timeline.append({
            # ── Identificare eveniment ────────────────────────────
            "step": i + 1,
            "event_id": ev.get("event_id", ""),
            "timestamp": ev.get("timestamp", 0),
            "timestamp_iso": ev.get("timestamp_iso", ""),

            # ── Clasificare ───────────────────────────────────────
            "risk_level": risk,
            "final_risk": round(score, 4),
            "log_category": ev.get("log_category", ""),
            "raw_log": ev.get("raw_log", "")[:200],

            # ── Rule Engine ───────────────────────────────────────
            "rules_fired": rules,
            "rule_shortcut": ev.get("rule_shortcut", False),
            "rule_triggered": ev.get("rule_triggered", False),

            # ── Context entitate ──────────────────────────────────
            "entity_context": ctx,

            # ── Analiză cauzală (DFRWS Q3/Q4) ────────────────────
            "transition": transition,
            "cause_note": cause_note,
            "score_delta": round(score - prev_score, 4),

            # ── Scoruri ML ────────────────────────────────────────
            "stat_score": ev.get("stat_score"),
            "behavior_score": ev.get("behavior_score"),
            "cat_score": ev.get("cat_score"),
            "rf_score": ev.get("rf_score"),
            "lstm_score": ev.get("lstm_score"),


            "confidence": confidence,
            "confidence_label": confidence_label,
        })

        prev_risk = risk
        prev_score = score

    return timeline