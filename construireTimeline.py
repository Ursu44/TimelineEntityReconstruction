# ── Construire timeline ────────────────────────────────────────────
def build_timeline(events: list) -> list:
    """
    Construiește cronologia evenimentelor cu adnotări cauzale.
    Bazat pe DFRWS timestamp correlation methodology.
    """
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
    timeline      = []

    prev_risk  = "LOW"
    prev_score = 0.0

    for i, ev in enumerate(sorted_events):
        risk  = ev.get("risk_level", "LOW")
        score = ev.get("final_risk", 0.0)
        rules = ev.get("rules_fired", [])
        ctx   = ev.get("entity_context", {})

        # ── Detectează tranziții și escaladări ────────────────────
        transition = None
        if prev_risk == "LOW"    and risk == "MEDIUM":
            transition = "escalation_low_medium"
        elif prev_risk == "LOW"  and risk == "HIGH":
            transition = "escalation_low_high"
        elif prev_risk == "MEDIUM" and risk == "HIGH":
            transition = "escalation_medium_high"
        elif score > prev_score + 0.3:
            transition = "score_jump"

        # ── Adnotare cauză ────────────────────────────────────────
        cause_note = None
        if any("lsass"         in r.lower() for r in rules):
            cause_note = "Credential dump"
        elif any("lateral"     in r.lower() for r in rules):
            cause_note = "Lateral movement"
        elif any("brute"       in r.lower() or
                 "auth_failure" in r.lower() for r in rules):
            cause_note = f"Brute force ({ctx.get('failed_auth', 0)}x)"
        elif any("sudo"        in r.lower() for r in rules):
            cause_note = f"Privilege escalation ({ctx.get('sudo_count', 0)}x sudo)"
        elif any("exfiltr"     in r.lower() or
                 "dlp"         in r.lower() for r in rules):
            cause_note = "Exfiltrare date"
        elif any("lolbin"      in r.lower() for r in rules):
            cause_note = "LOLBin execution"
        elif any("reverse_shell" in r.lower() for r in rules):
            cause_note = "Reverse shell"

        timeline.append({
            "step":           i + 1,
            "timestamp":      ev.get("timestamp", 0),
            "timestamp_iso":  ev.get("timestamp_iso", ""),
            "event_id":       ev.get("event_id", ""),
            "risk_level":     risk,
            "final_risk":     round(score, 4),
            "log_category":   ev.get("log_category", ""),
            "raw_log":        ev.get("raw_log", "")[:200],
            "rules_fired":    rules,
            "rule_shortcut":  ev.get("rule_shortcut", False),
            "entity_context": ctx,
            "transition":     transition,
            "cause_note":     cause_note,
            "score_delta":    round(score - prev_score, 4),
            "stat_score":     ev.get("stat_score"),
            "behavior_score": ev.get("behavior_score"),
            "rf_score":       ev.get("rf_score"),
            "lstm_score":     ev.get("lstm_score"),
        })

        prev_risk  = risk
        prev_score = score

    return timeline
