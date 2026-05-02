def find_root_cause(events: list) -> dict:
    if not events:
        return {"event": None, "explanation": "Niciun eveniment"}

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))


    pivot = None
    for ev in sorted_events:
        rules = ev.get("rules_fired", [])
        ctx   = ev.get("entity_context", {})

        # Criterii pivot (ordinea contează — DFS prioritizează)
        if any("lsass" in r.lower() for r in rules):
            pivot = ev
            break
        if any("lateral" in r.lower() for r in rules):
            pivot = ev
            break
        if any("download_exec" in r.lower() or
               "reverse_shell" in r.lower() for r in rules):
            pivot = ev
            break
        if any("brute" in r.lower() or
               "auth_failures" in r.lower() for r in rules):
            pivot = ev
            break
        if ev.get("risk_level") in ("MEDIUM", "HIGH") and not pivot:
            pivot = ev

    if not pivot:
        pivot = sorted_events[0]

    # ── Construiește explicație ───────────────────────────────────
    rules    = pivot.get("rules_fired", [])
    ctx      = pivot.get("entity_context", {})
    raw_log  = pivot.get("raw_log", "")
    ts       = pivot.get("timestamp_iso", "")

    if any("lsass" in r.lower() for r in rules):
        explanation = (
            f"Extragere credențiale LSASS la {ts} — "
            f"atacatorul a accesat memoria procesului lsass.exe "
            f"pentru a extrage hash-uri de parole"
        )
    elif any("lateral" in r.lower() for r in rules):
        explanation = (
            f"Lateral movement la {ts} — "
            f"atacatorul s-a deplasat pe alt sistem după compromiterea inițială"
        )
    elif any("brute" in r.lower() or
             "auth_failures" in r.lower() for r in rules):
        explanation = (
            f"Brute force la {ts} — "
            f"{ctx.get('failed_auth', 0)} autentificări eșuate "
            f"au marcat începutul atacului"
        )
    elif any("download_exec" in r.lower() for r in rules):
        explanation = (
            f"Download și execuție cod malițios la {ts} — "
            f"payload descărcat și rulat pe sistem"
        )
    else:
        explanation = (
            f"Primul eveniment anormal la {ts} — "
            f"deviere detectată față de baseline-ul entității"
        )

    return {
        "event":       pivot,
        "timestamp":   ts,
        "explanation": explanation,
        "rules":       rules,
    }