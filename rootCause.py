def find_root_cause(events: list) -> dict:
    """
    Identifică root cause prin traversare DFS.

    Metodologie DFRWS TER-Model Q4:
    - Sortare cronologică (Q2)
    - Traversare DFS pentru primul eveniment anormal (Q4)
    - Pivot point = primul eveniment cu certitudine ridicată
    - Confidence propagat din calculate_confidence()

    Referință: Carrier & Spafford (2004) — event-based
    digital forensic investigation framework
    """
    if not events:
        return {
            "event":       None,
            "timestamp":   "",
            "explanation": "Niciun eveniment disponibil",
            "rules":       [],
            "confidence":  0.0,
        }

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))

    # ── DFS traversal — caută pivot point ────────────────────────
    # Prioritate: shortcut > lsass > lateral > download > brute > ML
    pivot = None

    for ev in sorted_events:
        rules = ev.get("rules_fired", [])

        # Nivel 1 — Shortcut Rule Engine (certitudine maximă)
        if ev.get("rule_shortcut"):
            if any("lsass"          in r.lower() for r in rules):
                pivot = ev
                break
            if any("lateral"        in r.lower() for r in rules):
                pivot = ev
                break
            if any("download_exec"  in r.lower() for r in rules):
                pivot = ev
                break
            if any("reverse_shell"  in r.lower() for r in rules):
                pivot = ev
                break
            if any("lolbin"         in r.lower() for r in rules):
                pivot = ev
                break
            if not pivot:
                pivot = ev

        # Nivel 2 — Rule Engine triggered (fără shortcut)
        elif ev.get("rule_triggered") and not pivot:
            if any("lsass"          in r.lower() for r in rules):
                pivot = ev
            elif any("lateral"      in r.lower() for r in rules):
                pivot = ev
            elif any("brute"        in r.lower() or
                     "auth_failure" in r.lower() for r in rules):
                pivot = ev

        # Nivel 3 — ML pur cu score ridicat
        elif not pivot and ev.get("final_risk", 0) >= 0.8:
            pivot = ev

    # Fallback — primul eveniment MEDIUM sau HIGH
    if not pivot:
        for ev in sorted_events:
            if ev.get("risk_level") in ("MEDIUM", "HIGH"):
                pivot = ev
                break

    if not pivot:
        pivot = sorted_events[0]

    # ── Confidence pentru root cause ─────────────────────────────
    try:
        from construireTimeline import calculate_confidence
        root_confidence = calculate_confidence(pivot)
    except Exception:
        root_confidence = 0.5

    # ── Construiește explicație ───────────────────────────────────
    rules   = pivot.get("rules_fired", [])
    ctx     = pivot.get("entity_context", {})
    ts      = pivot.get("timestamp_iso", "")
    rf      = pivot.get("rf_score") or 0.0
    lstm    = pivot.get("lstm_score") or 0.0

    if pivot.get("rule_shortcut") and any(
            "lsass" in r.lower() for r in rules):
        explanation = (
            f"Extragere credențiale LSASS la {ts} — "
            f"atacatorul a accesat direct memoria procesului lsass.exe "
            f"pentru a extrage hash-uri de parole (Mimikatz/similar). "
            f"Confirmat de Rule Engine cu certitudine maximă."
        )
    elif pivot.get("rule_shortcut") and any(
            "lateral" in r.lower() for r in rules):
        explanation = (
            f"Lateral movement la {ts} — "
            f"atacatorul s-a deplasat pe alt sistem după "
            f"compromiterea inițială folosind credențiale furate."
        )
    elif pivot.get("rule_shortcut") and any(
            "download_exec" in r.lower() for r in rules):
        explanation = (
            f"Download și execuție payload malițios la {ts} — "
            f"un script sau executabil a fost descărcat de pe rețea "
            f"și rulat direct pe sistem (Dropper pattern)."
        )
    elif pivot.get("rule_shortcut") and any(
            "reverse_shell" in r.lower() for r in rules):
        explanation = (
            f"Reverse shell detectat la {ts} — "
            f"atacatorul a stabilit un canal de comandă și control (C2) "
            f"prin care controlează sistemul de la distanță."
        )
    elif pivot.get("rule_shortcut") and any(
            "lolbin" in r.lower() for r in rules):
        explanation = (
            f"LOLBin execution la {ts} — "
            f"un tool legitim de sistem a fost folosit malițios "
            f"pentru a executa cod sau a evita detecția (Living off the Land)."
        )
    elif any("brute" in r.lower() or
             "auth_failure" in r.lower() for r in rules):
        failed = ctx.get("failed_auth", 0)
        explanation = (
            f"Brute force SSH/RDP la {ts} — "
            f"{failed} autentificări eșuate au marcat începutul atacului. "
            f"Acesta reprezintă vectorul inițial de acces (Initial Access)."
        )
    elif ev.get("risk_level") in ("MEDIUM", "HIGH") and rf > 0.7:
        explanation = (
            f"Comportament anomal detectat de ML la {ts} — "
            f"Random Forest ({int(rf*100)}%) și LSTM ({int(lstm*100)}%) "
            f"au identificat un pattern similar cu atacuri cunoscute "
            f"din datele de antrenare, fără o regulă explicită."
        )
    else:
        explanation = (
            f"Primul eveniment anormal la {ts} — "
            f"deviere semnificativă detectată față de baseline-ul "
            f"entității (final_risk={pivot.get('final_risk', 0):.3f}). "
            f"Posibil vector inițial de acces neidentificat explicit."
        )

    return {
        "event":       pivot,
        "timestamp":   ts,
        "explanation": explanation,
        "rules":       rules,
        "confidence":  root_confidence,
        # DFRWS Q3 — nivel de incertitudine al root cause
        "uncertainty": round(1.0 - root_confidence, 2),
    }