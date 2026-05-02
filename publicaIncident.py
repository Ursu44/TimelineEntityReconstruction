import os
import time
from clasificareTipAtac import classify_attack_type
from construireTimeline import build_timeline
from rootCause import find_root_cause
import uuid
from datetime import datetime
from kafka import KafkaProducer
import json

MIN_EVENTS = 2
last_incident: dict = {}
last_peak:     dict = {}

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
OUTPUT_TOPIC    = "correlated_incidents"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8")
)

# ── Entități invalide — ignorate ──────────────────────────────────
INVALID_ENTITIES = {
    "generic_entity", "source:edr", "source:av",
    "source:ids", "source:dlp", "source:siem"
}


def is_valid_entity(entity_id: str) -> bool:
    """Verifică dacă entity_id e o entitate reală."""
    if not entity_id:
        return False
    # Entități invalide cunoscute
    if entity_id in INVALID_ENTITIES:
        return False
    # Hostname-uri — nu sunt entități reale
    if entity_id.startswith("host:"):
        return False
    # Path-uri de fișiere
    if entity_id.startswith("/") or entity_id.startswith("C:\\"):
        return False
    # IP-uri izolate fără context
    parts = entity_id.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return False
    return True


def publish_incident(entity_id: str, events: list) -> None:

    # ── Filtrează entități invalide ───────────────────────────────
    if not is_valid_entity(entity_id):
        return

    if len(events) < MIN_EVENTS:
        return

    peak_score = max(ev.get("final_risk", 0) for ev in events)

    # ── Publică dacă:
    #    1. Nu a mai fost publicat în ultimul minut SAU
    #    2. Peak score a crescut semnificativ (> 0.20)
    now = time.time()
    if entity_id in last_incident:
        time_ok  = now - last_incident[entity_id] >= 60
        score_ok = peak_score > last_peak.get(entity_id, 0) + 0.20
        if not time_ok and not score_ok:
            return

    attack_info = classify_attack_type(events)
    root_cause  = find_root_cause(events)
    timeline    = build_timeline(events)

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
    start_ts      = sorted_events[0].get("timestamp_iso", "")
    end_ts        = sorted_events[-1].get("timestamp_iso", "")
    high_count    = sum(1 for ev in events if ev.get("risk_level") == "HIGH")
    medium_count  = sum(1 for ev in events if ev.get("risk_level") == "MEDIUM")

    incident = {
        "incident_id":      str(uuid.uuid4()),
        "entity_id":        entity_id,
        "created_at":       datetime.utcnow().isoformat(),
        "start_time":       start_ts,
        "end_time":         end_ts,
        "duration_sec":     round(
            sorted_events[-1].get("timestamp", 0) -
            sorted_events[0].get("timestamp", 0), 1
        ),

        # Clasificare atac
        "attack_types":     attack_info["attack_types"],
        "mitre_tactics":    attack_info["mitre_tactics"],
        "apt_pattern":      attack_info["apt_pattern"],
        "severity":         attack_info["severity"],
        "multi_stage":      attack_info["multi_stage"],

        # Root cause
        "root_cause":       root_cause["explanation"],
        "root_cause_ts":    root_cause["timestamp"],
        "root_cause_rules": root_cause["rules"],

        # Statistici
        "total_events":     len(events),
        "high_events":      high_count,
        "medium_events":    medium_count,
        "peak_score":       round(peak_score, 4),

        # Timeline complet
        "timeline":         timeline,

        # Toate event_id-urile implicate
        "event_ids":        [ev.get("event_id") for ev in events],
    }

    print(f"""
{'='*60}
🔗 INCIDENT CORELAT — {attack_info['severity']}
{'='*60}
Entitate:    {entity_id}
Tip atac:    {', '.join(attack_info['attack_types'])}
Pattern APT: {attack_info['apt_pattern'] or 'N/A'}
MITRE:       {', '.join(attack_info['mitre_tactics'])}
Durată:      {incident['duration_sec']}s
Evenimente:  {len(events)} (HIGH={high_count}, MEDIUM={medium_count})
Peak Score:  {peak_score:.3f}
Root Cause:  {root_cause['explanation'][:80]}
{'='*60}
""")

    producer.send(OUTPUT_TOPIC, value=incident)
    last_incident[entity_id] = now
    last_peak[entity_id]     = peak_score