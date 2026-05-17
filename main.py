import os
import json
import time
from collections import defaultdict, deque
from kafka import KafkaConsumer, KafkaProducer

from publicaIncident import publish_incident

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC     = "ml_alerts"
OUTPUT_TOPIC    = "correlated_incidents"
WINDOW_SECONDS  = 600
MIN_EVENTS      = 2
RISK_LEVELS     = {"HIGH", "MEDIUM"}

consumer = KafkaConsumer(
    INPUT_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP,
    auto_offset_reset="earliest",
    group_id="timeline-reconstruction",
    value_deserializer=lambda v: json.loads(v.decode("utf-8", errors="ignore"))
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8")
)


entity_windows: dict = defaultdict(lambda: deque())
last_incident:  dict = {}

# ── Main loop ──────────────────────────────────────────────────────
print("🔗 Timeline Reconstruction Service pornit...")
print(f"   Fereastră corelare: {WINDOW_SECONDS}s")
print(f"   Nivel minim alerte: {MIN_EVENTS}")
print(f"   Risk levels: {RISK_LEVELS}")

for msg in consumer:
    alert = msg.value

    # Filtrează doar HIGH și MEDIUM
    if alert.get("risk_level") not in RISK_LEVELS:
        continue

    entity_id = alert.get("entity_id", "generic_entity")
    ts        = alert.get("timestamp", time.time())

    # Adaugă în fereastra entității
    entity_windows[entity_id].append(alert)

    # Elimină evenimente vechi (> 10 minute)
    cutoff = ts - WINDOW_SECONDS
    while (entity_windows[entity_id] and
           entity_windows[entity_id][0].get("timestamp", 0) < cutoff):
        entity_windows[entity_id].popleft()

    # Dacă avem suficiente evenimente — publică incident
    events = list(entity_windows[entity_id])
    if len(events) >= MIN_EVENTS:
        publish_incident(entity_id, events)