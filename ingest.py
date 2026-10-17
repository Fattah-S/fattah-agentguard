#!/usr/bin/env python3
"""
Fattah AgentGuard — stream ingestion (the bridge between field logs and the rule brain).

Reads the NDJSON datasets and replays them as a LIVE STREAM: one event at a time,
in timestamp order, into the StreamingEngine. Atomic alerts fire the instant a
matching event arrives; chain alerts fire the moment a session completes its
sequence. This is the equivalent of a SIEM log forwarder feeding the analytics layer.

Usage:
    python3 ingest.py                 # stream all datasets, no delay
    python3 ingest.py --delay 0.05    # 50ms between events (nice for the demo)
    python3 ingest.py --out alerts.json
"""

import argparse
import glob
import json
import os
from datetime import datetime
from time import sleep

from engine import StreamingEngine
from triage import classify
from mini_soar import MiniSOAR

HERE = os.path.dirname(os.path.abspath(__file__))

VERDICT_TAG = {"true_positive": "TP", "benign_positive": "BP", "false_positive": "FP"}
SEV_MARK = {"Critical": "[CRIT]", "High": "[HIGH]", "Medium": "[MED ]", "Low": "[LOW ]"}


def load_stream(data_dir):
    """Read every NDJSON line, then order by timestamp to mimic a real feed."""
    events = []
    for f in sorted(glob.glob(os.path.join(data_dir, "**", "*.ndjson"), recursive=True)):
        for line in open(f):
            line = line.strip()
            if line:
                events.append(json.loads(line))
    events.sort(key=lambda e: datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
    return events


def write_json_atomic(path, data):
    """Write to a temp file then rename, so readers (the dashboard) never see a partial file."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def short(event):
    p = event.get("payload", {})
    detail = (p.get("text") or p.get("command") or p.get("url")
              or p.get("detail") or p.get("path") or "")
    return str(detail)[:58]


def main():
    ap = argparse.ArgumentParser(description="Fattah AgentGuard stream ingester")
    ap.add_argument("--data", default=os.path.join(HERE, "datasets"))
    ap.add_argument("--sigma", default=os.path.join(HERE, "detections", "sigma"))
    ap.add_argument("--out", default=os.path.join(HERE, "alerts.json"))
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to wait between events (e.g. 0.05 for the demo)")
    ap.add_argument("--quiet", action="store_true", help="only print alerts, not every event")
    args = ap.parse_args()

    engine = StreamingEngine(args.sigma)
    soar = MiniSOAR(os.path.dirname(os.path.abspath(args.out)))
    stream = load_stream(args.data)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    state_path = os.path.join(out_dir, "stream_state.json")
    write_json_atomic(args.out, [])
    write_json_atomic(state_path, {"processed": 0, "total": len(stream), "last_ts": None})

    print(f"Streaming {len(stream)} events from {os.path.relpath(args.data, HERE)}/ ...\n")
    for i, event in enumerate(stream, 1):
        new_alerts = engine.process(event)
        if not args.quiet:
            print(f"  [{i:3d}] {event['event_type']:14} {event['session_id']:18} {short(event)}")
        for a in new_alerts:
            classify(a)                    # triage: TP / FP
            rec = soar.respond(a)          # Mini SOAR: act on the verdict
            mark = SEV_MARK.get(a["severity"], "[????]")
            print(f"        >>> ALERT {mark} {a['rule_id']} {a['threat_category']}  "
                  f"({a['alert_id']})  -> {VERDICT_TAG[a['triage']['verdict']]} "
                  f"conf {a['triage']['confidence']} -> {a['response_taken']} {rec.get('quarantine_id') or rec.get('closure_id')}")
        # live output for the dashboard
        if new_alerts:
            write_json_atomic(args.out, engine.alerts)
        write_json_atomic(state_path, {"processed": i, "total": len(stream), "last_ts": event["timestamp"]})
        if args.delay:
            sleep(args.delay)

    write_json_atomic(args.out, engine.alerts)

    by_rule = {}
    for a in engine.alerts:
        by_rule[a["rule_id"]] = by_rule.get(a["rule_id"], 0) + 1
    print(f"\nStream complete. {len(engine.alerts)} alerts raised -> {os.path.relpath(args.out, HERE)}")
    c = soar.counts
    print(f"Mini SOAR: {c['quarantined']} quarantined (TP) | {c['closed_false_positive']} closed (FP) | "
          f"{c['closed_benign_positive']} closed (BP) | {c['held_for_review']} held for review (guardrail)")
    print(f"  quarantine.log: {c['quarantined'] + c['held_for_review']} records | "
          f"triage.log: {c['closed_false_positive'] + c['closed_benign_positive']} closures")
    for r in sorted(by_rule):
        print(f"  {r}: {by_rule[r]}")


if __name__ == "__main__":
    main()
