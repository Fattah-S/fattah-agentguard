#!/usr/bin/env python3
"""
Fattah AgentGuard — Mini SOAR (response stage).

    detection (rules) -> triage (classify TP / FP) -> MINI SOAR (act)

The Mini SOAR does not classify. It reads the verdict that triage stamped on the
alert and takes the automated response action:

    true_positive                      -> preserve evidence in quarantine.log   status: new
    benign_positive / false_positive   -> close, audit record in triage.log      status: closed

Response policies:
  a) Guardrail: Critical or correlation-chain alerts are NEVER auto-closed.
     If triage marks one benign/false positive, the SOAR overrides the close:
     the evidence is preserved and the alert is held (status: held_for_review).
  b) Audit trail: every closure is written to triage.log with the triage reason
     and signals, so an analyst can review why it was closed.

Both logs are append-only JSON Lines with a SHA-256 per record, so any change
is detectable with `python3 mini_soar.py --verify`.

Scope: file/log level only. Nothing is executed on the host. In a cloud
environment this is the action you can always perform; in production these logs
would be shipped to write-once storage (S3 Object Lock / Azure immutable blob).
"""

import argparse
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = "fattah-agentguard/mini-soar"
CHAIN_RULES = {"T4", "T5"}
# replayed dataset logs + live-ingestion logs
LOG_FILES = ("quarantine.log", "triage.log", "live_quarantine.log", "live_triage.log")


def _record_hash(record):
    body = {k: v for k, v in record.items() if k != "sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _append(path, record):
    record["sha256"] = _record_hash(record)
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


def decide(alert):
    """
    The response policy, with no side effects. Returns one of:
      'quarantine'  true positive -> preserve evidence
      'close'       benign/false positive on a low-risk alert -> close with audit record
      'hold'        benign/false positive on a Critical/chain alert -> guardrail keeps it open
    Used by respond() and by the use-case test bench (dry run).
    """
    protected = alert["severity"] == "Critical" or alert["rule_id"] in CHAIN_RULES
    if alert["triage"]["verdict"] == "true_positive":
        return "quarantine"
    return "hold" if protected else "close"


class MiniSOAR:
    def __init__(self, out_dir=HERE, fresh=True, prefix="", quarantine_name="quarantine.log",
                 triage_name="triage.log"):
        """
        fresh=True starts new logs for this run (one run = one case).
        prefix separates ID ranges, e.g. 'L' for live-ingested events (QL-0001, CL-0001).
        """
        self.quarantine_path = os.path.join(out_dir, quarantine_name)
        self.triage_path = os.path.join(out_dir, triage_name)
        self.prefix = prefix
        self._q = 0
        self._c = 0
        self.counts = {"quarantined": 0, "closed_false_positive": 0, "closed_benign_positive": 0, "held_for_review": 0}
        if fresh:
            for p in (self.quarantine_path, self.triage_path):
                if os.path.exists(p):
                    os.remove(p)
        else:
            self._q = _count_lines(self.quarantine_path)
            self._c = _count_lines(self.triage_path)

    def respond(self, alert):
        """Act on a triaged alert. Requires alert['triage'] (set by triage.classify)."""
        t = alert["triage"]
        action = decide(alert)
        common = {
            "alert_id": alert["alert_id"],
            "rule_id": alert["rule_id"],
            "threat_category": alert["threat_category"],
            "severity": alert["severity"],
            "session_id": alert["session_id"],
            "agent": alert["agent"],
            "user": alert["user"],
            "repo": alert["repo"],
            "verdict": t["verdict"],
            "confidence": t["confidence"],
        }

        # benign / false positive on a low-risk alert -> close with audit record
        if action == "close":
            self._c += 1
            action = "closed_" + t["verdict"]
            self.counts[action] += 1
            rec = _append(self.triage_path, {
                "closure_id": f"C{self.prefix}-{self._c:04d}",
                **common,
                "closed_at": alert["detected_at"],
                "closed_by": COLLECTOR,
                "reason": t["reason"],
                "signals": t["signals"],
            })
            alert["response_taken"] = action
            alert["status"] = "closed"
            return rec

        # true positive, or guardrail override -> preserve evidence
        held = action == "hold"
        self._q += 1
        self.counts["held_for_review" if held else "quarantined"] += 1
        rec = _append(self.quarantine_path, {
            "quarantine_id": f"Q{self.prefix}-{self._q:04d}",
            **common,
            "quarantined_at": alert["detected_at"],
            "collected_by": COLLECTOR,
            "evidence": alert["evidence"],
        })
        alert["response_taken"] = ("quarantine_logged; held_for_analyst_review" if held
                                   else "quarantine_logged")
        alert["status"] = "held_for_review" if held else "new"
        return rec


def _count_lines(path):
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def read_records(path):
    """Every record in a response log with its integrity result: [(record, verified), ...]."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    out.append(({"unreadable_line": line[:120]}, False))
                    continue
                out.append((rec, isinstance(rec, dict) and _record_hash(rec) == rec.get("sha256")))
    except OSError:
        pass
    return out


def verify(path):
    total, tampered = 0, []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                rec = json.loads(line)
            except ValueError:
                tampered.append(f"line {total} (unreadable)")
                continue
            if not isinstance(rec, dict) or _record_hash(rec) != rec.get("sha256"):
                if not isinstance(rec, dict):
                    tampered.append(f"line {total}")
                    continue
                tampered.append(rec.get("quarantine_id") or rec.get("closure_id") or f"line {total}")
    return total, tampered


def main():
    ap = argparse.ArgumentParser(description="Fattah AgentGuard Mini SOAR")
    ap.add_argument("--verify", action="store_true", help="verify log integrity")
    ap.add_argument("--log", help="verify a single log file (default: quarantine.log and triage.log)")
    args = ap.parse_args()

    if not args.verify:
        ap.print_help()
        return
    paths = [args.log] if args.log else [os.path.join(HERE, n) for n in LOG_FILES
                                          if n in ("quarantine.log", "triage.log")
                                          or os.path.exists(os.path.join(HERE, n))]
    for p in paths:
        if not os.path.exists(p):
            print(f"{os.path.basename(p)}: not found (run engine.py or ingest.py first)")
            continue
        total, tampered = verify(p)
        name = os.path.basename(p)
        if tampered:
            print(f"{name}: INTEGRITY FAILED — {len(tampered)} of {total} records altered: {', '.join(tampered)}")
        else:
            print(f"{name}: integrity OK — all {total} records match their SHA-256")


if __name__ == "__main__":
    main()
