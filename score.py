#!/usr/bin/env python3
"""
Fattah AgentGuard — scoring harness.

Compares engine + Mini SOAR output against the ground-truth `label` / `owasp`
fields on events. Neither the engine nor the Mini SOAR ever reads those fields;
only this scorer does.

Reports three layers:
  1. Raw detection   — per rule TP / FP / FN against the events that rule covers
  2. Correlation     — chains fire on attack sessions, stay quiet on near-misses
  3. Triage          — Mini SOAR verdicts vs ground truth, including the critical
                       metric: real attacks wrongly closed as false positives
  4. Final actions   — what was preserved, closed, or held for review

Usage: python3 score.py
"""

import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# rule -> (ground-truth OWASP category, event types the rule is designed to inspect)
RULE_SCOPE = {
    "T1": ("LLM01", {"prompt", "file_read"}),
    "T2": ("LLM03", {"shell_command"}),
    "T3": ("LLM02", {"api_call", "git_operation"}),
}


def key(session_id, timestamp, event_type):
    return (session_id, timestamp, event_type)


def load_events():
    evs = []
    for f in sorted(glob.glob(os.path.join(HERE, "datasets", "**", "*.ndjson"), recursive=True)):
        for line in open(f):
            line = line.strip()
            if line:
                evs.append(json.loads(line))
    return evs


def pct(a, b):
    return f"{a / b:.0%}" if b else "n/a"


def main():
    events = load_events()
    alerts = json.load(open(os.path.join(HERE, "alerts.json")))
    label = {key(e["session_id"], e["timestamp"], e["event_type"]): e for e in events}

    def alert_keys(a):
        return [key(a["session_id"], ev["timestamp"], ev["event_type"]) for ev in a["evidence"]]

    def alert_is_malicious(a):
        return any(label.get(k, {}).get("label") == "malicious" for k in alert_keys(a))

    # ------------------------------------------------------------------ 1
    print("=" * 70)
    print("1. RAW DETECTION  (T1-T3, coverage-first rules)  vs ground truth")
    print("=" * 70)
    print(f"{'rule':6}{'alerts':>7}{'TP':>5}{'FP':>5}{'FN':>5}{'precision':>11}{'recall':>9}")
    tot = {"n": 0, "tp": 0, "fp": 0, "fn": 0}
    for rule, (owasp, etypes) in RULE_SCOPE.items():
        flagged = {k for a in alerts if a["rule_id"] == rule for k in alert_keys(a)}
        truth = {k for k, e in label.items()
                 if e["label"] == "malicious" and e["owasp"] == owasp and e["event_type"] in etypes}
        tp = len(flagged & truth)
        fp = len({k for k in flagged if label.get(k, {}).get("label") == "benign"})
        fn = len(truth - flagged)
        n = sum(1 for a in alerts if a["rule_id"] == rule)
        for k_, v in (("n", n), ("tp", tp), ("fp", fp), ("fn", fn)):
            tot[k_] += v
        print(f"{rule:6}{n:>7}{tp:>5}{fp:>5}{fn:>5}{pct(tp, tp + fp):>11}{pct(tp, tp + fn):>9}")
    print("-" * 70)
    print(f"{'ALL':6}{tot['n']:>7}{tot['tp']:>5}{tot['fp']:>5}{tot['fn']:>5}"
          f"{pct(tot['tp'], tot['tp'] + tot['fp']):>11}{pct(tot['tp'], tot['tp'] + tot['fn']):>9}")
    print("Rules are tuned for coverage, so false positives are expected here;")
    print("the triage layer (section 3) is what restores precision.")

    # ------------------------------------------------------------------ 2
    print("\n" + "=" * 70)
    print("2. CORRELATION  (T4-T5)  —  chain vs near-miss")
    print("=" * 70)
    chain_sessions = {a["session_id"] for a in alerts if a["rule_id"] in ("T4", "T5")}
    for s in ("sess-chain-04a", "sess-chain-04b", "sess-chain-05a", "sess-chain-05b"):
        ok = s in chain_sessions
        print(f"  {'[PASS]' if ok else '[FAIL]'} {s:20} chain alert raised: {ok!s:5} (expected: yes)")
    for s in ("sess-nearmiss-04", "sess-nearmiss-05"):
        ok = s not in chain_sessions
        print(f"  {'[PASS]' if ok else '[FAIL]'} {s:20} chain alert raised: {(not ok)!s:5} (expected: no)")

    # ------------------------------------------------------------------ 3
    print("\n" + "=" * 70)
    print("3. TRIAGE  (TP / FP classification)  vs ground truth")
    print("=" * 70)
    if not all("triage" in a for a in alerts):
        print("  alerts have no triage block — run engine.py or ingest.py first")
        return
    ok_tp = ok_fp = missed = false_alarm = bp = 0
    attacks_closed = attacks_saved = 0
    notes = []
    for a in alerts:
        mal = alert_is_malicious(a)
        v = a["triage"]["verdict"]
        resp = a.get("response_taken", "")
        # classification quality (triage stage)
        if mal and v == "true_positive":
            ok_tp += 1
        elif not mal and v in ("false_positive", "benign_positive"):
            ok_fp += 1
            if v == "benign_positive":
                bp += 1
        elif mal and v in ("false_positive", "benign_positive"):
            missed += 1
            notes.append(f"{a['alert_id']} {a['rule_id']}: attack classified as {v}")
        else:
            false_alarm += 1
            notes.append(f"{a['alert_id']} {a['rule_id']}: benign classified as TP")
        # outcome after the SOAR policy (response stage)
        if mal and resp.startswith("closed_"):
            attacks_closed += 1
        if mal and "held_for_analyst_review" in resp:
            attacks_saved += 1
    n = len(alerts)
    print(f"  attacks classified TP                     : {ok_tp}")
    print(f"  benign alerts classified FP / BP          : {ok_fp}  ({ok_fp - bp} false positive, {bp} benign positive)")
    print(f"  attacks classified FP/BP (missed)         : {missed}")
    print(f"  benign alerts classified TP               : {false_alarm}")
    print(f"  triage accuracy                           : {pct(ok_tp + ok_fp, n)} ({ok_tp + ok_fp}/{n})")
    for w in notes:
        print(f"    - {w}")
    print(f"  after SOAR guardrail:")
    print(f"    real attacks actually closed  <- critical : {attacks_closed}")
    print(f"    misclassified attacks saved by guardrail  : {attacks_saved}")

    # ------------------------------------------------------------------ 4
    print("\n" + "=" * 70)
    print("4. MINI SOAR ACTIONS")
    print("=" * 70)
    acts = {}
    for a in alerts:
        acts[a.get("response_taken", "none")] = acts.get(a.get("response_taken", "none"), 0) + 1
    for k_, v in sorted(acts.items()):
        print(f"  {k_:46} {v}")
    status = {}
    for a in alerts:
        status[a.get("status", "?")] = status.get(a.get("status", "?"), 0) + 1
    print("  alert status: " + ", ".join(f"{k_} {v}" for k_, v in sorted(status.items()))
          + f"  -> active alerts: {sum(v for k_, v in status.items() if k_ != 'closed')}")

    # system-level coverage
    flagged_all = {k for a in alerts for k in alert_keys(a)}
    mal_events = {k for k, e in label.items() if e["label"] == "malicious"}
    missing = sorted(mal_events - flagged_all)
    print(f"\n  malicious events appearing in alert evidence: "
          f"{len(mal_events) - len(missing)}/{len(mal_events)}")
    for m in missing:
        print(f"    - {m[2]} @ {m[1]} in {m[0]}")
    if missing:
        print("    (these follow-up steps happen after their session's chain alert already")
        print("     fired; the attack is caught, but these events are not in its evidence)")


if __name__ == "__main__":
    main()
