#!/usr/bin/env python3
"""
Fattah AgentGuard — detection engine.

Role: the execution layer. In a real SOC, Sentinel compiles Sigma to KQL and runs
it; here this engine loads the Sigma rules (T1-T3) and applies them to each event,
then runs the Python correlation rules (T4-T5) across sessions. Every hit is emitted
as an alert conforming to alert_schema.json (FAG- IDs).

The engine reads ONLY operational fields. It never reads the ground-truth
label/owasp fields on events (those exist only for scoring).

Usage:
    python3 engine.py --data datasets --out alerts.json
"""

import argparse
import glob
import json
import os
import re
import yaml

from correlation import CORRELATION_RULES  # T4, T5
from triage import classify                # triage stage (TP / FP)
from mini_soar import MiniSOAR             # response stage

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Rule metadata: maps a Sigma rule id -> the alert fields the Sigma file does
# not itself carry in a structured way (OWASP label, full MITRE block, rule_id).
# This is the engine's "rule-to-alert" table.
# ---------------------------------------------------------------------------
SIGMA_META = {
    "f41443ed-6393-491a-933b-8d1986182a62": {
        "rule_id": "T1",
        "owasp": "LLM01 Prompt Injection",
        "owasp_agentic": "ASI01 Agent Goal Hijack",
        "mitre": {
            "framework": "ATLAS", "tactic": "Initial Access",
            "technique_id": "AML.T0051.001", "technique_name": "Indirect Prompt Injection",
        },
    },
    "c464b969-103d-4f00-b912-fa7c558b4beb": {
        "rule_id": "T2",
        "owasp": "LLM03 Supply Chain",
        "owasp_agentic": "ASI04 Agentic Supply Chain Vulnerabilities",
        "mitre": {
            "framework": "ATLAS", "tactic": "Initial Access",
            "technique_id": "AML.T0010", "technique_name": "AI Supply Chain Compromise",
            "also": [{"framework": "ATT&CK", "technique_id": "T1195.001",
                      "technique_name": "Compromise Software Dependencies and Development Tools"}],
        },
    },
    "27af86ef-5646-4f05-9871-05a843117ef0": {
        "rule_id": "T3",
        "owasp": "LLM02 Sensitive Information Disclosure",
        "owasp_agentic": "ASI02 Tool Misuse & Exploitation",
        "mitre": {
            "framework": "ATLAS", "tactic": "Exfiltration",
            "technique_id": "AML.T0086", "technique_name": "Exfiltration via AI Agent Tool Invocation",
            "also": [{"framework": "ATT&CK", "technique_id": "T1567",
                      "technique_name": "Exfiltration Over Web Service"}],
        },
    },
}


# ---------------------------------------------------------------------------
# Minimal Sigma evaluator
#   Supports: dotted field paths (payload.text), |contains, |re,
#   list-of-values (OR), list-of-maps (OR of maps), and a boolean `condition`
#   over named selection blocks (and / or / parentheses).
# ---------------------------------------------------------------------------
def _get_field(event, dotted):
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_leaf(event, field_spec, values):
    """field_spec like 'payload.text|contains'; values is scalar or list (OR)."""
    if "|" in field_spec:
        field, op = field_spec.split("|", 1)
    else:
        field, op = field_spec, "equals"
    actual = _get_field(event, field)
    if actual is None:
        return False
    actual_s = str(actual)
    vals = values if isinstance(values, list) else [values]
    for v in vals:
        v = str(v)
        if op == "contains":
            if v.lower() in actual_s.lower():
                return True
        elif op == "re":
            if re.search(v, actual_s):
                return True
        else:  # equals
            if isinstance(actual, list):
                if v in [str(x) for x in actual]:
                    return True
            elif actual_s == v:
                return True
    return False


def _match_block(event, block):
    """
    A selection block is either:
      - a dict of {field_spec: values}  -> all keys must match (AND)
      - a list of such dicts            -> any item matches (OR)
    """
    if isinstance(block, list):
        return any(_match_block(event, item) for item in block)
    if isinstance(block, dict):
        return all(_match_leaf(event, k, v) for k, v in block.items())
    return False


CONDITION_WORDS = {"and", "or", "not"}


def validate_condition(condition, block_names):
    """
    Allow only block names, and/or/not and parentheses. Rules can be edited from
    the dashboard, so the condition must never carry anything else into eval().
    """
    if not isinstance(condition, str) or not condition.strip():
        raise ValueError("condition must be a non-empty string")
    leftover = re.sub(r"[()\s]|\b\w+\b", "", condition)
    if leftover:
        raise ValueError(f"condition has unsupported characters: {leftover[:20]!r}")
    for word in re.findall(r"\b\w+\b", condition):
        if word not in CONDITION_WORDS and word not in block_names:
            raise ValueError(f"condition refers to an unknown block: {word!r}")


def _eval_condition(condition, block_results):
    """Evaluate the Sigma condition string over {block_name: bool}."""
    validate_condition(condition, set(block_results))
    expr = condition
    # replace longest names first to avoid partial clobbering
    for name in sorted(block_results, key=len, reverse=True):
        expr = re.sub(rf"\b{name}\b", "True" if block_results[name] else "False", expr)
    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")
    try:
        return bool(eval(expr, {"__builtins__": {}}, {"True": True, "False": False}))
    except Exception:
        return False


class SigmaRule:
    def __init__(self, path=None, text=None):
        if text is None:
            with open(path) as f:
                text = f.read()
        self.raw = yaml.safe_load(text)
        if not isinstance(self.raw, dict):
            raise ValueError("rule must be a YAML mapping")
        self.path = path
        self.id = str(self.raw.get("id", ""))
        self.title = self.raw["title"]
        self.level = str(self.raw.get("level", "medium"))
        self.detection = self.raw["detection"]
        if not isinstance(self.detection, dict) or "condition" not in self.detection:
            raise ValueError("detection must be a mapping with a condition")
        self.condition = self.detection["condition"]
        validate_condition(self.condition, {k for k in self.detection if k != "condition"})
        self.recommended_action = " ".join(str(self.raw.get("recommended_action", "")).split())
        self.severity = self.raw.get("severity_label", self.level.capitalize())
        if self.severity not in ("Low", "Medium", "High", "Critical"):
            self.severity = "High"
        self.meta = self._meta()

    def _meta(self):
        """Built-in rules use SIGMA_META; rules created in the dashboard carry their own."""
        if self.id in SIGMA_META:
            return SIGMA_META[self.id]
        r = self.raw
        mitre = r.get("mitre") if isinstance(r.get("mitre"), dict) else {}
        return {
            "rule_id": str(r.get("rule_id", "T0")),
            "owasp": str(r.get("owasp", "Custom use case")),
            "owasp_agentic": str(r.get("owasp_agentic", "Not mapped")),
            "mitre": {
                "framework": mitre.get("framework", "ATLAS") if mitre.get("framework") in ("ATLAS", "ATT&CK") else "ATLAS",
                "tactic": str(mitre.get("tactic", "Not mapped")),
                "technique_id": str(mitre.get("technique_id", "not-mapped")),
                "technique_name": str(mitre.get("technique_name", self.title)),
            },
        }

    def match(self, event):
        blocks = {k: v for k, v in self.detection.items() if k != "condition"}
        results = {name: _match_block(event, spec) for name, spec in blocks.items()}
        return _eval_condition(self.condition, results)


# ---------------------------------------------------------------------------
# Evidence + alert construction
# ---------------------------------------------------------------------------
def _evidence_from_event(ev):
    p = ev.get("payload", {})
    src = p.get("source") or p.get("path") or p.get("url") or p.get("operation") or ""
    snippet = (p.get("text") or p.get("command") or p.get("detail")
               or (f"{p.get('method','')} {p.get('url','')} "
                   f"{p.get('body_size','')} bytes: {p.get('body_snippet','')}".strip())
               or json.dumps(p))
    return {
        "event_type": ev["event_type"],
        "source": str(src),
        "timestamp": ev["timestamp"],
        "snippet": str(snippet)[:400],
    }


class AlertFactory:
    def __init__(self, prefix="FAG-", start=0):
        self._n = start
        self.prefix = prefix

    def _next_id(self):
        self._n += 1
        return f"{self.prefix}{self._n:04d}"

    def from_sigma(self, rule, event):
        m = rule.meta
        return {
            "alert_id": self._next_id(),
            "rule_id": m["rule_id"],
            "threat_category": rule.title,
            "severity": rule.severity,
            "owasp": m["owasp"],
            "owasp_agentic": m["owasp_agentic"],
            "mitre": m["mitre"],
            "timestamp": event["timestamp"],
            "detected_at": event["timestamp"],
            "session_id": event["session_id"],
            "agent": event["agent"],
            "user": event["user"],
            "repo": event["repo"],
            "evidence": [_evidence_from_event(event)],
            "recommended_action": rule.recommended_action,
            "status": "new",
        }

    def from_correlation(self, result):
        """result is the dict returned by a correlation rule."""
        a = {
            "alert_id": self._next_id(),
            "rule_id": result["rule_id"],
            "threat_category": result["threat_category"],
            "severity": result["severity"],
            "owasp": result["owasp"],
            "owasp_agentic": result["owasp_agentic"],
            "mitre": result["mitre"],
            "timestamp": result["timestamp"],
            "detected_at": result["timestamp"],
            "session_id": result["session_id"],
            "agent": result["agent"],
            "user": result["user"],
            "repo": result["repo"],
            "evidence": result["evidence"],
            "recommended_action": result["recommended_action"],
            "status": "new",
        }
        return a


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def load_events(data_dir):
    events = []
    for f in sorted(glob.glob(os.path.join(data_dir, "**", "*.ndjson"), recursive=True)):
        for line in open(f):
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_sigma_rules(sigma_dir, active_only=True):
    """Load Sigma rules. By default only use cases that are enabled and in production."""
    rules = [SigmaRule(p) for p in sorted(glob.glob(os.path.join(sigma_dir, "*.yml")))]
    if not active_only:
        return rules
    import usecases
    return [r for r in rules if usecases.is_active(r.meta["rule_id"])]


def active_correlation_rules():
    import usecases
    return [fn for fn in CORRELATION_RULES if usecases.is_active(CORRELATION_ID[fn.__name__])]


# correlation function -> use case id
CORRELATION_ID = {"rule_T4_injection_to_exfil": "T4", "rule_T5_dependency_to_exec": "T5"}


def run(data_dir, sigma_dir):
    sigma_rules = load_sigma_rules(sigma_dir)
    correlation = active_correlation_rules()
    events = load_events(data_dir)
    factory = AlertFactory()
    alerts = []

    # --- atomic Sigma rules, per event ---
    for ev in events:
        for rule in sigma_rules:
            if rule.match(ev):
                alerts.append(factory.from_sigma(rule, ev))

    # --- correlation rules, across sessions ---
    for corr in correlation:
        for result in corr(events):
            alerts.append(factory.from_correlation(result))

    return alerts, events


class StreamingEngine:
    """
    Processes events ONE AT A TIME, the way a live log stream arrives.

    - Atomic Sigma rules (T1-T3) are evaluated the instant an event arrives.
    - Correlation rules (T4-T5) need a session's history, so events are buffered
      per session_id; after each new event the correlation rules re-run over that
      session only, and any NEW chain alert (one not already raised for the
      session+rule) is emitted immediately.

    This reuses the exact same SigmaRule / CORRELATION_RULES / AlertFactory as the
    batch path, so stream and batch produce identical detections.
    """

    def __init__(self, sigma_dir, prefix="FAG-", start=0):
        self.sigma_dir = sigma_dir
        self.factory = AlertFactory(prefix, start)
        self.sessions = {}                 # session_id -> list[event]
        self._fired_chain = set()          # (session_id, rule_id) already alerted
        self.alerts = []
        self.reload_rules()

    def reload_rules(self):
        """Pick up use-case changes (enable, disable, promote) without restarting."""
        self.sigma_rules = load_sigma_rules(self.sigma_dir)
        self.correlation = active_correlation_rules()

    def process(self, event):
        """Feed one event. Returns the list of NEW alerts this event produced."""
        new = []

        # atomic Sigma, evaluated immediately
        for rule in self.sigma_rules:
            if rule.match(event):
                a = self.factory.from_sigma(rule, event)
                self.alerts.append(a)
                new.append(a)

        # buffer by session, then re-run correlation over just this session
        sid = event["session_id"]
        self.sessions.setdefault(sid, []).append(event)
        session_events = self.sessions[sid]
        for corr in self.correlation:
            for result in corr(session_events):
                key = (result["session_id"], result["rule_id"])
                if key not in self._fired_chain:
                    self._fired_chain.add(key)
                    a = self.factory.from_correlation(result)
                    self.alerts.append(a)
                    new.append(a)

        return new


def main():
    ap = argparse.ArgumentParser(description="Fattah AgentGuard detection engine")
    ap.add_argument("--data", default=os.path.join(HERE, "datasets"))
    ap.add_argument("--sigma", default=os.path.join(HERE, "detections", "sigma"))
    ap.add_argument("--out", default=os.path.join(HERE, "alerts.json"))
    args = ap.parse_args()

    alerts, events = run(args.data, args.sigma)

    # pipeline: detection -> triage (classify) -> Mini SOAR (act)
    soar = MiniSOAR(os.path.dirname(os.path.abspath(args.out)))
    for a in alerts:
        classify(a)
        soar.respond(a)

    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(alerts, f, indent=2)
    os.replace(tmp, args.out)
    state = os.path.join(os.path.dirname(os.path.abspath(args.out)), "stream_state.json")
    last_ts = max((e["timestamp"] for e in events), default=None)
    with open(state + ".tmp", "w") as f:
        json.dump({"processed": len(events), "total": len(events), "last_ts": last_ts}, f)
    os.replace(state + ".tmp", state)

    by_rule = {}
    for a in alerts:
        by_rule[a["rule_id"]] = by_rule.get(a["rule_id"], 0) + 1
    print(f"Ingested {len(events)} events")
    print(f"Raised {len(alerts)} alerts -> {args.out}")
    c = soar.counts
    print(f"Mini SOAR: {c['quarantined']} quarantined (TP) | {c['closed_false_positive']} closed (FP) | "
          f"{c['closed_benign_positive']} closed (BP) | {c['held_for_review']} held for review (guardrail)")
    print(f"  quarantine.log: {c['quarantined'] + c['held_for_review']} records | "
          f"triage.log: {c['closed_false_positive'] + c['closed_benign_positive']} closures")
    for r in sorted(by_rule):
        print(f"  {r}: {by_rule[r]}")


if __name__ == "__main__":
    main()
