#!/usr/bin/env python3
"""
Fattah AgentGuard — dashboard server.

A small web server (Python standard library only, no installs) that reads the
pipeline's outputs and serves a Splunk-style SOC dashboard.

All calculations happen here in Python; the browser page only draws them.

Routes:
    /               the dashboard page (dashboard/index.html)
    /api/summary    every panel's data as JSON, recomputed on each request,
                    so the page updates live while ingest.py is streaming

Reads (from the project folder):
    alerts.json, quarantine.log, triage.log, stream_state.json, datasets/**.ndjson

Usage:
    python3 dashboard.py                  # http://localhost:8080
    PORT=9000 python3 dashboard.py
"""

import glob
import json
import os
import re
import statistics
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import triage as T                      # reuse the same threat-intel lists as triage
import sources
import usecases
from mini_soar import LOG_FILES, read_records, verify

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AGENTGUARD_DIR", HERE)
PAGE = os.path.join(HERE, "dashboard", "index.html")
FONT_RE = re.compile(r"/fonts/[a-z0-9-]+\.woff2")

RULE_NAMES = {
    "T1": "Prompt injection",
    "T2": "Suspicious package",
    "T3": "Unapproved egress",
    "T4": "Injection → exfil chain",
    "T5": "Dependency → exec chain",
}

# Detection coverage. "Agent scope" is the set of ATLAS techniques we consider
# relevant to coding-agent activity logs: the 5 covered plus 3 known gaps.
ATLAS_SCOPE = [
    ("Initial access", "AML.T0051.001", "Indirect prompt injection", ["T1", "T4"]),
    ("Initial access", "AML.T0010", "AI supply chain compromise", ["T2", "T5"]),
    ("Execution", "AML.T0053", "AI agent tool invocation", ["T5"]),
    ("Credential access", "AML.T0098", "Agent tool credential harvesting", ["T4"]),
    ("Exfiltration", "AML.T0086", "Exfil via agent tool invocation", ["T3", "T4"]),
    ("Persistence", "AML.T0080", "AI agent context poisoning", []),
    ("Impact", "AML.T0101", "Data destruction via agent tool", []),
    ("Exfiltration", "AML.T0024", "Exfil via AI inference API", []),
]
ATLAS_TOTAL_TECHNIQUES = 120          # ATLAS v2026.09
OWASP_AGENTIC = [
    ("ASI01", "Agent goal hijack", ["T1", "T4"]),
    ("ASI02", "Tool misuse and exploitation", ["T3", "T4"]),
    ("ASI03", "Identity and privilege abuse", []),
    ("ASI04", "Agentic supply chain", ["T2", "T5"]),
    ("ASI05", "Unexpected code execution", ["T5"]),
    ("ASI06", "Memory and context poisoning", []),
    ("ASI07", "Insecure inter-agent comms", []),
    ("ASI08", "Cascading failures", []),
    ("ASI09", "Human-agent trust exploitation", []),
    ("ASI10", "Rogue agents", []),
]
STEP_TECHNIQUE = {
    "injection": "AML.T0051.001", "secret_read": "AML.T0098", "exfil": "AML.T0086",
    "suspicious_install": "AML.T0010", "payload_exec": "AML.T0053",
}
SPIKE_FACTOR = 10                      # an hour above 10x the median hour is a spike


# ---------------------------------------------------------------------------
# Loading (tolerant of files that are missing or mid-write)
# ---------------------------------------------------------------------------
def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_alerts():
    return _read_json(os.path.join(DATA_DIR, "alerts.json"), [])


def load_events():
    events = []
    for f in sorted(glob.glob(os.path.join(DATA_DIR, "datasets", "**", "*.ndjson"), recursive=True)):
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    events.sort(key=lambda e: e["timestamp"])
    return events


def _host(url):
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url


def _git_host(detail):
    m = re.search(r"https?://([^/\s]+)", detail) or re.search(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", detail)
    return m.group(1) if m else "origin (default remote)"


def _minutes(ts):
    """ISO timestamp -> minutes since midnight (all data is within one day)."""
    return int(ts[11:13]) * 60 + int(ts[14:16]) + int(ts[17:19]) / 60


def _is_bad(host):
    return any(b in host for b in T.KNOWN_BAD_HOSTS) or bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


MAX_RESPONSE_RECORDS = 500


def load_response_records(alerts):
    """Mini SOAR response log: quarantine and closure records, each with its SHA-256 check."""
    status = {a["alert_id"]: a.get("status") for a in alerts}
    out = []
    for name in LOG_FILES:
        live = name.startswith("live_")
        for rec, ok in read_records(os.path.join(DATA_DIR, name)):
            if "unreadable_line" in rec:
                out.append({"id": "unreadable", "kind": "quarantine" if "quarantine" in name else "closure",
                            "log": name, "live": live, "verified": False, "alert_id": "", "rule_id": "",
                            "severity": "", "session_id": "", "verdict": "", "confidence": "",
                            "time": "", "summary": rec["unreadable_line"], "sha256": "", "held": False})
                continue
            quarantine = "quarantine_id" in rec
            if quarantine:
                ev = (rec.get("evidence") or [{}])[0]
                summary = f"{ev.get('source', '')}: {ev.get('snippet', '')}".strip(": ")
            else:
                summary = rec.get("reason", "")
            out.append({
                "id": str(rec.get("quarantine_id") or rec.get("closure_id") or "?"),
                "kind": "quarantine" if quarantine else "closure",
                "log": name, "live": live, "verified": ok,
                "alert_id": str(rec.get("alert_id", "")), "rule_id": str(rec.get("rule_id", "")),
                "severity": str(rec.get("severity", "")), "session_id": str(rec.get("session_id", "")),
                "verdict": str(rec.get("verdict", "")), "confidence": rec.get("confidence", ""),
                "time": str(rec.get("quarantined_at") or rec.get("closed_at") or ""),
                "summary": str(summary)[:160], "sha256": str(rec.get("sha256", "")),
                "held": quarantine and status.get(rec.get("alert_id")) == "held_for_review",
            })
    out.sort(key=lambda r: (r["time"], r["id"]), reverse=True)
    return out[:MAX_RESPONSE_RECORDS]


# ---------------------------------------------------------------------------
# Panels
# ---------------------------------------------------------------------------
def build_summary():
    dataset_alerts = load_alerts()
    live_alerts = sources.load_live_alerts()
    alerts = dataset_alerts + live_alerts
    all_events = load_events()
    live_events = sources.load_live_events()
    state = _read_json(os.path.join(DATA_DIR, "stream_state.json"), None)

    # When streaming, only count events the pipeline has processed so far.
    if state and state.get("last_ts"):
        events = [e for e in all_events if e["timestamp"] <= state["last_ts"]]
    else:
        events = all_events
    if state:
        processed, total = state["processed"], state["total"]
    else:
        # no progress file yet: nothing processed unless a previous run left alerts
        processed, total = (len(events) if alerts else 0), len(all_events)
        if not alerts:
            events = []
    # live-ingested events (from connected agents) are always "processed"
    events = events + live_events
    all_events = sorted(all_events + live_events, key=lambda e: e["timestamp"])
    processed, total = processed + len(live_events), total + len(live_events)

    active = [a for a in alerts if a.get("status") != "closed"]

    # --- single values
    integrity = {}
    for name in LOG_FILES:
        p = os.path.join(DATA_DIR, name)
        if os.path.exists(p):
            n, bad = verify(p)
            integrity[name] = {"records": n, "tampered": bad}
        else:
            integrity[name] = {"records": 0, "tampered": []}
    kpi = {
        "active": len(active),
        "critical": sum(1 for a in active if a["severity"] == "Critical"),
        "auto_closed": sum(1 for a in alerts if a.get("status") == "closed"),
        "held": sum(1 for a in alerts if a.get("status") == "held_for_review"),
        "total_alerts": len(alerts),
        "integrity_ok": all(not v["tampered"] for v in integrity.values()),
        "integrity_records": sum(v["records"] for v in integrity.values()),
        "integrity": integrity,
        "processed": processed,
        "total_events": total,
    }

    # --- time axis: every hour in the dataset window
    hours = sorted({e["timestamp"][11:13] for e in all_events}) or ["00"]
    hour_axis = [f"{h:02d}" for h in range(int(hours[0]), int(hours[-1]) + 1)]

    alerts_by_hour = {h: {"Critical": 0, "High": 0} for h in hour_axis}
    for a in alerts:
        h = a["timestamp"][11:13]
        if h in alerts_by_hour:
            alerts_by_hour[h][a["severity"]] = alerts_by_hour[h].get(a["severity"], 0) + 1

    bytes_by_hour = {h: 0 for h in hour_axis}
    for e in events:
        if e["event_type"] == "api_call":
            bytes_by_hour[e["timestamp"][11:13]] += int(e["payload"].get("body_size") or 0)
    nonzero = [v for v in bytes_by_hour.values() if v > 0]
    baseline = statistics.median(nonzero) if nonzero else 0
    threshold = baseline * SPIKE_FACTOR
    outbound = [{"hour": h, "bytes": b, "spike": bool(baseline) and b > threshold}
                for h, b in bytes_by_hour.items()]

    # --- breakdowns
    by_rule = Counter(a["rule_id"] for a in alerts)
    names = dict(RULE_NAMES)
    for uc in usecases.list_usecases():
        if uc["rule_id"] not in names and (uc["deployed"] or by_rule.get(uc["rule_id"])):
            names[uc["rule_id"]] = uc["name"]
    by_category = [{"rule": r, "name": names[r], "count": by_rule.get(r, 0),
                    "chain": r in ("T4", "T5")} for r in sorted(names, key=lambda x: int(x[1:]) if x[1:].isdigit() else 99)]
    by_verdict = Counter(a.get("triage", {}).get("verdict", "untriaged") for a in alerts)
    by_severity = Counter(a["severity"] for a in alerts)

    # --- coverage
    atlas = [{"tactic": t, "id": i, "name": n, "rules": r, "covered": bool(r)} for t, i, n, r in ATLAS_SCOPE]
    covered = sum(1 for x in atlas if x["covered"])
    asi = [{"id": i, "name": n, "rules": r, "covered": bool(r)} for i, n, r in OWASP_AGENTIC]
    coverage = {
        "atlas": atlas,
        "atlas_scope_covered": covered, "atlas_scope_total": len(atlas),
        "atlas_all_total": ATLAS_TOTAL_TECHNIQUES,
        "asi": asi, "asi_covered": sum(1 for x in asi if x["covered"]), "asi_total": len(asi),
    }

    # --- threat intel hits (indicators seen in true-positive alert evidence)
    indicators = ([(h, "host") for h in T.KNOWN_BAD_HOSTS] +
                  [(p, "package") for p in T.KNOWN_TYPOSQUATS])
    ti = Counter()
    ips = Counter()
    for a in alerts:
        if a.get("triage", {}).get("verdict") != "true_positive":
            continue
        text = " ".join(x.get("source", "") + " " + x.get("snippet", "") for x in a["evidence"]).lower()
        for ind, _ in indicators:
            if ind in text:
                ti[ind] += 1
        for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
            ips[ip] += 1
    kinds = dict(indicators)
    threat_intel = ([{"indicator": k, "type": kinds[k], "hits": v} for k, v in ti.items()] +
                    [{"indicator": k, "type": "ip", "hits": v} for k, v in ips.items()])
    threat_intel.sort(key=lambda x: -x["hits"])

    # --- top outbound destinations (from activity, not alerts)
    dest = Counter()
    for e in events:
        p = e["payload"]
        if e["event_type"] == "api_call":
            dest[_host(p.get("url", ""))] += 1
        elif e["event_type"] == "git_operation" and p.get("operation") in ("push", "remote_add"):
            dest[_git_host(p.get("detail", ""))] += 1
    top_destinations = [{"host": h, "count": c, "flagged": _is_bad(h)} for h, c in dest.most_common(10)]

    # --- entities: risky sessions and agent profiles
    sess_meta = {}
    for e in events:
        sess_meta.setdefault(e["session_id"], (e["agent"], e["user"], e["repo"]))
    risk = defaultdict(int)
    sess_alerts = defaultdict(int)
    for a in active:
        risk[a["session_id"]] += a.get("triage", {}).get("confidence", 0)
        sess_alerts[a["session_id"]] += 1
    risky_sessions = []
    for sid, score in sorted(risk.items(), key=lambda x: -x[1])[:5]:
        ag, us, rp = sess_meta.get(sid, ("?", "?", "?"))
        risky_sessions.append({"session": sid, "risk": score, "alerts": sess_alerts[sid],
                               "agent": ag, "user": us, "repo": rp})

    prof = defaultdict(lambda: {"sessions": set(), "events": Counter(), "active_alerts": 0})
    for e in events:
        prof[e["agent"]]["sessions"].add(e["session_id"])
        prof[e["agent"]]["events"][e["event_type"]] += 1
    for a in active:
        prof[a["agent"]]["active_alerts"] += 1
    agents = sorted(({"agent": k, "sessions": len(v["sessions"]), "events": dict(v["events"]),
                      "total_events": sum(v["events"].values()), "active_alerts": v["active_alerts"]}
                     for k, v in prof.items()), key=lambda x: -x["active_alerts"])

    # --- attack chains (correlation alerts)
    chains = []
    for a in alerts:
        if a["rule_id"] not in ("T4", "T5"):
            continue
        steps = [{"step": x.get("step", x["event_type"]), "timestamp": x.get("timestamp", ""),
                  "source": x.get("source", ""), "snippet": x.get("snippet", ""),
                  "technique": STEP_TECHNIQUE.get(x.get("step", ""), "")} for x in a["evidence"]]
        chains.append({"alert_id": a["alert_id"], "rule_id": a["rule_id"], "session": a["session_id"],
                       "user": a["user"], "agent": a["agent"], "repo": a["repo"],
                       "severity": a["severity"], "verdict": a.get("triage", {}).get("verdict"),
                       "confidence": a.get("triage", {}).get("confidence"),
                       "response": a.get("response_taken"), "steps": steps})

    # --- lab validation (uses ground-truth labels: lab only, never used by the pipeline)
    label = {(e["session_id"], e["timestamp"], e["event_type"]): e.get("label") for e in all_events}
    lab = {"alerts": len(dataset_alerts), "true_attacks": 0, "attacks_classified_tp": 0,
           "benign_closed": 0, "attacks_closed": 0, "malicious_events": sum(1 for v in label.values() if v == "malicious")}
    for a in dataset_alerts:
        mal = any(label.get((a["session_id"], x.get("timestamp"), x["event_type"])) == "malicious" for x in a["evidence"])
        v = a.get("triage", {}).get("verdict")
        lab["true_attacks"] += mal
        lab["attacks_classified_tp"] += mal and v == "true_positive"
        lab["benign_closed"] += (not mal) and a.get("status") == "closed"
        lab["attacks_closed"] += mal and a.get("status") == "closed"

    # --- activity tape: one lane per session, events and alerts on a shared time axis
    t0 = _minutes(all_events[0]["timestamp"]) if all_events else 0
    t1 = _minutes(all_events[-1]["timestamp"]) if all_events else 1
    lanes = {}
    for e in events:
        lane = lanes.setdefault(e["session_id"], {"session": e["session_id"], "agent": e["agent"],
                                                  "user": e["user"], "repo": e["repo"],
                                                  "events": [], "alerts": [], "chain": None})
        lane["events"].append({"t": _minutes(e["timestamp"]) - t0, "type": e["event_type"]})
    for a in alerts:
        lane = lanes.get(a["session_id"])
        if not lane:
            continue
        lane["alerts"].append({"id": a["alert_id"], "t": _minutes(a["timestamp"]) - t0, "rule": a["rule_id"],
                               "severity": a["severity"], "status": a.get("status"),
                               "verdict": a.get("triage", {}).get("verdict")})
        if a["rule_id"] in ("T4", "T5"):
            lane["chain"] = [_minutes(x["timestamp"]) - t0 for x in a["evidence"] if x.get("timestamp")]
    order = sorted(lanes.values(), key=lambda l: (-risk.get(l["session"], 0), l["events"][0]["t"] if l["events"] else 0))
    tape = {"start": all_events[0]["timestamp"] if all_events else "", "span": max(1, t1 - t0),
            "lanes": order}

    funnel = {
        "events": processed, "total_events": total,
        "alerts": len(alerts),
        "true_positive": sum(1 for a in alerts if a.get("triage", {}).get("verdict") == "true_positive"),
        "closed": kpi["auto_closed"], "held": kpi["held"],
        "quarantined": integrity["quarantine.log"]["records"] + integrity["live_quarantine.log"]["records"],
    }

    return {
        "kpi": kpi,
        "tape": tape,
        "funnel": funnel,
        "hours": hour_axis,
        "alerts_by_hour": [{"hour": h, **v} for h, v in alerts_by_hour.items()],
        "outbound": outbound, "outbound_baseline": baseline, "outbound_threshold": threshold,
        "by_category": by_category,
        "by_verdict": dict(by_verdict), "by_severity": dict(by_severity),
        "coverage": coverage,
        "threat_intel": threat_intel[:10],
        "top_destinations": top_destinations,
        "risky_sessions": risky_sessions,
        "agents": agents,
        "chains": chains,
        "response_records": load_response_records(alerts),
        "alerts": sorted(alerts, key=lambda a: a["timestamp"], reverse=True),
        "lab_validation": lab,
        "live": {"events": len(live_events), "alerts": len(live_alerts)},
        "window": {"start": all_events[0]["timestamp"] if all_events else "",
                   "end": all_events[-1]["timestamp"] if all_events else ""},
    }


# ---------------------------------------------------------------------------
# HTTP server: fixed routes only (no arbitrary file serving)
# ---------------------------------------------------------------------------
MAX_BODY = 1_000_000
USECASE_ACTIONS = {"create", "save", "test", "promote", "toggle", "discard"}


def _alert_counts():
    return dict(Counter(a["rule_id"] for a in load_alerts() + sources.load_live_alerts()))


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _base_url(self):
        host = self.headers.get("Host") or f"localhost:{os.environ.get('PORT', '8080')}"
        return f"http://{host}"

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise sources.IngestError("Request body is too large (1 MB max).", 413)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise sources.IngestError("Body must be valid JSON.")

    def _same_origin(self):
        """Dashboard actions must come from the dashboard page itself (blocks cross-site requests)."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True                      # not a browser cross-site request (e.g. curl)
        return urlparse(origin).netloc == self.headers.get("Host")

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, parse_qs(url.query)
        if path in ("/", "/index.html"):
            with open(PAGE, "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/summary":
            self._json(200, build_summary())
        elif path == "/api/usecases":
            self._json(200, {"usecases": usecases.list_usecases(_alert_counts())})
        elif path == "/api/usecases/samples":
            self._json(200, usecases.samples((q.get("rule") or [""])[0]))
        elif path == "/api/sources":
            tok = sources.get_token()
            self._json(200, {"sources": sources.list_sources(load_events(), self._base_url()),
                             "token_masked": sources.mask(tok),
                             "token_from_env": bool(os.environ.get("AGENTGUARD_TOKEN"))})
        elif path == "/api/sources/token":
            self._json(200, {"token": sources.get_token()})
        elif path == "/healthz":
            self._send(200, b"ok", "text/plain")
        elif FONT_RE.fullmatch(path):
            # only bundled font files, matched by a strict name pattern (no path traversal)
            font = os.path.join(HERE, "dashboard", "fonts", path.rsplit("/", 1)[1])
            if os.path.isfile(font):
                with open(font, "rb") as f:
                    self._send(200, f.read(), "font/woff2")
            else:
                self._send(404, b"not found", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            # live ingestion from connected agents: bearer token, no browser origin
            m = re.fullmatch(r"/ingest/v1/([a-z0-9-]+)", path)
            if m:
                if not sources.check_token(self.headers.get("Authorization")):
                    return self._json(401, {"error": "Missing or invalid token. Copy it from the Log sources tab."})
                return self._json(202, sources.ingest(m.group(1), self._read_json()))

            if not path.startswith("/api/"):
                return self._send(404, b"not found", "text/plain")
            if not self._same_origin():
                return self._json(403, {"error": "Cross-site request blocked."})
            body = self._read_json()

            m = re.fullmatch(r"/api/usecases/([a-z]+)", path)
            if m and m.group(1) in USECASE_ACTIONS:
                action, rid = m.group(1), str(body.get("rule_id", ""))
                if action == "create":
                    return self._json(200, {"rule_id": usecases.create(body.get("name", ""), body.get("severity", "High"))})
                if action == "save":
                    return self._json(200, {"version": usecases.save_draft(rid, str(body.get("yaml", "")))})
                if action == "test":
                    return self._json(200, usecases.run_test(rid, str(body.get("logs", "")), bool(body.get("draft", True))))
                if action == "promote":
                    return self._json(200, {"version": usecases.promote(rid)})
                if action == "toggle":
                    usecases.set_enabled(rid, bool(body.get("enabled")))
                    return self._json(200, {"ok": True})
                if action == "discard":
                    usecases.discard_draft(rid)
                    return self._json(200, {"ok": True})
            if path == "/api/sources/token/rotate":
                sources.rotate_token()
                return self._json(200, {"ok": True})
            if path == "/api/sources/add":
                return self._json(200, sources.add_source(body.get("name", ""), body.get("description", "")))
            m = re.fullmatch(r"/api/sources/([a-z0-9-]+)/delete", path)
            if m:
                sources.remove_source(m.group(1))
                return self._json(200, {"ok": True})
            m = re.fullmatch(r"/api/sources/([a-z0-9-]+)/test", path)
            if m:
                return self._json(200, sources.send_test_event(m.group(1)))
            return self._send(404, b"not found", "text/plain")
        except usecases.UseCaseError as ex:
            return self._json(400, {"error": str(ex)})
        except sources.IngestError as ex:
            return self._json(ex.code, {"error": str(ex)})

    def log_message(self, fmt, *args):      # keep the console quiet
        pass


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    print(f"Fattah AgentGuard Dashboard on http://localhost:{port}  (data: {DATA_DIR})")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
