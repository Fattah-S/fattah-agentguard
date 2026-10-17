#!/usr/bin/env python3
"""
Fattah AgentGuard — correlation rules (T4, T5).

These are kept in Python, not Sigma: they match a SEQUENCE of events within one
session_id inside a time window. Sigma's correlation support is limited and not
well-suited to session-scoped, multi-step chains, so this is the right tool.

Each rule is a function(events) -> list[result dict]. The engine wraps each
result into a FAG- alert via AlertFactory.from_correlation.

A chain fires only when ALL required steps are present IN ORDER within the window.
Near-miss sessions (missing the final step) deliberately do NOT fire here — they
are caught, if at all, only by the relevant atomic Sigma rule.
"""

from datetime import datetime
from collections import defaultdict

WINDOW_SECONDS = 1800  # 30 minutes: steps must occur within this span


def _ts(e):
    return datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ")


def _by_session(events):
    sessions = defaultdict(list)
    for e in events:
        sessions[e["session_id"]].append(e)
    for sid in sessions:
        sessions[sid].sort(key=_ts)
    return sessions


def _evidence(e, step):
    p = e.get("payload", {})
    src = p.get("source") or p.get("path") or p.get("url") or ""
    snippet = (p.get("text") or p.get("command") or p.get("detail")
               or f"{p.get('method','')} {p.get('url','')} "
                  f"{p.get('body_size','')} bytes: {p.get('body_snippet','')}".strip())
    return {
        "event_type": e["event_type"],
        "source": str(src),
        "timestamp": e["timestamp"],
        "snippet": str(snippet)[:400],
        "step": step,
    }


# --- step predicates (operational signals only; never read label/owasp) -----

INJECTION_PHRASES = ("ignore previous instructions", "ignore all previous instructions",
                     "disregard your system prompt", "override your guidelines")
SECRET_PATHS = (".env", "id_rsa", ".aws/credentials", ".pem", ".ssh")
EXFIL_HOSTS = ("ngrok.io", "webhook.site", "pastebin.com")
INSTALL_BAD = ("reqeusts", "expresss", "colourama", "djnago",
               "flask-auth-helper-pro", "--index-url http://", "git+https://github.com/")
EXEC_SIGNALS = ("| bash", "|bash", "curl -s http://", "/dev/tcp/", "nc -e",
                ".postinstall", "~/.bashrc", "base64 -d")


def _is_injection(e):
    if e["event_type"] not in ("prompt", "file_read"):
        return False
    t = (e.get("payload", {}).get("text") or "").lower()
    return any(p in t for p in INJECTION_PHRASES)


def _is_secret_read(e):
    if e["event_type"] != "file_read":
        return False
    path = (e.get("payload", {}).get("path") or "").lower()
    return any(s in path for s in SECRET_PATHS)


def _is_exfil(e):
    if e["event_type"] != "api_call":
        return False
    url = (e.get("payload", {}).get("url") or "").lower()
    if any(h in url for h in EXFIL_HOSTS):
        return True
    import re
    return bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))


def _is_suspicious_install(e):
    if e["event_type"] != "shell_command":
        return False
    cmd = (e.get("payload", {}).get("command") or "").lower()
    return ("install" in cmd) and any(b in cmd for b in INSTALL_BAD)


def _is_exec_payload(e):
    if e["event_type"] not in ("shell_command", "file_edit"):
        return False
    text = (e.get("payload", {}).get("command") or e.get("payload", {}).get("diff") or "").lower()
    return any(s in text for s in EXEC_SIGNALS)


# --- T4: injection -> secret read -> exfil ----------------------------------
def rule_T4_injection_to_exfil(events):
    results = []
    for sid, evs in _by_session(events).items():
        inj = next((e for e in evs if _is_injection(e)), None)
        if not inj:
            continue
        sec = next((e for e in evs if _is_secret_read(e) and _ts(e) >= _ts(inj)), None)
        if not sec:
            continue
        exf = next((e for e in evs if _is_exfil(e) and _ts(e) >= _ts(sec)), None)
        if not exf:
            continue  # near-miss (no exfil) -> chain does NOT fire
        if (_ts(exf) - _ts(inj)).total_seconds() > WINDOW_SECONDS:
            continue
        results.append({
            "rule_id": "T4",
            "threat_category": "Injection to Secret Exfiltration (attack chain)",
            "severity": "Critical",
            "owasp": "LLM01 Prompt Injection -> LLM02 Sensitive Information Disclosure",
            "owasp_agentic": "ASI01 Agent Goal Hijack -> ASI02 Tool Misuse & Exploitation",
            "mitre": {
                "framework": "ATLAS", "tactic": "Exfiltration",
                "technique_id": "AML.T0086", "technique_name": "Exfiltration via AI Agent Tool Invocation",
                "also": [
                    {"framework": "ATLAS", "technique_id": "AML.T0051.001", "technique_name": "Indirect Prompt Injection"},
                    {"framework": "ATLAS", "technique_id": "AML.T0098", "technique_name": "AI Agent Tool Credential Harvesting"},
                    {"framework": "ATT&CK", "technique_id": "T1552.001", "technique_name": "Credentials In Files"},
                    {"framework": "ATT&CK", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service"},
                ],
            },
            "timestamp": exf["timestamp"],
            "session_id": sid,
            "agent": inj["agent"], "user": inj["user"], "repo": inj["repo"],
            "evidence": [_evidence(inj, "injection"), _evidence(sec, "secret_read"), _evidence(exf, "exfil")],
            "recommended_action": "Kill the session immediately, rotate the exposed credentials, "
                                  "and block the destination host; escalate to incident response.",
        })
    return results


# --- T5: suspicious install -> payload executes -----------------------------
def rule_T5_dependency_to_exec(events):
    results = []
    for sid, evs in _by_session(events).items():
        inst = next((e for e in evs if _is_suspicious_install(e)), None)
        if not inst:
            continue
        payload = next((e for e in evs if _is_exec_payload(e) and _ts(e) >= _ts(inst)), None)
        if not payload:
            continue  # near-miss (install only) -> chain does NOT fire
        if (_ts(payload) - _ts(inst)).total_seconds() > WINDOW_SECONDS:
            continue
        results.append({
            "rule_id": "T5",
            "threat_category": "Dependency Confusion to Code Execution (attack chain)",
            "severity": "Critical",
            "owasp": "LLM03 Supply Chain -> LLM06 Excessive Agency",
            "owasp_agentic": "ASI04 Agentic Supply Chain Vulnerabilities -> ASI05 Unexpected Code Execution",
            "mitre": {
                "framework": "ATLAS", "tactic": "Execution",
                "technique_id": "AML.T0053", "technique_name": "AI Agent Tool Invocation",
                "also": [
                    {"framework": "ATLAS", "technique_id": "AML.T0010", "technique_name": "AI Supply Chain Compromise"},
                    {"framework": "ATT&CK", "technique_id": "T1195.001", "technique_name": "Compromise Software Dependencies and Development Tools"},
                    {"framework": "ATT&CK", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
                ],
            },
            "timestamp": payload["timestamp"],
            "session_id": sid,
            "agent": inst["agent"], "user": inst["user"], "repo": inst["repo"],
            "evidence": [_evidence(inst, "suspicious_install"), _evidence(payload, "payload_exec")],
            "recommended_action": "Kill the session, remove the installed package, and isolate the host; "
                                  "review for persistence (startup files, cron) and escalate.",
        })
    return results


CORRELATION_RULES = [rule_T4_injection_to_exfil, rule_T5_dependency_to_exec]
