#!/usr/bin/env python3
"""
Fattah AgentGuard — Triage (classification stage).

Sits between detection and response:

    detection (rules) -> TRIAGE (classify TP / FP) -> Mini SOAR (act)

classify(alert) computes label-free signals from the alert's own fields
(evidence text, source, destination, rule type), turns them into a confidence
score 0-100, and stamps a verdict on the alert:

    confidence >= 60                          -> true_positive
    confidence <  60, expected-activity signal -> benign_positive  (suspicious but expected)
    confidence <  60, no such signal           -> false_positive   (incorrect alert logic)

These are the same three closure classes Microsoft Sentinel uses.

Triage only CLASSIFIES. It takes no action; the Mini SOAR reads the verdict and
decides what to do. The ground-truth `label` on events is never read here.
"""

import re

TP_THRESHOLD = 60
BASE_CONFIDENCE = 50
CHAIN_RULES = {"T4", "T5"}

# ---------------------------------------------------------------------------
# Knowledge lists: general indicators (like threat intel / allowlists),
# not tied to specific dataset lines.
# ---------------------------------------------------------------------------
STRONG_OVERRIDE = ("ignore all previous instructions", "ignore previous instructions",
                   "disregard your system prompt", "disregard previous instructions",
                   "override your guidelines", "admin mode")
SECRECY_EVASION = ("do not tell the user", "must not tell the user", "to the user",
                   "skip code review", "without review")
DANGEROUS_ACTION = ("delete", "exfiltrate", "curl", "| bash", "push directly to main",
                    ".env", "environment file", "post its contents")
AGENT_CONFIG_SOURCES = (".cursorrules", "agents.md", "copilot-instructions")
ZERO_WIDTH = ("​", "‌", "‍", "﻿")
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{6,}={1,2}")

KNOWN_TYPOSQUATS = ("reqeusts", "expresss", "colourama", "djnago")
HALLUCINATION_SUFFIXES = ("-helper", "-pro", "-utils")
TRUSTED_REGISTRIES = ("npm.company.internal", "pypi.org", "registry.npmjs.org")
TRUSTED_GIT_ORGS = ("github.com/company-org/",)

KNOWN_BAD_HOSTS = ("ngrok.io", "webhook.site", "pastebin.com", "unknown-host.io")
RAW_IP = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SECRET_MARKERS = ("akia", "aws_secret", "db_password", "password=", "private key")
COMPANY_HOSTS = ("company.internal",)
LARGE_UPLOAD_BYTES = 10_000


def _sig(name, effect, detail):
    return {"signal": name, "effect": effect, "detail": detail}


def _signals_T1(text, source):
    t, s = text.lower(), (source or "").lower()
    sig = []
    if any(p in t for p in STRONG_OVERRIDE):
        sig.append(_sig("strong_override_phrase", +30, "explicit instruction-override wording"))
    if any(p in t for p in SECRECY_EVASION):
        sig.append(_sig("secrecy_or_evasion", +20, "hides actions from the user or skips review"))
    if any(z in text for z in ZERO_WIDTH) or BASE64_TOKEN.search(text):
        sig.append(_sig("hidden_content", +20, "zero-width characters or encoded payload"))
    if any(p in t for p in DANGEROUS_ACTION):
        sig.append(_sig("dangerous_action_requested", +15, "asks for a destructive or exfil action"))
    if any(c in s for c in AGENT_CONFIG_SOURCES):
        sig.append(_sig("agent_config_file", +15, "persistent agent rules file"))
    if not sig:
        sig.append(_sig("weak_phrase_only", -30, "matched only a generic phrase, no injection intent"))
    if s == "user":
        sig.append(_sig("developer_prompt", -15, "text typed by the developer, not ingested content"))
    return sig


def _signals_T2(cmd):
    c = cmd.lower()
    sig = []
    if any(x in c for x in KNOWN_TYPOSQUATS):
        sig.append(_sig("known_typosquat", +40, "name matches a known typosquat of a popular package"))
    if "--index-url http://" in c or RAW_IP.search(c):
        sig.append(_sig("insecure_index", +30, "plaintext or raw-IP package index"))
    if "git+https://" in c and not any(o in c for o in TRUSTED_GIT_ORGS):
        sig.append(_sig("unknown_git_source", +20, "package pulled from an untrusted git repo"))
    if sum(1 for s in HALLUCINATION_SUFFIXES if s in c) >= 2:
        sig.append(_sig("stacked_suffixes", +20, "multiple hallucination-style suffixes in the name"))
    if any(r in c for r in TRUSTED_REGISTRIES) and "--index-url http://" not in c:
        sig.append(_sig("trusted_registry", -30, "registry is on the approved list"))
    if any(o in c for o in TRUSTED_GIT_ORGS):
        sig.append(_sig("trusted_git_org", -30, "repository belongs to the organisation"))
    if not any(x["effect"] > 0 for x in sig):
        sig.append(_sig("no_corroborating_indicator", -20, "rule matched but no supporting threat indicator"))
    return sig


def _signals_T3(evidence):
    src = (evidence.get("source") or "").lower()
    snip = (evidence.get("snippet") or "").lower()
    blob = src + " " + snip
    sig = []
    if any(h in blob for h in KNOWN_BAD_HOSTS):
        sig.append(_sig("known_bad_destination", +40, "tunnelling / paste / unknown host"))
    if RAW_IP.search(blob):
        sig.append(_sig("raw_ip_destination", +30, "destination is a bare IP address"))
    m = re.search(r"(\d+) bytes", snip)
    if m and int(m.group(1)) > LARGE_UPLOAD_BYTES:
        sig.append(_sig("large_upload", +20, f"{m.group(1)} bytes sent out"))
    if any(s in snip for s in SECRET_MARKERS):
        sig.append(_sig("secret_in_payload", +25, "credential pattern in the request body"))
    if snip.startswith("get "):
        sig.append(_sig("read_only_request", -20, "GET request, no data sent"))
    if any(h in blob for h in COMPANY_HOSTS):
        sig.append(_sig("company_destination", -30, "destination is an organisation-owned host"))
    if not any(x["effect"] > 0 for x in sig):
        sig.append(_sig("no_corroborating_indicator", -20, "destination unlisted but no exfil indicator"))
    return sig


def _signals_chain(alert):
    sig = [_sig("part_of_attack_chain", +40, f"{alert['rule_id']} multi-step sequence in one session")]
    text = " ".join(e.get("snippet", "") + " " + e.get("source", "") for e in alert["evidence"]).lower()
    if any(s in text for s in SECRET_MARKERS):
        sig.append(_sig("secret_in_evidence", +25, "credential pattern in chain evidence"))
    if any(h in text for h in KNOWN_BAD_HOSTS) or RAW_IP.search(text):
        sig.append(_sig("known_bad_destination", +10, "chain reaches a bad host"))
    return sig


# signals that mean "the activity really happened, and it is expected/authorised"
EXPECTED_ACTIVITY = {"trusted_registry", "trusted_git_org", "company_destination", "read_only_request"}

REASONS = {
    "true_positive": "Corroborating threat indicators present.",
    "benign_positive": "Suspicious but expected: the activity is real and matches an approved pattern.",
    "false_positive": "Incorrect alert logic: the rule matched, but there is no threat indicator.",
}


def classify(alert):
    """Stamp alert['triage'] = {verdict, confidence, signals, reason}. Returns the triage block."""
    rid = alert["rule_id"]
    ev = alert["evidence"][0]
    if rid in CHAIN_RULES:
        signals = _signals_chain(alert)
    elif rid == "T1":
        signals = _signals_T1(ev.get("snippet", ""), ev.get("source", ""))
    elif rid == "T2":
        signals = _signals_T2(ev.get("snippet", ""))
    elif rid == "T3":
        signals = _signals_T3(ev)
    else:
        # use cases created in the dashboard have no tuned triage profile yet:
        # keep the evidence (lean towards true positive) until one is written
        signals = [_sig("no_triage_profile", +10, "custom use case: evidence kept until triage is tuned")]

    confidence = max(0, min(100, BASE_CONFIDENCE + sum(s["effect"] for s in signals)))
    if confidence >= TP_THRESHOLD:
        verdict = "true_positive"
    elif any(x["signal"] in EXPECTED_ACTIVITY for x in signals):
        verdict = "benign_positive"
    else:
        verdict = "false_positive"
    alert["triage"] = {
        "verdict": verdict,
        "confidence": confidence,
        "signals": signals,
        "reason": REASONS[verdict],
    }
    return alert["triage"]
