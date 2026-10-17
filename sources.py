#!/usr/bin/env python3
"""
Fattah AgentGuard — log sources (AI agent onboarding) and live ingestion.

Each AI coding agent is a "connector". Connected agents send their activity to

    POST /ingest/v1/<connector>        Authorization: Bearer <token>

and every event goes straight through the same pipeline as the replayed dataset:
detection -> triage -> Mini SOAR. Live results are kept apart from the replayed
dataset: live_events.ndjson, live_alerts.json (FAG-L0001...), live_quarantine.log
and live_triage.log (QL-/CL- IDs).

Formats:
  claude-code  Claude Code hook JSON (session_id, hook_event_name, tool_name,
               tool_input, cwd ...), mapped to the AgentGuard event schema.
  all others   the AgentGuard event schema itself (see schema.json). Native hook
               formats for those agents are not mapped yet.

New log sources (for example an agent built in-house) can be added from the
dashboard. Each one gets its own card, ingestion URL and connection status, and
its events are recorded under its own agent name. They are saved in
custom_sources.json.
"""

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AGENTGUARD_DIR", HERE)
TOKEN_PATH = os.path.join(DATA_DIR, "ingest_token.txt")
SOURCES_STATE = os.path.join(DATA_DIR, "sources_state.json")
LIVE_EVENTS = os.path.join(DATA_DIR, "live_events.ndjson")
LIVE_ALERTS = os.path.join(DATA_DIR, "live_alerts.json")
EVENT_TYPES = {"prompt", "file_read", "file_edit", "shell_command", "git_operation", "api_call"}
MAX_BATCH = 100

CONNECTORS = [
    {"id": "claude-code", "name": "Claude Code", "vendor": "Anthropic", "method": "Hooks",
     "agent": "claude-code", "format": "claude_code_hook", "initials": "CC", "color": "#c46a4a",
     "description": "Collects every tool call and prompt through Claude Code hooks."},
    {"id": "cursor", "name": "Cursor", "vendor": "Anysphere", "method": "Webhook (AgentGuard schema)",
     "agent": "cursor", "format": "native", "initials": "Cu", "color": "#3a3f4b",
     "description": "Send agent activity in the AgentGuard event schema."},
    {"id": "github-copilot", "name": "GitHub Copilot", "vendor": "GitHub", "method": "Webhook (AgentGuard schema)",
     "agent": "copilot", "format": "native", "initials": "GC", "color": "#3b6fd8",
     "description": "Send agent activity in the AgentGuard event schema."},
    {"id": "windsurf", "name": "Windsurf", "vendor": "Windsurf", "method": "Webhook (AgentGuard schema)",
     "agent": "windsurf", "format": "native", "initials": "Ws", "color": "#119b8a",
     "description": "Send agent activity in the AgentGuard event schema."},
    {"id": "gemini-cli", "name": "Gemini CLI", "vendor": "Google", "method": "Webhook (AgentGuard schema)",
     "agent": "gemini-cli", "format": "native", "initials": "Ge", "color": "#6b5fd6",
     "description": "Send agent activity in the AgentGuard event schema."},
    {"id": "custom", "name": "Custom webhook", "vendor": "Any agent", "method": "Webhook (AgentGuard schema)",
     "agent": None, "format": "native", "initials": "{ }", "color": "#5d6a85",
     "description": "Any agent or script that can send JSON. Include an agent field."},
]
BY_ID = {c["id"]: c for c in CONNECTORS}

# Log sources added from the dashboard (e.g. an agent built in-house).
CUSTOM_SOURCES = os.path.join(DATA_DIR, "custom_sources.json")
RESERVED_IDS = set(BY_ID) | {"add", "token", "test", "delete", "new", "api", "ingest"}
MAX_CUSTOM_SOURCES = 50
SOURCE_COLORS = ("#8a5a2b", "#2f7d4f", "#7a3e9d", "#b04a6a", "#2b6f8a", "#6b6b2b")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()&-]{1,59}")
_SOURCES_LOCK = threading.Lock()


class IngestError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def _load_custom():
    try:
        with open(CUSTOM_SOURCES) as f:
            data = json.load(f)
        return [c for c in data if isinstance(c, dict) and c.get("id")] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_custom(items):
    tmp = CUSTOM_SOURCES + ".tmp"
    with open(tmp, "w") as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, CUSTOM_SOURCES)


def _custom_connector(c):
    return {"id": c["id"], "name": c["name"], "vendor": "Internal", "method": "Webhook (AgentGuard schema)",
            "agent": c["id"], "format": "native", "initials": c["initials"], "color": c["color"],
            "description": c.get("description") or "Agent built in-house, onboarded from the dashboard.",
            "custom": True, "created_at": c.get("created_at")}


def all_connectors():
    return CONNECTORS + [_custom_connector(c) for c in _load_custom()]


def get_connector(connector_id):
    c = BY_ID.get(connector_id)
    if c:
        return c
    for x in _load_custom():
        if x["id"] == connector_id:
            return _custom_connector(x)
    return None


def _slug(name):
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")[:40]


def add_source(name, description=""):
    """Register a new log source (an in-house agent). Returns its connector card data."""
    name = re.sub(r"\s+", " ", str(name or "")).strip()
    if not _NAME_RE.fullmatch(name):
        raise IngestError("Give the agent a name of 2-60 characters: letters, numbers, spaces and . _ ( ) & -")
    description = re.sub(r"\s+", " ", str(description or "")).strip()[:160]
    sid = _slug(name)
    if len(sid) < 2:
        raise IngestError("The name needs at least two letters or numbers.")
    with _SOURCES_LOCK:
        items = _load_custom()
        if sid in BY_ID:
            raise IngestError(f"'{name}' is already a built-in log source.", 409)
        if sid in RESERVED_IDS:
            raise IngestError(f"'{name}' is a reserved word. Choose another name.", 409)
        if any(x["id"] == sid for x in items):
            raise IngestError(f"A log source called '{name}' already exists.", 409)
        if len(items) >= MAX_CUSTOM_SOURCES:
            raise IngestError(f"You can add up to {MAX_CUSTOM_SOURCES} log sources.", 409)
        words = re.findall(r"[A-Za-z0-9]+", name)
        initials = ((words[0][0] + words[1][0]) if len(words) > 1 else words[0][:2]).upper()
        item = {"id": sid, "name": name, "description": description, "initials": initials,
                "color": SOURCE_COLORS[len(items) % len(SOURCE_COLORS)], "created_at": _now()}
        items.append(item)
        _save_custom(items)
    return _custom_connector(item)


def remove_source(connector_id):
    """Remove a log source added from the dashboard. Built-in sources can't be removed."""
    if connector_id in BY_ID:
        raise IngestError("Built-in log sources can't be removed.", 409)
    with _SOURCES_LOCK:
        items = _load_custom()
        rest = [x for x in items if x["id"] != connector_id]
        if len(rest) == len(items):
            raise IngestError(f"Unknown log source: {connector_id}.", 404)
        _save_custom(rest)
    s = _load_state()
    if s.pop(connector_id, None) is not None:
        _save_state(s)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------
_TOKEN_LOCK = threading.Lock()


def get_token():
    env = os.environ.get("AGENTGUARD_TOKEN")
    if env:
        return env
    with _TOKEN_LOCK:
        try:
            with open(TOKEN_PATH) as f:
                tok = f.read().strip()
                if tok:
                    return tok
        except OSError:
            pass
        return _write_token()


def _write_token():
    tok = "fag_" + secrets.token_urlsafe(24)
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok)
    return tok


def rotate_token():
    if os.environ.get("AGENTGUARD_TOKEN"):
        raise IngestError("The token is set by the AGENTGUARD_TOKEN environment variable; change it there.", 409)
    with _TOKEN_LOCK:
        return _write_token()


def check_token(header):
    expected = get_token()
    m = re.fullmatch(r"Bearer\s+(\S+)", header or "")
    return bool(m) and secrets.compare_digest(m.group(1), expected)


def mask(tok):
    return tok[:4] + "•" * 14 + tok[-4:] if len(tok) > 8 else "•" * len(tok)


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------
def _text(v, limit=4000):
    if v is None:
        return ""
    if isinstance(v, str):
        return v[:limit]
    if isinstance(v, dict):
        for k in ("content", "text", "output", "stdout"):
            if isinstance(v.get(k), str):
                return v[k][:limit]
        if isinstance(v.get("file"), dict) and isinstance(v["file"].get("content"), str):
            return v["file"]["content"][:limit]
    return json.dumps(v)[:limit]


def _who(cwd):
    m = re.match(r"^(?:/Users|/home)/([^/]+)", cwd or "")
    return m.group(1) if m else "unknown"


def map_claude_code(body):
    """Claude Code hook JSON -> AgentGuard event. Returns None for tools we don't monitor."""
    if not isinstance(body, dict):
        raise IngestError("Expected a JSON object from the Claude Code hook.")
    hook = body.get("hook_event_name", "")
    cwd = str(body.get("cwd", ""))
    base = {"timestamp": _now(), "session_id": str(body.get("session_id") or "claude-code-session")[:120],
            "agent": "claude-code", "user": _who(cwd), "repo": os.path.basename(cwd.rstrip("/")) or "unknown"}

    if hook == "UserPromptSubmit":
        return {**base, "event_type": "prompt", "payload": {"text": _text(body.get("prompt")), "source": "user"}}

    tool = str(body.get("tool_name", ""))
    ti = body.get("tool_input") if isinstance(body.get("tool_input"), dict) else {}
    if tool == "Bash":
        cmd = str(ti.get("command", ""))[:4000]
        m = re.match(r"\s*git\s+(\S+)\s*(.*)", cmd)
        if m:
            return {**base, "event_type": "git_operation",
                    "payload": {"operation": "remote_add" if m.group(1) == "remote" and m.group(2).startswith("add")
                                else m.group(1), "detail": m.group(2)[:2000]}}
        return {**base, "event_type": "shell_command", "payload": {"command": cmd}}
    if tool == "Read":
        return {**base, "event_type": "file_read",
                "payload": {"path": str(ti.get("file_path", "")), "source": "file",
                            "text": _text(body.get("tool_response"))}}
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = str(ti.get("file_path") or ti.get("notebook_path") or "")
        diff = ti.get("new_string") or ti.get("content") or ti.get("new_source") or ""
        if tool == "MultiEdit" and isinstance(ti.get("edits"), list):
            diff = "\n".join(str(e.get("new_string", "")) for e in ti["edits"] if isinstance(e, dict))
        return {**base, "event_type": "file_edit", "payload": {"path": path, "diff": str(diff)[:4000]}}
    if tool == "WebFetch":
        return {**base, "event_type": "api_call",
                "payload": {"method": "GET", "url": str(ti.get("url", "")), "body_size": 0, "body_snippet": ""}}
    return None


def map_native(body, connector):
    """AgentGuard schema event (as in schema.json); fills what the sender left out."""
    if not isinstance(body, dict):
        raise IngestError("Each event must be a JSON object.")
    et = body.get("event_type")
    if et not in EVENT_TYPES:
        raise IngestError(f"event_type must be one of: {', '.join(sorted(EVENT_TYPES))}.")
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise IngestError("payload must be a JSON object.")
    agent = connector["agent"] or str(body.get("agent") or "")
    if not agent:
        raise IngestError("Custom webhook events need an agent field.")
    return {"timestamp": _now(), "session_id": str(body.get("session_id") or f"live-{connector['id']}")[:120],
            "agent": agent[:60], "user": str(body.get("user") or "unknown")[:60],
            "repo": str(body.get("repo") or "unknown")[:120], "event_type": et,
            "payload": {k: (v if isinstance(v, (int, float)) else str(v)[:4000]) for k, v in payload.items()}}


def to_events(connector_id, body):
    c = get_connector(connector_id)
    if not c:
        raise IngestError(f"Unknown log source: {connector_id}.", 404)
    items = body if isinstance(body, list) else [body]
    if len(items) > MAX_BATCH:
        raise IngestError(f"Send at most {MAX_BATCH} events per request.", 413)
    out, skipped = [], 0
    for item in items:
        ev = map_claude_code(item) if c["format"] == "claude_code_hook" else map_native(item, c)
        if ev is None:
            skipped += 1
        else:
            out.append(ev)
    return out, skipped


# ---------------------------------------------------------------------------
# Live pipeline
# ---------------------------------------------------------------------------
class LiveIngestor:
    def __init__(self):
        from engine import StreamingEngine
        from mini_soar import MiniSOAR
        self.lock = threading.Lock()
        try:
            with open(LIVE_ALERTS) as f:
                self.alerts = json.load(f)
        except (OSError, ValueError):
            self.alerts = []
        self.engine = StreamingEngine(os.path.join(HERE, "detections", "sigma"), prefix="FAG-L", start=len(self.alerts))
        self.soar = MiniSOAR(DATA_DIR, fresh=False, prefix="L",
                             quarantine_name="live_quarantine.log", triage_name="live_triage.log")
        self._rules_mtime = self._usecase_mtime()

    @staticmethod
    def _usecase_mtime():
        import usecases
        try:
            return os.path.getmtime(usecases.STATE_PATH)
        except OSError:
            return 0

    def ingest(self, events):
        from triage import classify
        raised = []
        with self.lock:
            m = self._usecase_mtime()
            if m != self._rules_mtime:          # a use case was enabled, disabled or promoted
                self.engine.reload_rules()
                self._rules_mtime = m
            with open(LIVE_EVENTS, "a") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
            for ev in events:
                for a in self.engine.process(ev):
                    classify(a)
                    self.soar.respond(a)
                    self.alerts.append(a)
                    raised.append({"alert_id": a["alert_id"], "rule_id": a["rule_id"],
                                   "severity": a["severity"], "verdict": a["triage"]["verdict"],
                                   "response": a["response_taken"]})
            tmp = LIVE_ALERTS + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.alerts, f, indent=2)
            os.replace(tmp, LIVE_ALERTS)
        return raised


_LIVE = None


def live():
    global _LIVE
    if _LIVE is None:
        _LIVE = LiveIngestor()
    return _LIVE


def ingest(connector_id, body):
    events, skipped = to_events(connector_id, body)
    raised = live().ingest(events) if events else []
    return {"accepted": len(events), "skipped": skipped, "alerts": raised}


# ---------------------------------------------------------------------------
# Test events and per-connector state
# ---------------------------------------------------------------------------
def _load_state():
    try:
        with open(SOURCES_STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(s):
    tmp = SOURCES_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, SOURCES_STATE)


def send_test_event(connector_id):
    c = get_connector(connector_id)
    if not c:
        raise IngestError(f"Unknown log source: {connector_id}.", 404)
    if c["format"] == "claude_code_hook":
        body = {"session_id": "test-claude-code", "hook_event_name": "PostToolUse", "tool_name": "Bash",
                "tool_input": {"command": "git status"}, "cwd": "/home/agentguard-test/payments-api"}
    else:
        body = {"event_type": "shell_command", "session_id": f"test-{connector_id}", "user": "agentguard-test",
                "repo": "payments-api", "payload": {"command": "git status"}}
        if not c["agent"]:
            body["agent"] = "custom-agent"
    result = ingest(connector_id, body)
    s = _load_state()
    s.setdefault(connector_id, {})["last_test_at"] = _now()
    _save_state(s)
    return result


def load_live_events():
    out = []
    try:
        with open(LIVE_EVENTS) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError:
        pass
    return out


def load_live_alerts():
    try:
        with open(LIVE_ALERTS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def setup_snippet(connector_id, url):
    c = get_connector(connector_id)
    if c["format"] == "claude_code_hook":
        cmd = (f"curl -s -X POST -H 'Authorization: Bearer '$AGENTGUARD_TOKEN "
               f"-H 'Content-Type: application/json' --data-binary @- {url}")
        hook = {"type": "command", "command": cmd}
        return {"file": "~/.claude/settings.json",
                "code": json.dumps({"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [hook]}],
                                              "UserPromptSubmit": [{"hooks": [hook]}]}}, indent=2)}
    example = {"event_type": "shell_command", "session_id": "sess-123", "user": "dev.sara", "repo": "payments-api",
               "payload": {"command": "pip install requests"}}
    if not c["agent"]:
        example = {"agent": "my-agent", **example}
    return {"file": "any HTTP client",
            "code": (f"curl -X POST {url} \\\n  -H 'Authorization: Bearer '$AGENTGUARD_TOKEN \\\n"
                     f"  -H 'Content-Type: application/json' \\\n  -d '{json.dumps(example)}'")}


FIELD_MAP = {
    "claude_code_hook": [
        ("session_id", "session_id"), ("hook_event_name: UserPromptSubmit, prompt", "event_type: prompt, payload.text"),
        ("tool_name: Bash, tool_input.command", "event_type: shell_command, payload.command"),
        ("tool_name: Bash with git …", "event_type: git_operation"),
        ("tool_name: Read, tool_input.file_path", "event_type: file_read, payload.path"),
        ("tool_name: Edit / Write / MultiEdit", "event_type: file_edit, payload.path, payload.diff"),
        ("tool_name: WebFetch, tool_input.url", "event_type: api_call, payload.url"),
        ("cwd", "repo (folder name), user (home folder)"),
    ],
    "native": [
        ("event_type", "event_type (prompt, file_read, file_edit, shell_command, git_operation, api_call)"),
        ("payload", "payload (same fields as schema.json)"),
        ("session_id, user, repo", "session_id, user, repo (optional)"),
        ("timestamp", "set by AgentGuard when the event arrives"),
    ],
}


def list_sources(dataset_events, base_url):
    """Connector cards with live statistics from dataset + live events."""
    events = list(dataset_events) + load_live_events()
    state = _load_state()
    by_agent = {}
    for e in events:
        by_agent.setdefault(e.get("agent"), []).append(e)
    connectors = all_connectors()
    known_agents = {c["agent"] for c in connectors if c["agent"]}
    out = []
    for c in connectors:
        evs = by_agent.get(c["agent"], []) if c["agent"] else [e for a, l in by_agent.items() if a not in known_agents for e in l]
        hours = {}
        for e in evs:
            hours[e["timestamp"][11:13]] = hours.get(e["timestamp"][11:13], 0) + 1
        url = f"{base_url}/ingest/v1/{c['id']}"
        out.append({**{k: c[k] for k in ("id", "name", "vendor", "method", "initials", "color", "description", "format")},
                    "custom": bool(c.get("custom")), "agent": c["agent"], "created_at": c.get("created_at"),
                    "connected": bool(evs) or bool(state.get(c["id"], {}).get("last_test_at")),
                    "events": len(evs), "sessions": len({e["session_id"] for e in evs}),
                    "last_event": max((e["timestamp"] for e in evs), default=None),
                    "last_test_at": state.get(c["id"], {}).get("last_test_at"),
                    "hourly": [hours.get(f"{h:02d}", 0) for h in range(24)],
                    "url": url, "setup": setup_snippet(c["id"], url), "field_map": FIELD_MAP[c["format"]]})
    return out
