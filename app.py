import os
import re
import json
import html
import time
import socket
import shutil
import ipaddress
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from pathlib import Path

import requests
from flask import Flask, request, jsonify, render_template, Response
try:
    from flask_cors import CORS
except Exception:  # pragma: no cover
    CORS = None
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "instance" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
if CORS:
    CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "*").split(",")}})

MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", "200000"))
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "45"))
MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() in {"1", "true", "yes"}
REQUIRE_AUTHORIZATION = os.getenv("REQUIRE_AUTHORIZATION", "true").lower() in {"1", "true", "yes"}
AUTHORIZED_HEADER = "X-OSINT-Authorized"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def authorized(payload=None):
    if not REQUIRE_AUTHORIZATION:
        return True
    if str(request.headers.get(AUTHORIZED_HEADER, "")).lower() in {"1", "true", "yes"}:
        return True
    if isinstance(payload, dict) and payload.get("authorized") is True:
        return True
    return False


def require_auth(payload=None):
    if not authorized(payload):
        return jsonify({"ok": False, "error": "Missing authorization confirmation. Confirm you have permission for this target."}), 403
    return None


def clip(text, limit=MAX_OUTPUT_BYTES):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[truncated at {limit} characters]"


def valid_username(value):
    return bool(USERNAME_RE.match((value or "").strip()))


def valid_email(value):
    return bool(EMAIL_RE.match((value or "").strip()))


def valid_google_target(value):
    value = (value or "").strip()
    return valid_email(value) or bool(re.match(r"^\d{21}$", value))


def valid_phone(value):
    digits = re.sub(r"[^0-9]", "", value or "")
    value = (value or "").strip()
    return value.startswith("+") and 7 <= len(digits) <= 18 and bool(re.match(r"^\+[0-9 ().-]+$", value))


def valid_domain(value):
    return bool(DOMAIN_RE.match((value or "").strip().lower()))


def url_hostname(value):
    try:
        parsed = urlparse((value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return parsed.hostname.lower()
    except Exception:
        return None


def valid_url(value):
    host = url_hostname(value)
    return bool(host and valid_domain(host))


def indicator_type(value):
    value = (value or "").strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except Exception:
        pass
    if valid_email(value):
        return "email"
    if HASH_RE.match(value):
        return "hash"
    if valid_url(value):
        return "url"
    if valid_domain(value):
        return "domain"
    return "unknown"


def classify_ip_risk(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"risk": "unknown", "reasons": ["invalid-ip"]}
    reasons = []
    risk = "low"
    if addr.is_private:
        reasons.append("private-or-rfc1918")
    if addr.is_loopback:
        reasons.append("loopback")
    if addr.is_multicast:
        reasons.append("multicast")
    if addr.is_reserved:
        reasons.append("reserved-range")
    if addr.version == 6:
        reasons.append("ipv6")
    if reasons:
        risk = "medium" if not addr.is_global else risk
    if addr.is_global:
        reasons.append("public-routable")
    return {"risk": risk, "reasons": reasons or ["public-routable"], "global": bool(addr.is_global)}


def dns_summary(name):
    try:
        infos = socket.getaddrinfo(name, None)
        addrs = sorted({i[4][0] for i in infos})[:20]
        return {"resolved": True, "addresses": addrs}
    except Exception as exc:
        return {"resolved": False, "error": str(exc)[:200]}


def external_threat_lookups(indicator, itype):
    results = {}
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    headers = {"User-Agent": "CyberAegis-Local-OSINT-Hub/1.0"}
    if vt_key and itype in {"domain", "url", "ip", "hash"}:
        try:
            if itype == "url":
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": vt_key, **headers}, timeout=20)
            elif itype == "hash":
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{indicator}", headers={"x-apikey": vt_key, **headers}, timeout=20)
            else:
                r = requests.get(f"https://www.virustotal.com/api/v3/{'ip_addresses' if itype == 'ip' else 'domains'}/{indicator}", headers={"x-apikey": vt_key, **headers}, timeout=20)
            if r.ok:
                data = r.json().get("data", {})
                attrs = data.get("attributes", {})
                results["virustotal"] = {
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "reputation": attrs.get("reputation"),
                    "tags": attrs.get("tags", [])[:20],
                }
            else:
                results["virustotal"] = {"error": f"HTTP {r.status_code}"}
        except Exception as exc:
            results["virustotal"] = {"error": str(exc)[:200]}
    if abuse_key and itype == "ip":
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json", **headers},
                params={"ipAddress": indicator, "maxAgeInDays": "90"},
                timeout=20,
            )
            if r.ok:
                d = r.json().get("data", {})
                results["abuseipdb"] = {
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "country_code": d.get("countryCode"),
                    "usage_type": d.get("usageType"),
                    "isp": d.get("isp"),
                    "total_reports": d.get("totalReports"),
                    "last_reported_at": d.get("lastReportedAt"),
                }
            else:
                results["abuseipdb"] = {"error": f"HTTP {r.status_code}"}
        except Exception as exc:
            results["abuseipdb"] = {"error": str(exc)[:200]}
    return results


def build_command(spec, value):
    return [part.format(value=value) for part in spec["cmd"]]


TOOL_SPECS = {
    "sherlock": {
        "name": "Sherlock",
        "group": "Username & People Search",
        "input": "username",
        "label": "Username",
        "placeholder": "e.g. johndoe",
        "validate": valid_username,
        "cmd": ["sherlock", "{value}", "--print-found", "--timeout", "10"],
        "timeout": 60,
        "hint": "Install: pipx install sherlock-project. Use only for accounts you own or are authorized to assess.",
    },
    "maigret": {
        "name": "Maigret",
        "group": "Username & People Search",
        "input": "username",
        "label": "Username",
        "placeholder": "e.g. johndoe",
        "validate": valid_username,
        "cmd": ["maigret", "{value}", "--print-found"],
        "timeout": 60,
        "hint": "Install: pipx install maigret. Keep request rates low and respect site terms.",
    },
    "whatsmyname": {
        "name": "WhatsMyName",
        "group": "Username & People Search",
        "input": "username",
        "label": "Username",
        "placeholder": "e.g. johndoe",
        "validate": valid_username,
        "cmd": ["whatsmyname", "-u", "{value}"],
        "timeout": 60,
        "hint": "Install the WhatsMyName CLI and keep its data file updated.",
    },
    "holehe": {
        "name": "Holehe",
        "group": "Email & Account Verification",
        "input": "email",
        "label": "Email",
        "placeholder": "name@example.com",
        "validate": valid_email,
        "cmd": ["holehe", "{value}", "--only-used", "--no-color"],
        "timeout": 45,
        "hint": "Install: pipx install holehe. Use only for email addresses you own or may test.",
    },
    "mosint": {
        "name": "MOSINT",
        "group": "Email & Account Verification",
        "input": "email",
        "label": "Email",
        "placeholder": "name@example.com",
        "validate": valid_email,
        "cmd": ["mosint", "{value}"],
        "timeout": 45,
        "hint": "Install MOSINT and configure its keys in that tool's own config file.",
    },
    "ghunt": {
        "name": "GHunt",
        "group": "Email & Account Verification",
        "input": "google",
        "label": "Google email / Gaia ID",
        "placeholder": "name@gmail.com or 21-digit Gaia ID",
        "validate": valid_google_target,
        "cmd": ["ghunt", "email", "{value}"],
        "timeout": 60,
        "hint": "Install and authenticate GHunt separately. Use only on your own account or with consent.",
    },
    "phoneinfoga": {
        "name": "PhoneInfoga",
        "group": "Phone Number Intelligence",
        "input": "phone",
        "label": "Phone (E.164)",
        "placeholder": "+14155552671",
        "validate": valid_phone,
        "cmd": ["phoneinfoga", "scan", "-n", "{value}", "-s", "numverify,local"],
        "timeout": 60,
        "hint": "Install: see PhoneInfoga docs. Validate numbers you own or are permitted to investigate.",
    },
    "theharvester": {
        "name": "TheHarvester",
        "group": "Domain & Subdomain Recon",
        "input": "domain",
        "label": "Domain",
        "placeholder": "example.com",
        "validate": valid_domain,
        "cmd": ["theHarvester", "-d", "{value}", "-b", "crtsh,bing", "-l", "200"],
        "timeout": 90,
        "hint": "Install: pipx install theHarvester. Passive sources only by default.",
    },
    "sublist3r": {
        "name": "Sublist3r",
        "group": "Domain & Subdomain Recon",
        "input": "domain",
        "label": "Domain",
        "placeholder": "example.com",
        "validate": valid_domain,
        "cmd": ["sublist3r", "-d", "{value}", "-t", "20"],
        "timeout": 90,
        "hint": "Install: pipx install sublist3r. Use passive enumeration for authorized assets.",
    },
    "amass": {
        "name": "Amass",
        "group": "Domain & Subdomain Recon",
        "input": "domain",
        "label": "Domain",
        "placeholder": "example.com",
        "validate": valid_domain,
        "cmd": ["amass", "enum", "-passive", "-d", "{value}"],
        "timeout": 180,
        "hint": "Install Amass and keep its config data sources updated. Passive mode is enabled.",
    },
    "photon": {
        "name": "Photon",
        "group": "URL & Web Recon",
        "input": "url",
        "label": "URL",
        "placeholder": "https://example.com",
        "validate": valid_url,
        "cmd": ["photon", "-u", "{value}", "--dns", "--keys"],
        "timeout": 120,
        "hint": "Install Photon. Crawl only assets you are authorized to test.",
    },
    "whatweb": {
        "name": "WhatWeb",
        "group": "Web Tech & WAF Detection",
        "input": "url",
        "label": "URL",
        "placeholder": "https://example.com",
        "validate": valid_url,
        "cmd": ["whatweb", "{value}", "--color=never"],
        "timeout": 45,
        "hint": "Install WhatWeb. Fingerprint only authorized targets.",
    },
    "wafw00f": {
        "name": "WafW00F",
        "group": "Web Tech & WAF Detection",
        "input": "url",
        "label": "URL",
        "placeholder": "https://example.com",
        "validate": valid_url,
        "cmd": ["wafw00f", "{value}", "-a"],
        "timeout": 45,
        "hint": "Install: pipx install wafw00f. Detection only; no evasion or bypass.",
    },
}


def executable_for(cmd):
    exe = cmd[0]
    if os.sep in exe or (os.altsep and os.altsep in exe):
        return exe if os.path.exists(exe) else None
    return shutil.which(exe)


def mock_tool_result(tool, value):
    spec = TOOL_SPECS[tool]
    return {
        "ok": True,
        "mock": True,
        "tool": tool,
        "name": spec["name"],
        "input": value,
        "started_at": utc_now(),
        "duration": 0.12,
        "returncode": 0,
        "stdout": f"[MOCK MODE] {spec['name']} completed for {value}.\nSet MOCK_MODE=false and install the tool to run live commands.",
        "stderr": "",
        "hint": spec["hint"],
        "authorization": "Local mock only. Confirm written authorization before live testing.",
    }


def run_tool(tool, value):
    spec = TOOL_SPECS.get(tool)
    if not spec:
        return {"ok": False, "error": f"Unknown tool: {tool}", "available": sorted(TOOL_SPECS)}, 404
    if not spec["validate"](value):
        return {"ok": False, "error": f"Invalid {spec['label'].lower()} value", "hint": spec["hint"]}, 400

    value = value.strip()
    if MOCK_MODE:
        return mock_tool_result(tool, value), 200

    cmd = build_command(spec, value)
    exe = executable_for(cmd)
    if not exe:
        return {
            "ok": False,
            "error": f"Executable not found: {cmd[0]}",
            "install_hint": spec["hint"],
            "cmd_preview": cmd,
        }, 404

    started = time.time()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=spec.get("timeout", TOOL_TIMEOUT),
            env=env,
            cwd=str(BASE_DIR),
        )
        duration = round(time.time() - started, 3)
        return {
            "ok": proc.returncode == 0,
            "tool": tool,
            "name": spec["name"],
            "group": spec["group"],
            "input": value,
            "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
            "duration": duration,
            "returncode": proc.returncode,
            "cmd_preview": cmd,
            "stdout": clip(proc.stdout),
            "stderr": clip(proc.stderr),
            "hint": spec["hint"],
        }, 200 if proc.returncode == 0 else 500
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "tool": tool,
            "name": spec["name"],
            "input": value,
            "error": f"Timeout after {spec.get('timeout', TOOL_TIMEOUT)}s",
            "stdout": clip(exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""),
            "stderr": clip(exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""),
            "hint": "Increase TOOL_TIMEOUT, reduce scope, or verify the target/tool is responsive.",
        }, 504
    except Exception as exc:
        return {"ok": False, "tool": tool, "error": f"{type(exc).__name__}: {exc}", "hint": spec["hint"]}, 500


def extract_targets(message):
    text = message or ""
    targets = {"domains": sorted(set(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text)))[:20], "emails": sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))[:20], "ips": [], "phones": sorted(set(re.findall(r"\+[0-9][0-9 ().-]{6,25}", text)))[:20]}
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(token)
            targets["ips"].append(token)
        except Exception:
            pass
    targets["ips"] = sorted(set(targets["ips"]))[:20]
    return targets


def local_ai_answer(message, context=None):
    msg = (message or "").strip()
    lower = msg.lower()
    targets = extract_targets(msg)
    bullets = []
    if any(k in lower for k in ["phish", "credential", "password", "login"]):
        bullets += [
            "Preserve headers/artifacts, disable compromised accounts, reset exposed credentials, and force MFA re-enrollment.",
            "Search mailbox rules, OAuth grants, sign-in logs, and forwarding settings for persistence.",
        ]
    if any(k in lower for k in ["ransom", "encrypt", "extort"]):
        bullets += [
            "Isolate impacted hosts, preserve volatile evidence, identify the ransomware family, and check backups/offline copies.",
            "Do not pay from production networks; engage legal/insurance/IR teams and document every action.",
        ]
    if any(k in lower for k in ["s3", "bucket", "cloud", "exposed"]):
        bullets += ["Validate exposure with read-only checks, rotate keys, tighten bucket policies, and add guardrails/alerts for public resources."]
    if any(k in lower for k in ["domain", "subdomain", "recon", "osint"]):
        bullets += ["Use passive sources first, maintain scope authorization, deduplicate assets, and map findings to owners and business criticality."]
    if any(k in lower for k in ["waf", "firewall", "blocked"]):
        bullets += ["Treat WAF output as detection telemetry only. Test with benign canary requests and confirm rules with the asset owner."]
    if not bullets:
        bullets += [
            "Define scope and written authorization before any active check.",
            "Start passive, keep evidence timestamps, minimize collected personal data, and track every command.",
            "Convert findings into owner, severity, remediation, and verification steps.",
        ]
    return {
        "provider": "local-rules",
        "answer": "Defensive analysis guidance",
        "targets": targets,
        "recommendations": bullets[:8],
        "safety": "Use only on systems you own or are explicitly authorized to assess. Avoid intrusive exploitation, credential attacks, and data exfiltration.",
        "timestamp": utc_now(),
        "context_received": bool(context),
    }


def call_remote_llm(message):
    base = os.getenv("AI_API_BASE", "").rstrip("/")
    key = os.getenv("AI_API_KEY")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    if not base or not key:
        return None
    try:
        r = requests.post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "system", "content": "You are a defensive cybersecurity assistant. Refuse harmful, intrusive, or unauthorized activity."}, {"role": "user", "content": message}], "temperature": 0.2},
            timeout=int(os.getenv("AI_TIMEOUT", "45")),
        )
        if r.ok:
            content = r.json()["choices"][0]["message"]["content"]
            return {"provider": model, "answer": content, "timestamp": utc_now()}
        return {"provider": model, "error": f"LLM HTTP {r.status_code}", "fallback": local_ai_answer(message)}
    except Exception as exc:
        return {"provider": model, "error": str(exc)[:300], "fallback": local_ai_answer(message)}


SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def norm_severity(value):
    v = str(value or "info").lower()
    return v if v in SEVERITY_WEIGHT else "info"


def analytics_from_findings(findings):
    normalized = []
    for f in findings[:5000]:
        if not isinstance(f, dict):
            continue
        item = {
            "type": str(f.get("type", "unknown"))[:60],
            "value": str(f.get("value", ""))[:300],
            "source": str(f.get("source", "manual"))[:80],
            "severity": norm_severity(f.get("severity")),
            "target": str(f.get("target", f.get("value", "")))[:300],
            "timestamp": str(f.get("timestamp", utc_now()))[:60],
        }
        normalized.append(item)
    stats = {"total": len(normalized), "by_type": {}, "by_source": {}, "by_severity": {s: 0 for s in SEVERITY_ORDER}}
    ids = {}
    nodes = []
    for i, item in enumerate(normalized):
        stats["by_type"][item["type"]] = stats["by_type"].get(item["type"], 0) + 1
        stats["by_source"][item["source"]] = stats["by_source"].get(item["source"], 0) + 1
        stats["by_severity"][item["severity"]] += 1
        ids[(item["target"], item["type"], item["value"])] = i
        nodes.append({"id": i, "label": item["value"] or item["type"], "type": item["type"], "severity": item["severity"], "source": item["source"]})
    max_possible = max(1, len(normalized) * SEVERITY_WEIGHT["high"])
    raw = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in normalized)
    risk_score = min(100, round((raw / max_possible) * 100, 1))
    links = []
    seen = set()
    for i in range(len(normalized)):
        for j in range(i + 1, len(normalized)):
            a, b = normalized[i], normalized[j]
            shared = None
            if a["target"] and a["target"] == b["target"]:
                shared = "target"
            elif a["value"] and a["value"] == b["value"]:
                shared = "value"
            elif a["source"] and a["source"] == b["source"] and a["type"] == b["type"]:
                shared = "source-type"
            if shared and (i, j) not in seen:
                seen.add((i, j))
                links.append({"source": i, "target": j, "relation": shared})
    return {
        "ok": True,
        "generated_at": utc_now(),
        "stats": stats,
        "risk": {
            "score": risk_score,
            "band": "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 35 else "low",
            "method": "weighted finding severity normalized to a 0-100 defensive risk index",
        },
        "graph": {"nodes": nodes[:1000], "links": links[:3000]},
        "findings": normalized[:1000],
    }


def render_report(fmt, title, payload):
    analytics = payload.get("analytics") or {}
    stats = analytics.get("stats", {})
    risk = analytics.get("risk", {})
    findings = analytics.get("findings", payload.get("findings", []))[:1000]
    threat = payload.get("threat") or {}
    lines = []
    if fmt == "json":
        return json.dumps({"title": title, "generated_at": utc_now(), "threat": threat, "analytics": analytics}, indent=2, ensure_ascii=False)
    lines.append(f"# {title}")
    lines.append(f"Generated: {utc_now()}")
    lines.append("Scope: Authorized defensive assessment only")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Findings: {stats.get('total', len(findings))}")
    lines.append(f"- Risk index: {risk.get('score', 0)}/100 ({risk.get('band', 'unknown')})")
    lines.append(f"- Severities: {json.dumps(stats.get('by_severity', {}), sort_keys=True)}")
    lines.append("")
    lines.append("## Threat Intelligence")
    lines.append("```json")
    lines.append(json.dumps(threat, indent=2, ensure_ascii=False)[:8000])
    lines.append("```")
    lines.append("")
    lines.append("## Top Findings")
    for f in findings[:100]:
        lines.append(f"- [{f.get('severity','info').upper()}] {f.get('type','unknown')}: {f.get('value','')} (source: {f.get('source','manual')})")
    if fmt == "txt":
        return "\n".join(lines)
    rows = "".join(f"<tr><td>{html.escape(str(f.get('severity','info')))}</td><td>{html.escape(str(f.get('type','unknown')))}</td><td>{html.escape(str(f.get('value','')))}</td><td>{html.escape(str(f.get('source','manual')))}</td></tr>" for f in findings[:500])
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>
<style>body{{font-family:Arial,sans-serif;margin:2rem;color:#111827}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d1d5db;padding:6px}}th{{background:#f3f4f6}}.risk{{font-size:1.2rem;font-weight:700}}</style></head><body>
<h1>{html.escape(title)}</h1><p>Generated: {utc_now()}</p><p>Scope: Authorized defensive assessment only</p>
<p class='risk'>Risk index: {html.escape(str(risk.get('score', 0)))}/100 ({html.escape(str(risk.get('band', 'unknown')))})</p>
<h2>Threat Intelligence</h2><pre>{html.escape(json.dumps(threat, indent=2, ensure_ascii=False)[:12000])}</pre>
<h2>Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th></tr>{rows}</table>
</body></html>"""


@app.get("/")
def index():
    return render_template("index.html", tools=TOOL_SPECS, mock_mode=MOCK_MODE, require_authorization=REQUIRE_AUTHORIZATION)


@app.get("/api/health")
def health():
    return {"ok": True, "mock_mode": MOCK_MODE, "authorization_required": REQUIRE_AUTHORIZATION, "time": utc_now()}


@app.post("/api/tool/<tool>")
def tool(tool):
    payload = request.get_json(silent=True) or {}
    auth_error = require_auth(payload)
    if auth_error:
        return auth_error
    value = str(payload.get("value", ""))
    body, status = run_tool(tool, value)
    body["request_id"] = f"{int(time.time())}-{client_ip()}"
    return jsonify(body), status


@app.post("/api/ai")
def ai():
    payload = request.get_json(silent=True) or {}
    auth_error = require_auth(payload)
    if auth_error:
        return auth_error
    message = str(payload.get("message", "")).strip()
    if not message or len(message) > 8000:
        return jsonify({"ok": False, "error": "message must be 1-8000 characters"}), 400
    remote = call_remote_llm(message)
    result = remote if remote and "answer" in remote else local_ai_answer(message, payload.get("context"))
    result["ok"] = True
    result["message_received_chars"] = len(message)
    return jsonify(result)


@app.post("/api/threat")
def threat():
    payload = request.get_json(silent=True) or {}
    auth_error = require_auth(payload)
    if auth_error:
        return auth_error
    indicator = str(payload.get("indicator", "")).strip()
    itype = indicator_type(indicator)
    if itype == "unknown":
        return jsonify({"ok": False, "error": "Provide a valid IP, domain, URL, email, or hash indicator."}), 400
    if itype == "email":
        domain = indicator.split("@", 1)[-1]
        checks = {"mx_dns": dns_summary(domain), "external": external_threat_lookups(indicator, itype)}
        risk = "medium" if checks["mx_dns"].get("resolved") else "low"
    elif itype == "ip":
        checks = {"ip": classify_ip_risk(indicator), "ptr": None, "external": external_threat_lookups(indicator, itype)}
        try:
            checks["ptr"] = socket.gethostbyaddr(indicator)[0]
        except Exception:
            checks["ptr"] = None
        risk = checks["ip"]["risk"]
        ext = checks["external"].get("virustotal", {}).get("last_analysis_stats", {})
        if ext.get("malicious", 0) >= 3 or checks["external"].get("abuseipdb", {}).get("abuse_confidence_score", 0) >= 50:
            risk = "high"
    else:
        host = url_hostname(indicator) if itype == "url" else indicator
        checks = {"dns": dns_summary(host), "external": external_threat_lookups(indicator, itype)}
        risk = "medium" if checks["dns"].get("resolved") else "low"
        ext = checks["external"].get("virustotal", {}).get("last_analysis_stats", {})
        if ext.get("malicious", 0) >= 3:
            risk = "high"
    return jsonify({"ok": True, "indicator": indicator, "type": itype, "risk": risk, "checks": checks, "generated_at": utc_now()})


@app.post("/api/analytics")
def analytics():
    payload = request.get_json(silent=True) or {}
    auth_error = require_auth(payload)
    if auth_error:
        return auth_error
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        return jsonify({"ok": False, "error": "findings must be a list"}), 400
    return jsonify(analytics_from_findings(findings))


@app.post("/api/report")
def report():
    payload = request.get_json(silent=True) or {}
    auth_error = require_auth(payload)
    if auth_error:
        return auth_error
    fmt = str(payload.get("format", "html")).lower()
    if fmt not in {"html", "json", "txt"}:
        return jsonify({"ok": False, "error": "format must be html, json, or txt"}), 400
    title = str(payload.get("title", "Cyber Intelligence Report"))[:140] or "Cyber Intelligence Report"
    content = render_report(fmt, title, payload)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-").lower() or "cyber-intelligence-report"
    filename = f"{slug}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.{fmt}"
    path = REPORT_DIR / filename
    path.write_text(content, encoding="utf-8")
    mime = {"html": "text/html", "json": "application/json", "txt": "text/plain"}[fmt]
    return jsonify({"ok": True, "filename": filename, "mime": mime, "content": content, "saved_to": str(path)})


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true"})
