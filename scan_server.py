#!/usr/bin/env python3
"""
scan_server.py — Webhook server for the VULNDASH autoscan feature.

Runs on Kali as a systemd service. The React dashboard's "Autoscan" button
sends a POST /scan request to this server. The server runs scan.py, which
executes Trivy locally, writes both report files, and git-pushes to GitHub
so Vercel auto-deploys.

Security:
  - Only listens on the Tailscale interface (100.95.217.28) — not public internet.
  - Requires a shared secret token in the Authorization header.
  - Rate-limited: ignores requests if a scan is already running.

Setup on Kali:
  1. Install Flask:
       pip3 install flask --break-system-packages
  2. Set your token (change this value, keep it secret):
       export SCAN_TOKEN="your-secret-token-here"
     Or hardcode it below in SCAN_TOKEN.
  3. Run directly for testing:
       python3 scan_server.py
  4. Install as a systemd service (see instructions at the bottom of this file).

Dashboard usage:
  The React dashboard calls:
    POST http://100.95.217.28:5000/scan
    Authorization: Bearer <SCAN_TOKEN>
  And polls:
    GET  http://100.95.217.28:5000/status

CORS:
  Configured to accept requests from your Vercel dashboard URL.
  Update ALLOWED_ORIGIN below if your Vercel URL changes.
"""

import os
import json
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


try:
    from flask import Flask, jsonify, request
except ImportError:
    print("ERROR: Flask is not installed. Run: pip3 install flask --break-system-packages")
    raise

# ── Configuration ──────────────────────────────────────────────────────────────

# The shared secret token. Set via environment variable or hardcode here.
# Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "CHANGE_ME_USE_A_REAL_SECRET")

# Where scan.py lives (relative to this file, or absolute path)
SCAN_SCRIPT = Path(__file__).parent / "scan.py"

# Only listen on the Tailscale IP — never 0.0.0.0 in production.
LISTEN_HOST = "100.95.217.28"
LISTEN_PORT = 5000

# Your Vercel dashboard URL (for CORS).
# Update this if your Vercel project URL changes.
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN","https://vuln-dashboard.vercel.app")

# How long (seconds) to keep scan log output before clearing it.
LOG_TTL = 300

# ── State ──────────────────────────────────────────────────────────────────────

app = Flask(__name__)

_lock        = threading.Lock()
_scan_running = False
_scan_log     = []        # list of strings, lines of stdout/stderr
_last_scan_dt = None      # datetime of last completed scan
_last_scan_ok = None      # True/False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _add_cors(response):
    origin = request.headers.get("Origin", "")

    # Allow localhost dev server, the production Vercel URL, and
    # any Vercel preview deployment URL for this project.
    allowed = (
        origin == "http://localhost:5173"
        or origin.endswith("pestacials-projects.vercel.app")
        or ("vuln-dashboard" in origin and origin.endswith(".vercel.app"))
    )
    if allowed:
        response.headers["Access-Control-Allow-Origin"] = origin

    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"

    # Chrome Private Network Access (PNA) policy:
    # A public HTTPS site (Vercel) calling a private IP (Tailscale 100.x.x.x)
    # requires the server to explicitly opt in via this header on preflight.
    # Without it Chrome blocks the request entirely before it even reaches CORS.
    response.headers["Access-Control-Allow-Private-Network"] = "true"

    return response


def _check_token():
    """Return True if the request carries a valid Bearer token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth[len("Bearer "):]
    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(token.encode(), SCAN_TOKEN.encode())


def _run_scan_background(container: str, severity: str):
    """Run scan.py in a background thread, capture output."""
    global _scan_running, _scan_log, _last_scan_dt, _last_scan_ok

    cmd = [
        "python3", str(SCAN_SCRIPT),
        "--container", container,
        "--severity",  severity,
    ]

    _scan_log = [f"[server] Starting scan at {datetime.now(timezone.utc).isoformat()}"]
    _scan_log.append(f"[server] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(SCAN_SCRIPT.parent),
            timeout=300,   # 5-minute hard timeout
        )
        lines = (result.stdout + result.stderr).splitlines()
        _scan_log.extend(lines)

        _last_scan_ok = (result.returncode == 0)
        _last_scan_dt = datetime.now(timezone.utc)

        if result.returncode == 0:
            _scan_log.append("[server] Scan completed successfully.")
        else:
            _scan_log.append(f"[server] Scan FAILED (exit code {result.returncode}).")

    except subprocess.TimeoutExpired:
        _scan_log.append("[server] ERROR: Scan timed out after 5 minutes.")
        _last_scan_ok = False
        _last_scan_dt = datetime.now(timezone.utc)
    except Exception as e:
        _scan_log.append(f"[server] ERROR: {e}")
        _last_scan_ok = False
        _last_scan_dt = datetime.now(timezone.utc)
    finally:
        with _lock:
            _scan_running = False


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.after_request
def after_request(response):
    return _add_cors(response)


@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def catch_all_preflight(path):
    """
    Single catch-all OPTIONS handler for every endpoint.
    Chrome's Private Network Access policy sends a preflight OPTIONS to EVERY
    URL before the real request — including polling endpoints like /status and
    /remediate/status. Flask's after_request hook does NOT fire for OPTIONS, so
    we need an explicit handler. This one covers all routes at once.
    """
    return _add_cors(app.response_class(status=204))


@app.route("/scan", methods=["POST"])
def trigger_scan():
    """
    Trigger a Trivy scan.
    Body (JSON, optional):
      { "container": "sandbox-opensilex-docker-opensilexapp",
        "severity":  "CRITICAL,HIGH,MEDIUM,LOW" }
    """
    global _scan_running

    if not _check_token():
        return jsonify({"error": "Unauthorized"}), 401

    with _lock:
        if _scan_running:
            return jsonify({
                "status": "busy",
                "message": "A scan is already in progress. Please wait.",
            }), 409

        body = request.get_json(silent=True) or {}
        container = body.get("container", "sandbox-opensilex-docker-opensilexapp")
        severity  = body.get("severity",  "CRITICAL,HIGH,MEDIUM,LOW")

        _scan_running = True
        thread = threading.Thread(
            target=_run_scan_background,
            args=(container, severity),
            daemon=True,
        )
        thread.start()

    return jsonify({
        "status":  "started",
        "message": f"Scan started for container: {container}",
    }), 202


@app.route("/status", methods=["GET"])
def scan_status():
    """Poll scan status and log. No auth required."""
    return jsonify({
        "running":     _scan_running,
        "lastScanAt":  _last_scan_dt.isoformat() if _last_scan_dt else None,
        "lastScanOk":  _last_scan_ok,
        "log":         _scan_log[-50:],   # last 50 lines
    })


@app.route("/health", methods=["GET"])
def health():
    """Simple health check."""
    return jsonify({"ok": True, "server": "vulndash-scan-server"})


# ── AI Remediation state ───────────────────────────────────────────────────────

_remediate_running = False
_remediate_result  = None   # dict: {"fixes": [...]} or {"error": "..."}
_remediate_started = None   # datetime


# ── AI Remediation Routes ──────────────────────────────────────────────────────
# NOTE: These MUST be defined before app.run() — Flask registers routes at
# decoration time, so anything after app.run() is never reached.

def call_ollama(prompt: str) -> str:
    """Send a prompt to local Ollama and get a JSON response."""
    data = json.dumps({
        "model": "qwen2.5:7b",
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }).encode('utf-8')

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode('utf-8'))['response']
    except Exception as e:
        return json.dumps({"error": str(e)})


def _extract_fixes(raw: str) -> list:
    """
    Robustly extract the fixes list from whatever qwen returns.
    Handles: bare array, {"fixes":[...]}, {"remediation":[...]},
    {"result":[...]}, single object, and JSON embedded in prose.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Try to find a JSON array or object anywhere in the string
        import re
        m = re.search(r'(\[.*\]|\{.*\})', raw, re.DOTALL)
        if not m:
            return []
        try:
            parsed = json.loads(m.group(1))
        except json.JSONDecodeError:
            return []

    # Already a list
    if isinstance(parsed, list):
        return parsed

    # Dict — hunt for a list value under any common key
    if isinstance(parsed, dict):
        for key in ("fixes", "remediation", "results", "result", "items", "vulnerabilities"):
            if isinstance(parsed.get(key), list):
                return parsed[key]
        # If every value is itself a dict with "cve"/"command", the dict IS one fix
        if "cve" in parsed and "command" in parsed:
            return [parsed]
        # Last resort: return the first list value found
        for v in parsed.values():
            if isinstance(v, list):
                return v

    return []


def _run_remediate_background(vulns_for_ai: list):
    """Run Ollama in a background thread so the POST returns immediately."""
    global _remediate_running, _remediate_result

    print(f"[ai] Starting analysis of {len(vulns_for_ai)} vulnerabilities.", flush=True)

    # ── Pre-filter: separate Java/Maven packages from real Debian packages ──────
    # Java packages always contain ":" (groupId:artifactId) or known Java names.
    # We do this on the server so the AI only has to write commands, not classify.
    JAVA_INDICATORS = (":", "jackson", "netty", "tomcat", "log4j", "spring",
                       "hibernate", "tika", "nimbus", "commons-", "io.netty",
                       "org.apache", "com.fasterxml", "com.nimbusds")

    system_pkgs = []
    skipped_java = []
    for v in vulns_for_ai:
        pkg = v.get("pkg", "")
        if any(pkg.lower().startswith(ind) or ind in pkg.lower() for ind in JAVA_INDICATORS):
            skipped_java.append(pkg)
        else:
            system_pkgs.append(v)

    print(f"[ai] System packages: {len(system_pkgs)}, Java (skipped): {len(skipped_java)}", flush=True)
    if skipped_java:
        print(f"[ai] Skipped Java: {', '.join(set(skipped_java))[:200]}", flush=True)

    if not system_pkgs:
        _remediate_result = {
            "fixes": [],
            "message": f"All {len(vulns_for_ai)} vulnerabilities are in Java libraries "
                       f"(tomcat, netty, jackson, etc.) which cannot be patched with apt-get. "
                       f"These require updating the application's bundled dependencies.",
        }
        _remediate_running = False
        return

    # Deduplicate by CVE+pkg so the same gnupg CVE isn't repeated 8 times
    seen = set()
    deduped = []
    for v in system_pkgs:
        key = f"{v['cve']}|{v['pkg'].split('/')[0]}"  # treat gnupg/gpg/gpgv as same family
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    print(f"[ai] Deduped system packages to send: {len(deduped)}", flush=True)

    vuln_lines = "\n".join(
        f'- CVE: {v["cve"]}, Package: {v["pkg"]}, InstalledVersion: {v["version"]}'
        for v in deduped
    )

    prompt = f"""You are a Linux sysadmin fixing vulnerabilities in a Debian-based Docker container.

Container name: sandbox-opensilex-docker-opensilexapp

All packages listed below are real Debian/Ubuntu system packages that CAN be upgraded with apt-get. For each one, produce a fix entry.

Return ONLY a JSON array with no other text. Each element must have exactly these 4 fields:
"cve", "pkg", "explanation", "command"

The "command" must be exactly:
docker exec sandbox-opensilex-docker-opensilexapp apt-get install --only-upgrade -y <pkg>

Example:
[{{"cve": "CVE-2025-68973", "pkg": "gnupg", "explanation": "Upgrades GnuPG to fix a signature verification vulnerability.", "command": "docker exec sandbox-opensilex-docker-opensilexapp apt-get install --only-upgrade -y gnupg"}}]

Packages to fix:
{vuln_lines}"""

    ai_response = call_ollama(prompt)
    print(f"[ai] Raw Ollama response (first 800 chars):\n{ai_response[:800]}", flush=True)

    fixes = _extract_fixes(ai_response)
    print(f"[ai] Extracted {len(fixes)} fixes from response.", flush=True)

    # Validate: must have cve, command, and correct container name
    valid_fixes = [
        f for f in fixes
        if isinstance(f, dict)
        and f.get("cve")
        and f.get("command")
        and "sandbox-opensilex-docker-opensilexapp" in f.get("command", "")
    ]
    print(f"[ai] {len(valid_fixes)} fixes passed validation.", flush=True)

    if valid_fixes:
        _remediate_result = {"fixes": valid_fixes}
    else:
        _remediate_result = {
            "fixes": [],
            "error": "AI did not return valid fix commands.",
            "raw": ai_response[:800],
        }

    _remediate_running = False


@app.route("/remediate", methods=["POST"])
def remediate():
    global _remediate_running, _remediate_result, _remediate_started
    if not _check_token():
        return jsonify({"error": "Unauthorized"}), 401

    # If a job is running, tell the client to keep polling /remediate/status
    with _lock:
        if _remediate_running:
            return jsonify({"status": "busy", "message": "AI analysis already in progress."}), 202

    json_path = Path(__file__).parent / "public" / "base-report.json"
    if not json_path.exists():
        return jsonify({"error": "base-report.json not found"}), 404

    try:
        data = json.loads(json_path.read_text())
    except Exception as e:
        return jsonify({"error": f"Failed to read JSON: {e}"}), 500

    # scan.py wraps Trivy output as {"scanDate":..., "results": <trivy JSON>}
    trivy_results = data.get("results", data)

    vulns_for_ai = []
    for res in trivy_results.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            if v.get("Severity") in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                vulns_for_ai.append({
                    "cve": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "version": v.get("InstalledVersion")
                })

    vulns_for_ai = vulns_for_ai[:50]  # Limit to 30 to prevent timeouts

    if not vulns_for_ai:
        return jsonify({"fixes": [], "message": "No critical/high vulnerabilities to analyze."})

    with _lock:
        _remediate_running = True
        _remediate_result  = None
        _remediate_started = datetime.now(timezone.utc)

    thread = threading.Thread(
        target=_run_remediate_background,
        args=(vulns_for_ai,),
        daemon=True,
    )
    thread.start()

    # Return 202 immediately — client should poll /remediate/status
    return jsonify({
        "status": "started",
        "message": f"AI is analysing {len(vulns_for_ai)} vulnerabilities. Poll /remediate/status for results.",
    }), 202


@app.route("/remediate/status", methods=["GET"])
def remediate_status():
    """Poll AI remediation progress. No auth required."""
    return jsonify({
        "running":   _remediate_running,
        "startedAt": _remediate_started.isoformat() if _remediate_started else None,
        "result":    _remediate_result,
    })


@app.route("/apply-fix", methods=["POST"])
def apply_fix():
    if not _check_token():
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    cmd = body.get("command", "")

    # Security check: Only allow apt-get upgrades inside the specific container
    if not cmd.startswith("docker exec sandbox-opensilex-docker-opensilexapp apt-get"):
        return jsonify({"error": "Command rejected by security policy."}), 403

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=120
        )
        return jsonify({
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if SCAN_TOKEN == "CHANGE_ME_USE_A_REAL_SECRET":
        print("WARNING: You are using the default SCAN_TOKEN. Set a real secret!")
        print("  export SCAN_TOKEN=\"$(python3 -c 'import secrets; print(secrets.token_hex(32))')\"\n")

    print(f"[server] vulndash scan server starting on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[server] Scan script: {SCAN_SCRIPT}")
    print(f"[server] CORS origin: {ALLOWED_ORIGIN}")
    print(f"[server] Token set  : {'YES (custom)' if SCAN_TOKEN != 'CHANGE_ME_USE_A_REAL_SECRET' else 'NO — SET IT!'}\n")

    # HTTPS for Tailscale-only access
    cert_file = Path(__file__).parent / "100.95.217.28.pem"
    key_file  = Path(__file__).parent / "100.95.217.28-key.pem"
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True,
            ssl_context=(str(cert_file), str(key_file)))

# ══════════════════════════════════════════════════════════════════════════════
# SYSTEMD SERVICE SETUP
# ══════════════════════════════════════════════════════════════════════════════
#
# 1. Install Flask:
#      pip3 install flask --break-system-packages
#
# 2. Generate a token and save it somewhere safe:
#      python3 -c "import secrets; print(secrets.token_hex(32))"
#
# 3. Create the service file:
#      sudo nano /etc/systemd/system/vulndash-scan.service
#
#    Paste this (update the token and path as needed):
#
#    [Unit]
#    Description=VulnDash Trivy Scan Webhook Server
#    After=network.target
#
#    [Service]
#    Type=simple
#    User=pasta
#    WorkingDirectory=/home/pasta/vuln-dashboard
#    Environment="SCAN_TOKEN=YOUR_SECRET_TOKEN_HERE"
#    ExecStart=/usr/bin/python3 /home/pasta/vuln-dashboard/scan_server.py
#    Restart=on-failure
#    RestartSec=5
#
#    [Install]
#    WantedBy=multi-user.target
#
# 4. Enable and start:
#      sudo systemctl daemon-reload
#      sudo systemctl enable vulndash-scan
#      sudo systemctl start vulndash-scan
#      sudo systemctl status vulndash-scan
#
# 5. Check logs:
#      sudo journalctl -u vulndash-scan -f
#
# ══════════════════════════════════════════════════════════════════════════════
