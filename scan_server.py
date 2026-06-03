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
    
    # Allow localhost, OR any Vercel deployment for your project
    if origin == "http://localhost:5173" or origin.endswith("pestacials-projects.vercel.app"):
        response.headers["Access-Control-Allow-Origin"] = origin
        
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
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


@app.route("/scan", methods=["OPTIONS"])
def scan_preflight():
    """Handle CORS preflight."""
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
    """
    Poll scan status and log.
    No auth required — log output doesn't contain secrets.
    """
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

# ── AI Remediation Routes ──────────────────────────────────────────────────────

def call_ollama(prompt: str) -> str:
    """Send a prompt to local Ollama and get a JSON response."""
    import urllib.request
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
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode('utf-8'))['response']
    except Exception as e:
        return json.dumps({"error": str(e)})

@app.route("/remediate", methods=["POST", "OPTIONS"])
def remediate():
    # 1. Handle the browser's CORS preflight test
    if request.method == "OPTIONS":
        return _add_cors(app.response_class(status=204))

    if not _check_token():
        return jsonify({"error": "Unauthorized"}), 401
        
    json_path = Path(__file__).parent / "public" / "base-report.json"
    if not json_path.exists():
        return jsonify({"error": "base-report.json not found"}), 404
        
    try:
        data = json.loads(json_path.read_text())
    except Exception as e:
        return jsonify({"error": f"Failed to read JSON: {e}"}), 500

    # Extract only CRITICAL and HIGH vulns to save AI tokens
    vulns_for_ai = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            if v.get("Severity") in ["CRITICAL", "HIGH"]:
                vulns_for_ai.append({
                    "cve": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "version": v.get("InstalledVersion")
                })
    
    vulns_for_ai = vulns_for_ai[:30] # Limit to 30 to prevent timeouts
    
    if not vulns_for_ai:
        return jsonify({"fixes": [], "message": "No critical/high vulnerabilities to analyze."})

    prompt = f"""You are an expert Linux system administrator. You are given a list of vulnerabilities from a Trivy scan of a Docker container running on Debian/Ubuntu.
Your goal is to suggest SAFE, non-destructive commands to fix these vulnerabilities using the package manager.
The container name is "sandbox-opensilex-docker-opensilexapp".

Rules:
1. ONLY suggest commands that run inside the container using: `docker exec sandbox-opensilex-docker-opensilexapp apt-get update && docker exec sandbox-opensilex-docker-opensilexapp apt-get install --only-upgrade -y <package_name>`
2. If a vulnerability is in a Java library (e.g., jackson, netty, tomcat) or cannot be fixed via apt-get, DO NOT include it in your response.
3. You MUST respond ONLY with a valid JSON array. No markdown, no explanations outside the JSON.
4. JSON format: [{{"cve": "CVE-XXXX-YYYY", "pkg": "exact_package_name", "explanation": "Brief 1-sentence explanation", "command": "the exact docker exec command"}}]

Vulnerabilities:
{json.dumps(vulns_for_ai)}
"""
    
    ai_response = call_ollama(prompt)
    
    try:
        fixes = json.loads(ai_response)
        if isinstance(fixes, dict) and "fixes" in fixes:
            fixes = fixes["fixes"]
        return jsonify({"fixes": fixes})
    except json.JSONDecodeError:
        return jsonify({"fixes": [], "error": "AI returned invalid JSON", "raw": ai_response})

@app.route("/apply-fix", methods=["POST", "OPTIONS"])
def apply_fix():
    # 1. Handle the browser's CORS preflight test
    if request.method == "OPTIONS":
        return _add_cors(app.response_class(status=204))

    if not _check_token():
        return jsonify({"error": "Unauthorized"}), 401
        
    body = request.get_json(silent=True) or {}
    cmd = body.get("command", "")
    
    # Security check: Only allow apt-get updates inside the specific container
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
