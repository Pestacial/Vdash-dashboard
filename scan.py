#!/usr/bin/env python3
"""
scan.py — Trivy scan runner for PHIS / OpenSILEX containers
Runs Trivy against the target Docker container, generates an HTML report
matching the base-report.html format, and drops it into public/base-report.html.

Usage:
    python3 scan.py [options]

Options:
    --container NAME     Docker container to scan (default: sandbox-opensilex-docker-opensilexapp)
    --output PATH        Where to write the HTML report (default: ./public/base-report.html)
    --severity LEVELS    Comma-separated severity filter, e.g. CRITICAL,HIGH,MEDIUM,LOW
                         (default: CRITICAL,HIGH,MEDIUM,LOW — excludes UNKNOWN)
    --no-git             Skip the git add/commit/push after generating the report

Example (from inside your vuln-dashboard folder on the Lenovo):
    python3 scan.py
    python3 scan.py --container sandbox-opensilex-docker-mongodb --output public/mongo-report.html
    python3 scan.py --no-git

How it works:
    1. Runs: trivy image --format json ... on the container's image
       OR:   trivy fs --format json ...  inside the container via docker exec
    2. Parses the Trivy JSON output
    3. Renders the HTML report in the same format as base-report.html
    4. Injects a <!-- SCAN_DATE: ISO8601 --> comment so the dashboard
       can display "Last scanned: ..." without any extra API calls
    5. Optionally commits and pushes via git so Vercel auto-deploys

Requirements:
    - Trivy must be installed on the machine where this script runs
      (or accessible via SSH on Kali — see SSH_MODE below)
    - Python 3.7+, no third-party packages needed

SSH_MODE:
    If Trivy is not installed locally but is on Kali, set:
        SCAN_ON_KALI = False
    The script will SSH into Kali, run Trivy there, and pull back the JSON.
    Edit SSH_HOST / SSH_USER / SSH_KEY below to match your setup.
"""

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration — edit these to match your setup ────────────────────────────

# Run Trivy on Kali via SSH instead of locally?
SCAN_ON_KALI = False

SSH_HOST = "100.95.217.28"          # Kali Tailscale IP
SSH_USER = "pasta"
SSH_KEY  = "/home/pasta/.ssh/id_ed25519"
#SSH_KEY  = r"C:\Users\Pasta\Desktop\PHIS-docker-compose-official\id_ed25519"
# On Linux/Mac use a path like: "/home/user/.ssh/id_ed25519"

# Default container to scan
DEFAULT_CONTAINER = "sandbox-opensilex-docker-opensilexapp"

# Severity levels to include (ordered from most to least severe)
ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]

# ── HTML template matching base-report.html exactly ───────────────────────────

HTML_HEAD = """\
<html><head><style>
table {{ border-collapse: collapse; width: 100%; font-family: sans-serif; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
.CRITICAL {{ color: red; font-weight: bold; }}
.HIGH {{ color: orange; font-weight: bold; }}
.MEDIUM {{ color: blue; }}
.LOW {{ color: gray; }}
</style></head><body>
"""

HTML_TITLE = "<h1>Trivy Vulnerability Report: OpenSILEX</h1>\n"

HTML_TABLE_HEADER = (
    "<table>"
    "<tr>"
    "<th>Severity</th>"
    "<th>ID</th>"
    "<th>Package</th>"
    "<th>Title</th>"
    "</tr>"
)

HTML_FOOT = "</table></body></html>\n"


def row_html(severity: str, vuln_id: str, pkg: str, title: str) -> str:
    sev = severity.upper()
    # Truncate very long titles the same way the original does (with " ...")
    if len(title) > 80:
        title = title[:77] + " ..."
    escaped_title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    escaped_pkg   = pkg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        f"<tr>"
        f"<td class='{sev}'>{sev}</td>"
        f"<td>{vuln_id}</td>"
        f"<td>{escaped_pkg}</td>"
        f"<td>{escaped_title}</td>"
        f"</tr>"
    )

# -- container name helper --
def get_image_from_container(container: str) -> str:
    """Resolve a running container name to its source image name/tag."""
    try:
        result = subprocess.run(
            ["docker", "inspect", container, "--format={{.Config.Image}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    # Fallback: assume user passed image name directly
    return container
# ── Trivy runner ───────────────────────────────────────────────────────────────

def run_trivy_local(container: str, severities: list[str]) -> dict:
    """Run trivy via docker exec on the local machine."""
    sev_filter = ",".join(severities)

    # Resolve container name to actual image name for `trivy image`
    image_name = get_image_from_container(container)

    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", sev_filter,
        "--quiet",
        "--no-progress",
    ]
    # Try scanning the container's filesystem directly — works even without
    # pulling the image, since the container is already running.
    docker_cmd = [
        "docker", "exec", container,
        "trivy", "fs",
        "--format", "json",
        "--severity", sev_filter,
        "--quiet",
        "--no-progress",
        "/",
    ]
    print(f"[scan] Running trivy fs inside {container}...")
    result = subprocess.run(docker_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Fallback: trivy image against the running container
        print("[scan] docker exec trivy failed, trying trivy image...")
        img_cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", sev_filter,
            "--quiet", "--no-progress",
            container,
        ]
        result = subprocess.run(img_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[scan] ERROR: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    return json.loads(result.stdout)


def run_trivy_on_kali(container: str, severities: list[str]) -> dict:
    """SSH into Kali, run trivy there, return parsed JSON."""
    sev_filter = ",".join(severities)

    # Build the remote trivy command
    # We try `docker exec <container> trivy fs /` first,
    # then fall back to `trivy image <container>` if trivy isn't in the container.
    remote_cmd = (
        f"docker exec {container} trivy fs "
        f"--format json --severity {sev_filter} --quiet --no-progress / "
        f"2>/dev/null || "
        f"sudo trivy image "
        f"--format json --severity {sev_filter} --quiet --no-progress {container}"
    )

    # Detect if we're on Windows (ssh key path with backslash)
    key = SSH_KEY
    ssh_cmd = [
        "ssh",
        "-i", key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        f"{SSH_USER}@{SSH_HOST}",
        remote_cmd,
    ]

    print(f"[scan] SSHing to {SSH_USER}@{SSH_HOST} to run Trivy on {container}...")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[scan] SSH command failed (exit {result.returncode}):", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    stdout = result.stdout.strip()
    if not stdout:
        print("[scan] ERROR: Trivy returned no output.", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        print(f"[scan] ERROR: Could not parse Trivy JSON: {e}", file=sys.stderr)
        print(f"[scan] Raw output (first 500 chars):\n{stdout[:500]}", file=sys.stderr)
        sys.exit(1)


def parse_trivy_json(data: dict | list) -> list[dict]:
    """Flatten Trivy JSON output into a list of vulnerability dicts."""
    vulns = []
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        results = report.get("Results") or []
        for result in results:
            for v in (result.get("Vulnerabilities") or []):
                vid = v.get("VulnerabilityID", "")
                if not vid:
                    continue
                pkg_name = v.get("PkgName", "")
                installed = v.get("InstalledVersion", "")
                pkg = f"{pkg_name} ({installed})" if installed else pkg_name
                vulns.append({
                    "severity":     (v.get("Severity") or "UNKNOWN").upper(),
                    "id":           vid,
                    "pkg":          pkg,
                    "title":        v.get("Title") or vid,
                    "fixedVersion": v.get("FixedVersion") or "",
                    "target":       result.get("Target") or "",
                })
    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, NEGLIGIBLE, UNKNOWN last
    sev_order = {s: i for i, s in enumerate(ALL_SEVERITIES + ["UNKNOWN"])}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 99))
    return vulns


def build_html(vulns: list[dict], container: str, scan_dt: datetime) -> str:
    """Render the HTML report in base-report.html format."""
    iso = scan_dt.strftime("%Y-%m-%dT%H:%M:%S")

    rows = "".join(
        row_html(v["severity"], v["id"], v["pkg"], v["title"])
        for v in vulns
    )

    return (
        f"<!-- SCAN_DATE: {iso} -->\n"
        + HTML_HEAD
        + HTML_TITLE
        + HTML_TABLE_HEADER
        + rows
        + HTML_FOOT
    )


# ── Git helpers ────────────────────────────────────────────────────────────────

def git_push(output_path: Path):
    """Add, commit and push the updated report file."""
    rel = str(output_path)
    cmds = [
        ["git", "add", rel],
        ["git", "commit", "-m", f"chore: update vulnerability report ({datetime.now().strftime('%Y-%m-%d %H:%M')})"],
        ["git", "push"],
    ]
    for cmd in cmds:
        print(f"[git] {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[git] WARN: {result.stderr.strip()}", file=sys.stderr)
            # Don't exit — e.g. "nothing to commit" is exit 1 but harmless
            if "nothing to commit" in result.stdout + result.stderr:
                print("[git] Nothing new to commit.")
                break


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run Trivy and generate a base-report.html for the VULNDASH dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 scan.py
              python3 scan.py --container sandbox-opensilex-docker-mongodb
              python3 scan.py --severity CRITICAL,HIGH
              python3 scan.py --no-git
        """),
    )
    parser.add_argument(
        "--container", default=DEFAULT_CONTAINER,
        help=f"Docker container to scan (default: {DEFAULT_CONTAINER})",
    )
    parser.add_argument(
        "--output", default="public/base-report.html",
        help="Output path for the HTML report (default: public/base-report.html)",
    )
    parser.add_argument(
        "--severity", default="CRITICAL,HIGH,MEDIUM,LOW",
        help="Comma-separated severity filter (default: CRITICAL,HIGH,MEDIUM,LOW)",
    )
    parser.add_argument(
        "--no-git", action="store_true",
        help="Skip git add/commit/push after generating the report",
    )
    args = parser.parse_args()

    severities = [s.strip().upper() for s in args.severity.split(",") if s.strip()]
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[scan] Container : {args.container}")
    print(f"[scan] Severities: {', '.join(severities)}")
    print(f"[scan] Output    : {output_path}")
    print(f"[scan] SSH mode  : {SCAN_ON_KALI}")

    # Run Trivy
    if SCAN_ON_KALI:
        raw = run_trivy_on_kali(args.container, severities)
    else:
        raw = run_trivy_local(args.container, severities)

    # Parse
    vulns = parse_trivy_json(raw)
    print(f"[scan] Found {len(vulns)} vulnerabilities.")

    if not vulns:
        print("[scan] WARN: No vulnerabilities found — check container name and severity filter.")

    # Render HTML
    scan_dt = datetime.now(timezone.utc)
    html = build_html(vulns, args.container, scan_dt)

    # Write
    output_path.write_text(html, encoding="utf-8")
    print(f"[scan] Report written to {output_path}")

    # ── ALSO WRITE JSON REPORT ─────────────────────────────────────
    json_output = {
        "scanDate": scan_dt.isoformat(),
        "container": args.container,
        "results": raw  # original Trivy JSON
    }
    json_path = output_path.with_suffix(".json")
    json_path.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
    print(f"[scan] JSON report written to {json_path}")
    # ──────────────────────────────────────────────────────────────

    # Git push
    if not args.no_git:
        git_push(output_path)
        git_push(json_path)
        print("[scan] Done. Vercel will deploy the updated report automatically.")
    else:
        print("[scan] Done. Skipped git push (--no-git).")


if __name__ == "__main__":
    main()

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan.py

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ python3 scan.py --container sandbox-opensilex-docker-opensilexapp --no-git
[scan] Container : sandbox-opensilex-docker-opensilexapp
[scan] Severities: CRITICAL, HIGH, MEDIUM, LOW
[scan] Output    : public/base-report.html
[scan] SSH mode  : False
[scan] Running trivy fs inside sandbox-opensilex-docker-opensilexapp...
[scan] docker exec trivy failed, trying trivy image...
[scan] Found 220 vulnerabilities.
[scan] Report written to public/base-report.html
[scan] JSON report written to public/base-report.json
[scan] Done. Skipped git push (--no-git).

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ ls -la public/base-report.*
-rw-rw-r-- 1 pasta pasta  40715 Jun  1 14:58 public/base-report.html
-rw-rw-r-- 1 pasta pasta 907328 Jun  1 14:58 public/base-report.json

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ python3 scan.py --container sandbox-opensilex-docker-opensilexapp
[scan] Container : sandbox-opensilex-docker-opensilexapp
[scan] Severities: CRITICAL, HIGH, MEDIUM, LOW
[scan] Output    : public/base-report.html
[scan] SSH mode  : False
[scan] Running trivy fs inside sandbox-opensilex-docker-opensilexapp...
[scan] docker exec trivy failed, trying trivy image...
[scan] Found 220 vulnerabilities.
[scan] Report written to public/base-report.html
[scan] JSON report written to public/base-report.json
[git] git add public/base-report.html
[git] git commit -m chore: update vulnerability report (2026-06-01 14:59)
[git] git push
[git] WARN: To github.com:Pestacial/vuln-dashboard.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'github.com:Pestacial/vuln-dashboard.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
[git] git add public/base-report.json
[git] git commit -m chore: update vulnerability report (2026-06-01 15:00)
[git] git push
[git] WARN: To github.com:Pestacial/vuln-dashboard.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'github.com:Pestacial/vuln-dashboard.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
[scan] Done. Vercel will deploy the updated report automatically.

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl restart vulndash-scan

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl status vulndash-scan
● vulndash-scan.service - VulnDash Trivy Scan Webhook Server
     Loaded: loaded (/etc/systemd/system/vulndash-scan.service; enabled; preset: disabl>
     Active: active (running) since Mon 2026-06-01 15:01:13 CEST; 14s ago
 Invocation: 68e1c28ef45a4f85a469fb1b277d95cd
   Main PID: 354312 (python3)
      Tasks: 1 (limit: 18617)
     Memory: 21.7M (peak: 22M)
        CPU: 134ms
     CGroup: /system.slice/vulndash-scan.service
             └─354312 /usr/bin/python3 /home/pasta/vuln-dashboard/scan_server.py

Jun 01 15:01:13 kali systemd[1]: Started vulndash-scan.service - VulnDash Trivy Scan We>
Jun 01 15:01:13 kali python3[354312]: [server] vulndash scan server starting on 100.95.>
Jun 01 15:01:13 kali python3[354312]: [server] Scan script: /home/pasta/vuln-dashboard/>
Jun 01 15:01:13 kali python3[354312]: [server] CORS origin: https://vuln-dashboard.verc>
Jun 01 15:01:13 kali python3[354312]: [server] Token set  : YES (custom)
Jun 01 15:01:13 kali python3[354312]:  * Serving Flask app 'scan_server'
Jun 01 15:01:13 kali python3[354312]:  * Debug mode: off
Jun 01 15:01:13 kali python3[354312]: WARNING: This is a development server. Do not use>
Jun 01 15:01:13 kali python3[354312]:  * Running on http://100.95.217.28:5000
Jun 01 15:01:13 kali python3[354312]: Press CTRL+C to quit





┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl daemon-reload

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl restart vulndash-scan

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl status vulndash-scan
● vulndash-scan.service - VulnDash Trivy Scan Webhook Server
     Loaded: loaded (/etc/systemd/system/vulndash-scan.service; enabled; preset: disabl>
     Active: active (running) since Mon 2026-06-01 15:10:40 CEST; 6s ago
 Invocation: 9b803af25b0e4ac5962e47701907d386
   Main PID: 367242 (python3)
      Tasks: 1 (limit: 18617)
     Memory: 21.7M (peak: 22M)
        CPU: 161ms
     CGroup: /system.slice/vulndash-scan.service
             └─367242 /usr/bin/python3 /home/pasta/vuln-dashboard/scan_server.py

Jun 01 15:10:40 kali systemd[1]: Started vulndash-scan.service - VulnDash Trivy Scan We>
Jun 01 15:10:40 kali python3[367242]: [server] vulndash scan server starting on 100.95.>
Jun 01 15:10:40 kali python3[367242]: [server] Scan script: /home/pasta/vuln-dashboard/>
Jun 01 15:10:40 kali python3[367242]: [server] CORS origin: https://vuln-dashboard.verc>
Jun 01 15:10:40 kali python3[367242]: [server] Token set  : YES (custom)
Jun 01 15:10:40 kali python3[367242]:  * Serving Flask app 'scan_server'
Jun 01 15:10:40 kali python3[367242]:  * Debug mode: off
Jun 01 15:10:40 kali python3[367242]: WARNING: This is a development server. Do not use>
Jun 01 15:10:40 kali python3[367242]:  * Running on http://100.95.217.28:5000
Jun 01 15:10:40 kali python3[367242]: Press CTRL+C to quit


┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ python3 scan.py --container sandbox-opensilex-docker-opensilexapp
[scan] Container : sandbox-opensilex-docker-opensilexapp
[scan] Severities: CRITICAL, HIGH, MEDIUM, LOW
[scan] Output    : public/base-report.html
[scan] SSH mode  : False
[scan] Running trivy fs inside sandbox-opensilex-docker-opensilexapp...
[scan] docker exec trivy failed, trying trivy image...
[scan] Found 220 vulnerabilities.
[scan] Report written to public/base-report.html
[scan] JSON report written to public/base-report.json
[git] git add public/base-report.html
[git] git commit -m chore: update vulnerability report (2026-06-01 15:13)
[git] git push
[git] WARN: To github.com:Pestacial/vuln-dashboard.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'github.com:Pestacial/vuln-dashboard.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
[git] git add public/base-report.json
[git] git commit -m chore: update vulnerability report (2026-06-01 15:13)
[git] git push
[git] WARN: To github.com:Pestacial/vuln-dashboard.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'github.com:Pestacial/vuln-dashboard.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
[scan] Done. Vercel will deploy the updated report automatically.

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ cat /etc/systemd/system/vulndash-scan.service
[Unit]
Description=VulnDash Trivy Scan Webhook Server
After=network.target

[Service]
Type=simple
User=pasta
WorkingDirectory=/home/pasta/vuln-dashboard
Environment="SCAN_TOKEN=b7ca8a9c89f3a9fd1e90c9d742825fc511ca3bd9050309b37ffd97347cfd017e"
ExecStart=/usr/bin/python3 /home/pasta/vuln-dashboard/scan_server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ ssh -T -i ~/.ssh/vulndash_deploy git@github.com
Hi Pestacial/vuln-dashboard! You've successfully authenticated, but GitHub does not provide shell access.

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ git pull --rebase origin main
error: cannot pull with rebase: You have unstaged changes.
error: Please commit or stash them.

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ git add public/base-report.html public/base-report.json

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ git rebase --continue
fatal: no rebase in progress

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ git push
To github.com:Pestacial/vuln-dashboard.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'github.com:Pestacial/vuln-dashboard.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan.py

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan_server.py


┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan_server.py

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan_server.py

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ sudo systemctl restart vulndash-scan

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ cat scan_server.py
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
import subprocess
import threading
import time
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
    allowed = [
        "https://vuln-dashboard.vercel.app",
        "https://vulndashboard-nu.vercel.app",  # add your preview URL
        "http://localhost:5173",  # local dev
    ]
    if origin in allowed:
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

    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)


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

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ cd ..

┌──(pasta㉿kali)-[~]
└─$ sudo apt install -y mkcert
mkcert is already the newest version (1.4.4-1+b20).
Summary:
  Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 1168

┌──(pasta㉿kali)-[~]
└─$ sudo apt install -y mkcert
mkcert is already the newest version (1.4.4-1+b20).
Summary:
  Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 1168

┌──(pasta㉿kali)-[~]
└─$ mkcert -install
The local CA is already installed in the system trust store! 👍
The local CA is already installed in the Firefox and/or Chrome/Chromium trust store! 👍


┌──(pasta㉿kali)-[~]
└─$ cd ~/vuln-dashboard

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ mkcert 100.95.217.28

Created a new certificate valid for the following names 📜
 - "100.95.217.28"

The certificate is at "./100.95.217.28.pem" and the key at "./100.95.217.28-key.pem" ✅

It will expire on 1 September 2028 🗓


┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ nano scan_server.py

┌──(pasta㉿kali)-[~/vuln-dashboard]
└─$ cat scan.py
#!/usr/bin/env python3
"""
scan.py — Trivy scan runner for PHIS / OpenSILEX containers
Runs Trivy against the target Docker container, generates an HTML report
matching the base-report.html format, and drops it into public/base-report.html.

Usage:
    python3 scan.py [options]

Options:
    --container NAME     Docker container to scan (default: sandbox-opensilex-docker-opensilexapp)
    --output PATH        Where to write the HTML report (default: ./public/base-report.html)
    --severity LEVELS    Comma-separated severity filter, e.g. CRITICAL,HIGH,MEDIUM,LOW
                         (default: CRITICAL,HIGH,MEDIUM,LOW — excludes UNKNOWN)
    --no-git             Skip the git add/commit/push after generating the report

Example (from inside your vuln-dashboard folder on the Lenovo):
    python3 scan.py
    python3 scan.py --container sandbox-opensilex-docker-mongodb --output public/mongo-report.html
    python3 scan.py --no-git

How it works:
    1. Runs: trivy image --format json ... on the container's image
       OR:   trivy fs --format json ...  inside the container via docker exec
    2. Parses the Trivy JSON output
    3. Renders the HTML report in the same format as base-report.html
    4. Injects a <!-- SCAN_DATE: ISO8601 --> comment so the dashboard
       can display "Last scanned: ..." without any extra API calls
    5. Optionally commits and pushes via git so Vercel auto-deploys

Requirements:
    - Trivy must be installed on the machine where this script runs
      (or accessible via SSH on Kali — see SSH_MODE below)
    - Python 3.7+, no third-party packages needed

SSH_MODE:
    If Trivy is not installed locally but is on Kali, set:
        SCAN_ON_KALI = False
    The script will SSH into Kali, run Trivy there, and pull back the JSON.
    Edit SSH_HOST / SSH_USER / SSH_KEY below to match your setup.
"""

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration — edit these to match your setup ────────────────────────────

# Run Trivy on Kali via SSH instead of locally?
SCAN_ON_KALI = False

SSH_HOST = "100.95.217.28"          # Kali Tailscale IP
SSH_USER = "pasta"
SSH_KEY  = "/home/pasta/.ssh/id_ed25519"
#SSH_KEY  = r"C:\Users\Pasta\Desktop\PHIS-docker-compose-official\id_ed25519"
# On Linux/Mac use a path like: "/home/user/.ssh/id_ed25519"

# Default container to scan
DEFAULT_CONTAINER = "sandbox-opensilex-docker-opensilexapp"

# Severity levels to include (ordered from most to least severe)
ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]

# ── HTML template matching base-report.html exactly ───────────────────────────

HTML_HEAD = """\
<html><head><style>
table {{ border-collapse: collapse; width: 100%; font-family: sans-serif; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
.CRITICAL {{ color: red; font-weight: bold; }}
.HIGH {{ color: orange; font-weight: bold; }}
.MEDIUM {{ color: blue; }}
.LOW {{ color: gray; }}
</style></head><body>
"""

HTML_TITLE = "<h1>Trivy Vulnerability Report: OpenSILEX</h1>\n"

HTML_TABLE_HEADER = (
    "<table>"
    "<tr>"
    "<th>Severity</th>"
    "<th>ID</th>"
    "<th>Package</th>"
    "<th>Title</th>"
    "</tr>"
)

HTML_FOOT = "</table></body></html>\n"


def row_html(severity: str, vuln_id: str, pkg: str, title: str) -> str:
    sev = severity.upper()
    # Truncate very long titles the same way the original does (with " ...")
    if len(title) > 80:
        title = title[:77] + " ..."
    escaped_title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    escaped_pkg   = pkg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        f"<tr>"
        f"<td class='{sev}'>{sev}</td>"
        f"<td>{vuln_id}</td>"
        f"<td>{escaped_pkg}</td>"
        f"<td>{escaped_title}</td>"
        f"</tr>"
    )

# -- container name helper --
def get_image_from_container(container: str) -> str:
    """Resolve a running container name to its source image name/tag."""
    try:
        result = subprocess.run(
            ["docker", "inspect", container, "--format={{.Config.Image}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    # Fallback: assume user passed image name directly
    return container
# ── Trivy runner ───────────────────────────────────────────────────────────────

def run_trivy_local(container: str, severities: list[str]) -> dict:
    """Run trivy via docker exec on the local machine."""
    sev_filter = ",".join(severities)

    # Resolve container name to actual image name for `trivy image`
    image_name = get_image_from_container(container)

    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", sev_filter,
        "--quiet",
        "--no-progress",
    ]
    # Try scanning the container's filesystem directly — works even without
    # pulling the image, since the container is already running.
    docker_cmd = [
        "docker", "exec", container,
        "trivy", "fs",
        "--format", "json",
        "--severity", sev_filter,
        "--quiet",
        "--no-progress",
        "/",
    ]
    print(f"[scan] Running trivy fs inside {container}...")
    result = subprocess.run(docker_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Fallback: trivy image against the running container
        print("[scan] docker exec trivy failed, trying trivy image...")
        img_cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", sev_filter,
            "--quiet", "--no-progress",
            image_name,
        ]
        result = subprocess.run(img_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[scan] ERROR: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    return json.loads(result.stdout)


def run_trivy_on_kali(container: str, severities: list[str]) -> dict:
    """SSH into Kali, run trivy there, return parsed JSON."""
    sev_filter = ",".join(severities)

    # Build the remote trivy command
    # We try `docker exec <container> trivy fs /` first,
    # then fall back to `trivy image <container>` if trivy isn't in the container.
    remote_cmd = (
        f"docker exec {container} trivy fs "
        f"--format json --severity {sev_filter} --quiet --no-progress / "
        f"2>/dev/null || "
        f"sudo trivy image "
        f"--format json --severity {sev_filter} --quiet --no-progress {container}"
    )

    # Detect if we're on Windows (ssh key path with backslash)
    key = SSH_KEY
    ssh_cmd = [
        "ssh",
        "-i", key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        f"{SSH_USER}@{SSH_HOST}",
        remote_cmd,
    ]

    print(f"[scan] SSHing to {SSH_USER}@{SSH_HOST} to run Trivy on {container}...")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[scan] SSH command failed (exit {result.returncode}):", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    stdout = result.stdout.strip()
    if not stdout:
        print("[scan] ERROR: Trivy returned no output.", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        print(f"[scan] ERROR: Could not parse Trivy JSON: {e}", file=sys.stderr)
        print(f"[scan] Raw output (first 500 chars):\n{stdout[:500]}", file=sys.stderr)
        sys.exit(1)


def parse_trivy_json(data: dict | list) -> list[dict]:
    """Flatten Trivy JSON output into a list of vulnerability dicts."""
    vulns = []
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        results = report.get("Results") or []
        for result in results:
            for v in (result.get("Vulnerabilities") or []):
                vid = v.get("VulnerabilityID", "")
                if not vid:
                    continue
                pkg_name = v.get("PkgName", "")
                installed = v.get("InstalledVersion", "")
                pkg = f"{pkg_name} ({installed})" if installed else pkg_name
                vulns.append({
                    "severity":     (v.get("Severity") or "UNKNOWN").upper(),
                    "id":           vid,
                    "pkg":          pkg,
                    "title":        v.get("Title") or vid,
                    "fixedVersion": v.get("FixedVersion") or "",
                    "target":       result.get("Target") or "",
                })
    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, NEGLIGIBLE, UNKNOWN last
    sev_order = {s: i for i, s in enumerate(ALL_SEVERITIES + ["UNKNOWN"])}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 99))
    return vulns


def build_html(vulns: list[dict], container: str, scan_dt: datetime) -> str:
    """Render the HTML report in base-report.html format."""
    iso = scan_dt.strftime("%Y-%m-%dT%H:%M:%S")

    rows = "".join(
        row_html(v["severity"], v["id"], v["pkg"], v["title"])
        for v in vulns
    )

    return (
        f"<!-- SCAN_DATE: {iso} -->\n"
        + HTML_HEAD
        + HTML_TITLE
        + HTML_TABLE_HEADER
        + rows
        + HTML_FOOT
    )


# ── Git helpers ────────────────────────────────────────────────────────────────

def git_push(output_path: Path):
    """Add, commit and push the updated report file."""
    rel = str(output_path)
    cmds = [
        ["git", "add", rel],
        ["git", "commit", "-m", f"chore: update vulnerability report ({datetime.now().strftime('%Y-%m-%d %H:%M')})"],
        ["git", "push"],
    ]
    for cmd in cmds:
        print(f"[git] {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[git] WARN: {result.stderr.strip()}", file=sys.stderr)
            # Don't exit — e.g. "nothing to commit" is exit 1 but harmless
            if "nothing to commit" in result.stdout + result.stderr:
                print("[git] Nothing new to commit.")
                break


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run Trivy and generate a base-report.html for the VULNDASH dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 scan.py
              python3 scan.py --container sandbox-opensilex-docker-mongodb
              python3 scan.py --severity CRITICAL,HIGH
              python3 scan.py --no-git
        """),
    )
    parser.add_argument(
        "--container", default=DEFAULT_CONTAINER,
        help=f"Docker container to scan (default: {DEFAULT_CONTAINER})",
    )
    parser.add_argument(
        "--output", default="public/base-report.html",
        help="Output path for the HTML report (default: public/base-report.html)",
    )
    parser.add_argument(
        "--severity", default="CRITICAL,HIGH,MEDIUM,LOW",
        help="Comma-separated severity filter (default: CRITICAL,HIGH,MEDIUM,LOW)",
    )
    parser.add_argument(
        "--no-git", action="store_true",
        help="Skip git add/commit/push after generating the report",
    )
    args = parser.parse_args()

    severities = [s.strip().upper() for s in args.severity.split(",") if s.strip()]
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[scan] Container : {args.container}")
    print(f"[scan] Severities: {', '.join(severities)}")
    print(f"[scan] Output    : {output_path}")
    print(f"[scan] SSH mode  : {SCAN_ON_KALI}")

    # Run Trivy
    if SCAN_ON_KALI:
        raw = run_trivy_on_kali(args.container, severities)
    else:
        raw = run_trivy_local(args.container, severities)

    # Parse
    vulns = parse_trivy_json(raw)
    print(f"[scan] Found {len(vulns)} vulnerabilities.")

    if not vulns:
        print("[scan] WARN: No vulnerabilities found — check container name and severity filter.")

    # Render HTML
    scan_dt = datetime.now(timezone.utc)
    html = build_html(vulns, args.container, scan_dt)

    # Write
    output_path.write_text(html, encoding="utf-8")
    print(f"[scan] Report written to {output_path}")

    # ── ALSO WRITE JSON REPORT ─────────────────────────────────────
    json_output = {
        "scanDate": scan_dt.isoformat(),
        "container": args.container,
        "results": raw  # original Trivy JSON
    }
    json_path = output_path.with_suffix(".json")
    json_path.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
    print(f"[scan] JSON report written to {json_path}")
    # ──────────────────────────────────────────────────────────────

    # Git push
    if not args.no_git:
        git_push(output_path)
        git_push(json_path)
        print("[scan] Done. Vercel will deploy the updated report automatically.")
    else:
        print("[scan] Done. Skipped git push (--no-git).")


if __name__ == "__main__":
    main()