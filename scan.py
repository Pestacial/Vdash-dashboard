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

How it works:
    1. Runs: trivy image --format json ... on the container's image
       OR:   trivy fs --format json ...  inside the container via docker exec
    2. Parses the Trivy JSON output
    3. Renders the HTML report in the same format as base-report.html
    4. Injects a <!-- SCAN_DATE: ISO8601 --> comment so the dashboard
       can display "Last scanned: ..." without any extra API calls
    5. Optionally commits and pushes via git so Vercel auto-deploys
    6. ALSO writes public/base-report.json for the dashboard to parse

Requirements:
    - Trivy must be installed on the machine where this script runs
    - Python 3.7+, no third-party packages needed

Note: This script runs LOCALLY on Kali (SCAN_ON_KALI = False).
      It does NOT SSH anywhere — it's called by scan_server.py on the same machine.
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
# Set to False when this script runs directly on Kali (called by scan_server.py)
SCAN_ON_KALI = False

SSH_HOST = "100.95.217.28"          # Kali Tailscale IP (only used if SCAN_ON_KALI = True)
SSH_USER = "pasta"
SSH_KEY  = "/home/pasta/.ssh/id_ed25519"  # Linux path (only used if SCAN_ON_KALI = True)

# Default container to scan
DEFAULT_CONTAINER = "sandbox-opensilex-docker-opensilexapp"

# Severity levels to include (ordered from most to least severe)
ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]

# ── HTML template matching base-report.html exactly ───────────────────────────

HTML_HEAD = """\
<html><head><style>
table { border-collapse: collapse; width: 100%; font-family: sans-serif; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.CRITICAL { color: red; font-weight: bold; }
.HIGH { color: orange; font-weight: bold; }
.MEDIUM { color: blue; }
.LOW { color: gray; }
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
    """Generate a single table row for a vulnerability."""
    sev = severity.upper()
    # Truncate very long titles
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

    # Try scanning the container's filesystem directly via docker exec
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
        # Fallback: trivy image against the resolved image name
        print("[scan] docker exec trivy failed, trying trivy image...")
        img_cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", sev_filter,
            "--quiet", "--no-progress",
            image_name,  # Use resolved image name, not container name
        ]
        result = subprocess.run(img_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[scan] ERROR: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    
    return json.loads(result.stdout)


def run_trivy_on_kali(container: str, severities: list[str]) -> dict:
    """SSH into Kali, run trivy there, return parsed JSON.
    
    NOTE: This function is NOT used when SCAN_ON_KALI = False (default).
    """
    sev_filter = ",".join(severities)

    remote_cmd = (
        f"docker exec {container} trivy fs "
        f"--format json --severity {sev_filter} --quiet --no-progress / "
        f"2>/dev/null || "
        f"sudo trivy image "
        f"--format json --severity {sev_filter} --quiet --no-progress {container}"
    )

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

    # Write HTML report
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

    # Git push both files
    if not args.no_git:
        git_push(output_path)      # HTML
        git_push(json_path)        # JSON
        print("[scan] Done. Vercel will deploy the updated report automatically.")
    else:
        print("[scan] Done. Skipped git push (--no-git).")


if __name__ == "__main__":
    main()
