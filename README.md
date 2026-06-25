# VDash — AI-Powered Vulnerability Management Dashboard

A lightweight, infrastructure-agnostic vulnerability scanning and remediation platform. VDash combines **Trivy**, a **Flask API server**, and a **React frontend** to automatically scan Docker containers, generate structured reports, and use local AI (Ollama) to suggest and apply security fixes.

---

## 🏗 Architecture

| Component | Purpose |
|-----------|---------|
| `App.jsx` | React dashboard: displays vulnerabilities, triggers scans, shows AI fixes, tracks patch status |
| `scan_server.py` | Flask API: orchestrates scans, batches AI remediation, validates & executes patch commands |
| `scan.py` | CLI scanner: runs Trivy, parses JSON, generates HTML/JSON reports, handles Git automation |

---

## ✨ Key Features

- **Automated Scanning** — Trigger Trivy scans against any Docker container via the dashboard or CLI
- **AI Remediation** — Uses local Ollama models to generate safe, package-specific upgrade commands
- **Secure Execution** — Strict command prefix validation prevents arbitrary shell execution
- **Git-Driven Deployment** — Scan results auto-commit & push to trigger static host deployments
- **Status Lifecycle** — Track vulnerabilities as `Open → Patched → Ignored`
- **Report Comparison** — Upload historical reports to highlight newly introduced CVEs
- **Polling-Based Realtime UI** — Lightweight status tracking without WebSockets

---

## 🔄 How It Works

1. **Trigger Scan** — User clicks ⟳ Autoscan → `POST /scan` sent to Flask server
2. **Run Trivy** — Server executes `scan.py` in background → runs `trivy image` or `docker exec trivy fs`
3. **Generate Reports** — Script outputs `base-report.html` + `base-report.json`
4. **Git Auto-Deploy** — Reports are committed & pushed → triggers Vercel/Netlify/GitHub Pages rebuild
5. **Update UI** — Dashboard polls `/status`, detects completion, fetches updated report from static host
6. **AI Remediation** — User clicks AI Remediate → server batches CVEs → queries Ollama → returns validated commands
7. **Apply Fix** — User reviews → consents → server executes `docker exec ... apt-get install` with prefix validation

---

## 📦 Prerequisites

| Component | Requirements |
|-----------|-------------|
| Scanner & Server | Python 3.7+, `flask`, `python-dotenv`, `requests`, Docker, Trivy, Git |
| AI Engine | Ollama running locally (default: `qwen2.5:7b`) |
| Frontend | Node.js 18+, React 18+, Vite |
| Infrastructure | Static hosting (Vercel/Netlify/etc), Git repo for reports, Private network (Tailscale/VPN) |

---

## ⚙️ Setup & Configuration

All infrastructure-specific values are externalized via environment variables. **Never hardcode secrets or URLs in production.**

### 1. Create `.env` Files

**Backend** (`scan_server.py` & `scan.py`):

```env
SCAN_TOKEN=your-secret-token
SCAN_SERVER_HOST=100.x.x.x          # Tailscale/private IP
SCAN_SERVER_PORT=5001
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
ALLOWED_ORIGIN=https://your-dashboard.vercel.app
TARGET_CONTAINER=your-container-name
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_HOST=http://localhost:11434
REPORT_OUTPUT_DIR=/path/to/static/public
GIT_BRANCH=main
SKIP_GIT_PUSH=false
SECURITY_CMD_PREFIX=docker exec your-container apt-get install
```

**Frontend** (`App.jsx` via Vite):

```env
VITE_SCAN_SERVER_URL=https://100.x.x.x:5001
VITE_SCAN_TOKEN=your-secret-token
```

### 2. Install Dependencies

```bash
# Backend
pip install flask python-dotenv requests

# Frontend
npm install

# Trivy (Linux)
sudo apt-get install trivy
```

---

## Running the Project

**Backend (API Server):**

```bash
python scan_server.py
```

**Frontend (Development):**

```bash
npm run dev
```

**Standalone Scan (CLI):**

```bash
python scan.py --help
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/scan` | ✅ Bearer | Trigger background Trivy scan |
| `GET` | `/status` | ❌ | Return scan state + last 50 log lines |
| `POST` | `/remediate` | ✅ Bearer | Start AI batch analysis |
| `GET` | `/remediate/status` | ❌ | Poll AI progress & results |
| `POST` | `/apply-fix` | ✅ Bearer | Execute validated patch command |
| `GET` | `/health` | ❌ | Liveness check |

---

## Security Model

- **Network Isolation** — Server binds to private/Tailscale IP (`SCAN_SERVER_HOST`)
- **TLS Encryption** — Enforced via `ssl_context=(cert, key)`
- **Bearer Authentication** — All write endpoints require `SCAN_TOKEN`
- **Command Validation** — `/apply-fix` rejects any command not matching `SECURITY_CMD_PREFIX`
- **AI Output Sanitization** — Ollama responses are parsed, validated, and deduplicated before execution
- **No Public Exposure** — Designed for internal networks only; never bind to `0.0.0.0`

---

## Migration & Portability Guide

This project is infrastructure-agnostic. To deploy in a new environment:

| What to Change | How to Change |
|----------------|---------------|
| Git Provider | Update `GIT_BRANCH`, ensure `git push` targets your remote |
| Static Host | Change `REPORT_OUTPUT_DIR` to match your host's public folder (e.g., `dist/`, `public/`, `docs/`) |
| Dashboard URL | Set `ALLOWED_ORIGIN` & `VITE_SCAN_SERVER_URL` to your domains |
| Target Container | Update `TARGET_CONTAINER` & `SECURITY_CMD_PREFIX` |
| AI Model | Change `OLLAMA_MODEL` (any JSON-capable model works) |
| Auth Method | Replace `SCAN_TOKEN` logic with OAuth/JWT if needed |

**Key Portability Notes:**

- The dashboard does not store data — it fetches `base-report.html` from the static host.
- Scan history is preserved via Git commits, not a database.
- AI remediation works with any LLM that returns structured JSON. Adjust `_build_prompt()` in `scan_server.py` if switching models.
- To disable Git auto-deploy, set `--no-git` or `SKIP_GIT_PUSH=true`.

---

## Developer Tips

- Run `python scan.py --help` to see all CLI flags.
- The dashboard UI automatically adapts to the report structure — HTML table changes only require updating the `parseTrivyHtml()` regex in `App.jsx`.

---

## License

MIT License — free to use, modify, and distribute.
