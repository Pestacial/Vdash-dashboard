import { useState, useMemo, useEffect, useRef, useCallback } from "react";

// ── Config — update these to match your deployment ───────────────────────────
const SCAN_SERVER_URL = "http://100.95.217.28:5000";
// Set your SCAN_TOKEN here, or load it from a build-time env var:
//   VITE_SCAN_TOKEN=your_token npm run build
const SCAN_TOKEN = import.meta.env.VITE_SCAN_TOKEN || "CHANGE_ME";

// ── Helpers ────────────────────────────────────────────────────────────────────
function normalizePkg(pkg) {
  return pkg.replace(/\((\d+):/, "(");
}

function parseTrivyJson(text) {
  try {
    const data = JSON.parse(text);
    // Handle our envelope format: { scanDate, results: <trivy json> }
    const raw = data.results !== undefined ? data.results : data;
    const vulns = [];
    const reports = Array.isArray(raw) ? raw : [raw];
    reports.forEach((report) => {
      if (!report.Results) return;
      report.Results.forEach((result) => {
        if (!result.Vulnerabilities) return;
        result.Vulnerabilities.forEach((v) => {
          if (!v.VulnerabilityID) return;
          vulns.push({
            severity: (v.Severity || "UNKNOWN").toUpperCase(),
            id: v.VulnerabilityID,
            pkg: v.PkgName + (v.InstalledVersion ? " (" + v.InstalledVersion + ")" : ""),
            title: v.Title || v.VulnerabilityID,
            target: result.Target || "",
            fixedVersion: v.FixedVersion || "",
          });
        });
      });
    });
    // Extract scan date from envelope if present
    const scanDate = data.scanDate ? new Date(data.scanDate) : null;
    return { vulns, scanDate };
  } catch (e) {
    console.warn("JSON parse failed", e);
    return { vulns: [], scanDate: null };
  }
}

function parseTrivyHtml(html) {
  const scan2htmlMatch = html.match(/i9=(\[\s*\{[\s\S]*?\}\s*\])\s*[,;]/);
  if (scan2htmlMatch) {
    try {
      const data = JSON.parse(scan2htmlMatch[1]);
      const vulns = [];
      data.forEach((report) => {
        if (!report.Results) return;
        report.Results.forEach((result) => {
          if (!result.Vulnerabilities) return;
          result.Vulnerabilities.forEach((v) => {
            if (!v.VulnerabilityID) return;
            vulns.push({
              severity: (v.Severity || "UNKNOWN").toUpperCase(),
              id: v.VulnerabilityID,
              pkg: v.PkgName + (v.InstalledVersion ? " (" + v.InstalledVersion + ")" : ""),
              title: v.Title || v.VulnerabilityID,
              target: result.Target || "",
              fixedVersion: v.FixedVersion || "",
            });
          });
        });
      });
      if (vulns.length > 0) return vulns;
    } catch (e) {
      console.warn("scan2html parse failed, falling back", e);
    }
  }

  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const rows = doc.querySelectorAll("table tr");
  const vulns = [];
  rows.forEach((row) => {
    const cells = row.querySelectorAll("td");
    if (cells.length < 4) return;
    const severity = cells[0]?.textContent?.trim().toUpperCase();
    const id = cells[1]?.textContent?.trim();
    const pkg = cells[2]?.textContent?.trim();
    const title = cells[3]?.textContent?.trim();
    if (!severity || !id) return;
    vulns.push({ severity, id, pkg, title, target: "", fixedVersion: "" });
  });
  return vulns;
}

function parseScanDate(html) {
  const m = html.match(/<!--\s*SCAN_DATE:\s*([^\s>]+)\s*-->/);
  if (!m) return null;
  const d = new Date(m[1]);
  if (isNaN(d)) return null;
  return d;
}

const nvdUrl = (id) =>
  id.startsWith("GHSA-")
    ? `https://github.com/advisories/${id}`
    : `https://nvd.nist.gov/vuln/detail/${id}`;

const isGhsa = (id) => id.startsWith("GHSA-");

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4 };

const SEV_STYLE = {
  CRITICAL:   { bg: "#e8193c", glow: "#e8193c55" },
  HIGH:       { bg: "#f97316", glow: "#f9731655" },
  MEDIUM:     { bg: "#eab308", glow: "#eab30855" },
  LOW:        { bg: "#6b7280", glow: "#6b728055" },
  NEGLIGIBLE: { bg: "#374151", glow: "#37415155" },
};

const STATUS_CYCLE = ["open", "patched", "ignored"];
const STATUS_STYLE = {
  open:    { bg: "#1e293b", color: "#94a3b8", border: "#334155", label: "Open" },
  patched: { bg: "#052e16", color: "#4ade80", border: "#166534", label: "✓ Patched" },
  ignored: { bg: "#1c1917", color: "#a8a29e", border: "#44403c", label: "~ Ignored" },
};

// Scan UI states
const SCAN_STATE = {
  IDLE:     "idle",
  STARTING: "starting",
  RUNNING:  "running",
  SUCCESS:  "success",
  ERROR:    "error",
};

function formatDate(d) {
  if (!d) return null;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function timeSince(d) {
  if (!d) return null;
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60)  return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SevBadge({ level }) {
  const s = SEV_STYLE[level] || { bg: "#374151", glow: "#37415155" };
  return (
    <span style={{
      background: s.bg, color: "#fff",
      padding: "3px 10px", borderRadius: 3,
      fontSize: 10, fontWeight: 800, letterSpacing: 1.2,
      fontFamily: "'DM Mono', monospace",
      boxShadow: `0 0 8px ${s.glow}`,
      display: "inline-block", whiteSpace: "nowrap",
    }}>{level}</span>
  );
}

function StatusBtn({ status, onClick }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.open;
  return (
    <span onClick={onClick} title="Click to cycle status" style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      padding: "3px 10px", borderRadius: 4,
      fontSize: 11, fontWeight: 600,
      cursor: "pointer", display: "inline-block",
      fontFamily: "'DM Mono', monospace",
      userSelect: "none", whiteSpace: "nowrap",
      transition: "all 0.15s",
    }}>{s.label}</span>
  );
}

// Pulsing dot indicator
function PulseDot({ color = "#4ade80" }) {
  return (
    <span style={{ position: "relative", display: "inline-block", width: 8, height: 8 }}>
      <style>{`
        @keyframes ping {
          0%   { transform: scale(1);   opacity: 0.8; }
          70%  { transform: scale(2.2); opacity: 0; }
          100% { transform: scale(2.2); opacity: 0; }
        }
      `}</style>
      <span style={{
        position: "absolute", inset: 0, borderRadius: "50%",
        background: color, animation: "ping 1.2s ease-out infinite",
      }} />
      <span style={{
        position: "relative", display: "block", width: 8, height: 8,
        borderRadius: "50%", background: color,
      }} />
    </span>
  );
}

// Autoscan button with states
function AutoscanButton({ scanState, onScan, T }) {
  const isActive = scanState === SCAN_STATE.STARTING || scanState === SCAN_STATE.RUNNING;

  const stateConfig = {
    [SCAN_STATE.IDLE]:     { label: "⟳  Autoscan",   bg: "#0ea5e9", shadow: "#0ea5e955" },
    [SCAN_STATE.STARTING]: { label: "Connecting…",    bg: "#6366f1", shadow: "#6366f155" },
    [SCAN_STATE.RUNNING]:  { label: "Scanning…",      bg: "#8b5cf6", shadow: "#8b5cf655" },
    [SCAN_STATE.SUCCESS]:  { label: "✓  Scan sent",   bg: "#10b981", shadow: "#10b98155" },
    [SCAN_STATE.ERROR]:    { label: "✕  Failed",      bg: "#ef4444", shadow: "#ef444455" },
  };

  const cfg = stateConfig[scanState] || stateConfig[SCAN_STATE.IDLE];

  return (
    <button
      onClick={onScan}
      disabled={isActive}
      title="Trigger a fresh Trivy scan on Kali and push results to GitHub"
      style={{
        background: cfg.bg, color: "#fff", border: "none",
        padding: "6px 18px", borderRadius: 6,
        cursor: isActive ? "not-allowed" : "pointer",
        fontSize: 12, fontWeight: 700, fontFamily: "inherit",
        letterSpacing: 0.3, display: "flex", alignItems: "center", gap: 8,
        boxShadow: `0 0 14px ${cfg.shadow}`,
        opacity: isActive ? 0.75 : 1,
        transition: "all 0.2s",
        whiteSpace: "nowrap",
      }}
    >
      {isActive && <PulseDot color="#fff" />}
      {cfg.label}
    </button>
  );
}

// Compact scan log drawer
function ScanLogDrawer({ log, show, onClose, T }) {
  if (!show) return null;
  return (
    <div style={{
      position: "fixed", bottom: 0, left: 0, right: 0,
      background: T.surface, borderTop: `2px solid #0ea5e9`,
      zIndex: 500, maxHeight: "35vh", display: "flex", flexDirection: "column",
    }}>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "8px 16px", borderBottom: `1px solid ${T.border}`,
        background: T.surface2,
      }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: "#0ea5e9", fontFamily: "'DM Mono', monospace", letterSpacing: 1.5 }}>
          SCAN LOG
        </span>
        <button onClick={onClose} style={{
          background: "transparent", border: "none", color: T.subtext,
          cursor: "pointer", fontSize: 16, lineHeight: 1, padding: "2px 6px",
        }}>✕</button>
      </div>
      <div style={{
        overflowY: "auto", padding: "10px 16px",
        fontFamily: "'DM Mono', monospace", fontSize: 11,
        color: T.text, lineHeight: 1.6,
        background: T.bg,
      }}>
        {log.length === 0
          ? <span style={{ color: T.subtext }}>No log output yet…</span>
          : log.map((line, i) => {
            const col = line.includes("ERROR") || line.includes("FAIL")
              ? "#f87171"
              : line.includes("Done") || line.includes("successfully") || line.includes("✓")
              ? "#4ade80"
              : line.startsWith("[git]")
              ? "#818cf8"
              : T.text;
            return (
              <div key={i} style={{ color: col, wordBreak: "break-all" }}>{line}</div>
            );
          })
        }
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function App() {
  const [baseVulns, setBaseVulns]             = useState([]);
  const [uploadedVulns, setUploadedVulns]     = useState(null);
  const [uploadedName, setUploadedName]       = useState("");
  const [activeView, setActiveView]           = useState("base");
  const [severityFilter, setSeverityFilter]   = useState("ALL");
  const [searchQuery, setSearchQuery]         = useState("");
  const [patchStatus, setPatchStatus]         = useState({});
  const [expandedRow, setExpandedRow]         = useState(null);
  const [darkMode, setDarkMode]               = useState(false);
  const [pageSize, setPageSize]               = useState(20);
  const [page, setPage]                       = useState(1);
  const [baseLoading, setBaseLoading]         = useState(true);
  const [baseError, setBaseError]             = useState(false);
  const [sortCol, setSortCol]                 = useState(null);
  const [sortDir, setSortDir]                 = useState(null);
  const [scanDate, setScanDate]               = useState(null);
  // Autoscan state
  const [scanState, setScanState]             = useState(SCAN_STATE.IDLE);
  const [scanLog, setScanLog]                 = useState([]);
  const [showLog, setShowLog]                 = useState(false);
  const [scanErrorMsg, setScanErrorMsg]       = useState("");
  const pollTimerRef                          = useRef(null);
  const fileRef                               = useRef();

  // ── Load base report ────────────────────────────────────────────────────────
  useEffect(() => {
    fetch("/base-report.html")
      .then((r) => { if (!r.ok) throw new Error("Not found"); return r.text(); })
      .then((html) => {
        setBaseVulns(parseTrivyHtml(html));
        setScanDate(parseScanDate(html));
        setBaseLoading(false);
      })
      .catch(() => { setBaseError(true); setBaseLoading(false); });
  }, []);

  // ── Poll scan status while running ─────────────────────────────────────────
  const startPolling = useCallback(() => {
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);

    pollTimerRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${SCAN_SERVER_URL}/status`);
        if (!res.ok) return;
        const data = await res.json();

        setScanLog(data.log || []);

        if (!data.running) {
          clearInterval(pollTimerRef.current);
          pollTimerRef.current = null;

          if (data.lastScanOk === true) {
            setScanState(SCAN_STATE.SUCCESS);
            // Reload the base report to pick up the new data
            setTimeout(() => {
              fetch("/base-report.html?bust=" + Date.now())
                .then((r) => r.text())
                .then((html) => {
                  setBaseVulns(parseTrivyHtml(html));
                  setScanDate(parseScanDate(html));
                });
            }, 3000); // Give Vercel ~3s to deploy
          } else if (data.lastScanOk === false) {
            setScanState(SCAN_STATE.ERROR);
            setScanErrorMsg("Scan failed. Check the log for details.");
          }

          // Auto-reset button after 8s
          setTimeout(() => setScanState(SCAN_STATE.IDLE), 8000);
        } else {
          setScanState(SCAN_STATE.RUNNING);
        }
      } catch (e) {
        // Network error while polling — keep trying
      }
    }, 2000);
  }, []);

  useEffect(() => {
    return () => { if (pollTimerRef.current) clearInterval(pollTimerRef.current); };
  }, []);

  // ── Autoscan trigger ────────────────────────────────────────────────────────
  const handleAutoscan = useCallback(async () => {
    if (scanState === SCAN_STATE.STARTING || scanState === SCAN_STATE.RUNNING) return;

    setScanState(SCAN_STATE.STARTING);
    setScanLog([]);
    setScanErrorMsg("");
    setShowLog(true);

    try {
      const res = await fetch(`${SCAN_SERVER_URL}/scan`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${SCAN_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ container: "sandbox-opensilex-docker-opensilexapp" }),
      });

      if (res.status === 409) {
        setScanLog(["[server] A scan is already running on Kali."]);
        setScanState(SCAN_STATE.RUNNING);
        startPolling();
        return;
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setScanState(SCAN_STATE.ERROR);
        setScanErrorMsg(err.error || `Server returned HTTP ${res.status}`);
        setTimeout(() => setScanState(SCAN_STATE.IDLE), 8000);
        return;
      }

      setScanState(SCAN_STATE.RUNNING);
      startPolling();

    } catch (e) {
      setScanState(SCAN_STATE.ERROR);
      setScanErrorMsg(`Could not reach scan server at ${SCAN_SERVER_URL}. Is it running on Kali?`);
      setScanLog([`[client] ${e.message}`]);
      setTimeout(() => setScanState(SCAN_STATE.IDLE), 8000);
    }
  }, [scanState, startPolling]);

  // ── Data derivations ────────────────────────────────────────────────────────
  const vulns = activeView === "base" ? baseVulns : (uploadedVulns || []);

  useEffect(() => { setPage(1); }, [severityFilter, searchQuery, activeView, pageSize, sortCol, sortDir]);

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 };
    vulns.forEach((v) => { if (c[v.severity] !== undefined) c[v.severity]++; });
    return c;
  }, [vulns]);

  const baseIdSet = useMemo(() => {
    const s = new Set();
    baseVulns.forEach((v) => s.add(`${v.id}|${normalizePkg(v.pkg)}`));
    return s;
  }, [baseVulns]);

  const filtered = useMemo(() => {
    let list = [...vulns];
    if (severityFilter === "NEW") {
      list = list.filter((v) => {
        const key = `${v.id}|${normalizePkg(v.pkg)}`;
        return !baseIdSet.has(key) && (patchStatus[key] || "open") !== "patched";
      });
    } else if (severityFilter !== "ALL") {
      list = list.filter((v) => v.severity === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((v) =>
        v.id?.toLowerCase().includes(q) ||
        v.pkg?.toLowerCase().includes(q) ||
        v.title?.toLowerCase().includes(q)
      );
    }
    if (sortCol && sortDir) {
      list.sort((a, b) => {
        if (sortCol === "severity") {
          const va = SEVERITY_ORDER[a.severity] ?? 9;
          const vb = SEVERITY_ORDER[b.severity] ?? 9;
          return sortDir === "asc" ? va - vb : vb - va;
        }
        const va = a[sortCol] ?? "";
        const vb = b[sortCol] ?? "";
        return sortDir === "asc"
          ? va.toString().localeCompare(vb.toString())
          : vb.toString().localeCompare(va.toString());
      });
    } else {
      list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    }
    return list;
  }, [vulns, severityFilter, searchQuery, sortCol, sortDir, baseIdSet, patchStatus]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paginated  = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploadedName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target.result;
      const isJson  = file.name.toLowerCase().endsWith(".json");
      let parsed, uploadScanDate = null;

      if (isJson) {
        const result = parseTrivyJson(content);
        parsed = result.vulns;
        uploadScanDate = result.scanDate;
      } else {
        parsed = parseTrivyHtml(content);
      }

      const uploadedKeys = new Set(parsed.map((v) => `${v.id}|${normalizePkg(v.pkg)}`));
      setPatchStatus((prev) => {
        const updated = { ...prev };
        baseVulns.forEach((v) => {
          const key = `${v.id}|${normalizePkg(v.pkg)}`;
          if (!uploadedKeys.has(key) && !prev[key]) updated[key] = "patched";
        });
        return updated;
      });

      setUploadedVulns(parsed);
      setActiveView("uploaded");
      setSeverityFilter("ALL");
      setSearchQuery("");
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleSort = (col) => {
    if (sortCol !== col)     { setSortCol(col); setSortDir("asc"); }
    else if (sortDir === "asc")  setSortDir("desc");
    else                     { setSortCol(null); setSortDir(null); }
  };

  const cycleStatus = (e, key) => {
    e.stopPropagation();
    setPatchStatus((prev) => {
      const cur  = prev[key] || "open";
      const next = STATUS_CYCLE[(STATUS_CYCLE.indexOf(cur) + 1) % STATUS_CYCLE.length];
      return { ...prev, [key]: next };
    });
  };

  // ── Theme ───────────────────────────────────────────────────────────────────
  const T = darkMode ? {
    bg: "#080f1a", surface: "#0d1829", surface2: "#111f33",
    border: "#1a2d48", text: "#c8daf0", subtext: "#4a6080",
    hover: "#162035", accent: "#3b82f6",
  } : {
    bg: "#f1f5fb", surface: "#ffffff", surface2: "#f7f9fd",
    border: "#dde5f0", text: "#0f1f38", subtext: "#7a90b0",
    hover: "#eef3fc", accent: "#2563eb",
  };

  const isBase  = activeView === "base";
  const gridCols = isBase
    ? "110px minmax(0, 1fr) 180px 100px 100px"
    : "110px minmax(0, 1fr) 180px 100px";

  return (
    <div style={{ minHeight: "100vh", width: "100%", overflowX: "hidden", background: T.bg, color: T.text, fontFamily: "'DM Sans', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500;600&display=swap" rel="stylesheet" />

      {/* ── Topbar ── */}
      <div style={{
        position: "sticky", top: 0, zIndex: 200,
        background: T.surface, borderBottom: `1px solid ${T.border}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 8px", height: 52,
        boxShadow: darkMode ? "0 2px 20px #00000060" : "0 2px 10px #0000001a",
      }}>
        {/* Left */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "nowrap", overflow: "hidden" }}>
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: 12, fontWeight: 600, color: T.accent, letterSpacing: 2, flexShrink: 0 }}>
            ▸ VULNDASH
          </span>
          <div style={{ width: 1, height: 24, background: T.border, flexShrink: 0 }} />

          <button onClick={() => { setActiveView("base"); setSeverityFilter("ALL"); setSearchQuery(""); }}
            style={{
              background: isBase ? `${T.accent}20` : "transparent",
              color: isBase ? T.accent : T.subtext,
              border: `1px solid ${isBase ? T.accent + "55" : "transparent"}`,
              padding: "4px 14px", borderRadius: 5, cursor: "pointer",
              fontSize: 12, fontWeight: 600, fontFamily: "inherit", transition: "all 0.2s", flexShrink: 0,
            }}>Base Report</button>

          {uploadedVulns && (
            <button onClick={() => { setActiveView("uploaded"); setSeverityFilter("ALL"); setSearchQuery(""); }}
              style={{
                background: !isBase ? "#10b98120" : "transparent",
                color: !isBase ? "#10b981" : T.subtext,
                border: `1px solid ${!isBase ? "#10b98155" : "transparent"}`,
                padding: "4px 14px", borderRadius: 5, cursor: "pointer",
                fontSize: 12, fontWeight: 600, fontFamily: "inherit", transition: "all 0.2s", flexShrink: 0,
              }}>↑ {uploadedName}</button>
          )}

          {/* Last scan timestamp pill */}
          {scanDate && isBase && (
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              background: T.surface2, border: `1px solid ${T.border}`,
              padding: "3px 12px", borderRadius: 20, flexShrink: 0,
            }}>
              <span style={{ fontSize: 10, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>🕐</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: T.text, fontFamily: "'DM Mono', monospace", whiteSpace: "nowrap" }}>
                {formatDate(scanDate)}
              </span>
              <span style={{ fontSize: 10, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>
                ({timeSince(scanDate)})
              </span>
            </div>
          )}

          {/* Scan error inline */}
          {scanState === SCAN_STATE.ERROR && scanErrorMsg && (
            <span style={{
              fontSize: 11, color: "#f87171", fontFamily: "'DM Mono', monospace",
              background: "#3f0f0f", border: "1px solid #7f1d1d",
              padding: "3px 10px", borderRadius: 4, flexShrink: 0, maxWidth: 280,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }} title={scanErrorMsg}>
              ✕ {scanErrorMsg}
            </span>
          )}
        </div>

        {/* Right */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, package, title…"
            style={{
              background: T.surface2, border: `1px solid ${T.border}`,
              color: T.text, padding: "5px 14px", borderRadius: 6,
              fontSize: 12, fontFamily: "inherit", outline: "none", width: 220,
            }} />

          <button onClick={() => setDarkMode((d) => !d)} style={{
            background: T.surface2, border: `1px solid ${T.border}`,
            color: T.text, padding: "5px 10px", borderRadius: 6,
            cursor: "pointer", fontSize: 14, lineHeight: 1,
          }}>{darkMode ? "☀" : "☾"}</button>

          <select value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))} style={{
            background: T.surface2, border: `1px solid ${T.border}`,
            color: T.text, padding: "5px 10px", borderRadius: 6,
            fontSize: 12, fontFamily: "inherit", cursor: "pointer", outline: "none",
          }}>
            <option value={20}>20 rows</option>
            <option value={50}>50 rows</option>
            <option value={100}>100 rows</option>
          </select>

          <input ref={fileRef} type="file" accept=".html,.json" style={{ display: "none" }} onChange={handleUpload} />
          <button onClick={() => fileRef.current.click()} style={{
            background: T.surface2, color: T.text,
            border: `1px solid ${T.border}`,
            padding: "6px 14px", borderRadius: 6, cursor: "pointer",
            fontSize: 12, fontWeight: 600, fontFamily: "inherit",
          }}>↑ Upload</button>

          {/* Autoscan button */}
          <AutoscanButton scanState={scanState} onScan={handleAutoscan} T={T} />

          {/* Log toggle — only show when there's a log */}
          {(scanLog.length > 0 || scanState !== SCAN_STATE.IDLE) && (
            <button onClick={() => setShowLog((s) => !s)} style={{
              background: showLog ? "#0ea5e920" : T.surface2,
              color: showLog ? "#0ea5e9" : T.subtext,
              border: `1px solid ${showLog ? "#0ea5e955" : T.border}`,
              padding: "5px 10px", borderRadius: 6,
              cursor: "pointer", fontSize: 11,
              fontFamily: "'DM Mono', monospace", fontWeight: 600,
            }}>LOG</button>
          )}
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ padding: "16px 12px", width: "100%", boxSizing: "border-box" }}>

        {baseLoading && activeView === "base" && (
          <div style={{ color: T.subtext, fontSize: 13, padding: 40, textAlign: "center" }}>
            Loading base report…
          </div>
        )}
        {baseError && activeView === "base" && (
          <div style={{
            background: "#1a0a0a", border: "1px solid #7f1d1d",
            borderRadius: 8, padding: 20, marginBottom: 20, color: "#fca5a5", fontSize: 13,
          }}>
            ⚠ Could not load <code>base-report.html</code>. Make sure it exists in the <code>public/</code> folder.
          </div>
        )}

        {/* Severity pills */}
        {!baseLoading && (
          <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap", paddingLeft: 2 }}>
            {[
              { key: "ALL",        label: `All (${vulns.length})` },
              ...(!isBase && uploadedVulns ? [{ key: "NEW", label: `New (${vulns.filter(v => {
                const k = `${v.id}|${normalizePkg(v.pkg)}`;
                return !baseIdSet.has(k) && (patchStatus[k] || "open") !== "patched";
              }).length})` }] : []),
              { key: "CRITICAL",   label: `Critical (${counts.CRITICAL})` },
              { key: "HIGH",       label: `High (${counts.HIGH})` },
              { key: "MEDIUM",     label: `Medium (${counts.MEDIUM})` },
              { key: "LOW",        label: `Low (${counts.LOW})` },
              { key: "NEGLIGIBLE", label: `Negligible (${counts.NEGLIGIBLE})` },
            ].map(({ key, label }) => {
              const active = severityFilter === key;
              const sev    = SEV_STYLE[key];
              const isNewBtn = key === "NEW";
              return (
                <button key={key} onClick={() => setSeverityFilter(key)} style={{
                  background: active ? (isNewBtn ? "#0ea5e9" : (sev?.bg || T.accent)) : T.surface2,
                  color: active ? "#fff" : T.subtext,
                  border: `1px solid ${active ? (isNewBtn ? "#0ea5e9" : (sev?.bg || T.accent)) : T.border}`,
                  padding: "5px 16px", borderRadius: 20,
                  cursor: "pointer", fontSize: 12, fontWeight: 600,
                  fontFamily: "inherit", transition: "all 0.18s",
                  boxShadow: active ? (isNewBtn ? "0 0 10px #0ea5e955" : (sev ? `0 0 10px ${sev.glow}` : "none")) : "none",
                }}>{label}</button>
              );
            })}
          </div>
        )}

        {/* Table */}
        {!baseLoading && (
          <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden", width: "100%" }}>
            {/* Header */}
            <div style={{
              display: "grid", gridTemplateColumns: gridCols,
              gap: 12, padding: "10px 18px",
              background: T.surface2, borderBottom: `1px solid ${T.border}`,
            }}>
              {[
                { label: "Severity",       col: "severity" },
                { label: "Title / Package",col: "title" },
                { label: "CVE / ID",       col: "id" },
                { label: "Status",         col: null },
                ...(isBase ? [{ label: "Remediation", col: null }] : []),
              ].map(({ label, col }) => {
                const isActive  = sortCol === col && col !== null;
                const upActive   = isActive && sortDir === "asc";
                const downActive = isActive && sortDir === "desc";
                return (
                  <div key={label}
                    onClick={() => col && handleSort(col)}
                    style={{ display: "flex", alignItems: "center", gap: 4, cursor: col ? "pointer" : "default", userSelect: "none" }}>
                    {col && (
                      <span style={{ display: "flex", flexDirection: "column", gap: 1, lineHeight: 1 }}>
                        <span style={{ fontSize: 8, color: upActive ? T.accent : T.subtext, lineHeight: 1 }}>▲</span>
                        <span style={{ fontSize: 8, color: downActive ? T.accent : T.subtext, lineHeight: 1 }}>▼</span>
                      </span>
                    )}
                    <span style={{
                      fontSize: 10, fontWeight: 700,
                      color: isActive ? T.accent : T.subtext,
                      textTransform: "uppercase", letterSpacing: 1.5,
                      fontFamily: "'DM Mono', monospace",
                    }}>{label}</span>
                  </div>
                );
              })}
            </div>

            {/* Rows */}
            {paginated.length === 0 ? (
              <div style={{ padding: 48, textAlign: "center", color: T.subtext, fontSize: 13 }}>
                No vulnerabilities match the current filter.
              </div>
            ) : paginated.map((v, i) => {
              const key     = `${v.id}|${normalizePkg(v.pkg)}`;
              const status  = patchStatus[key] || "open";
              const isExp   = expandedRow === key;
              const isPatched = status === "patched";
              const isNew   = !isBase && !baseIdSet.has(key) && status !== "patched";
              const rowBg   = isExp ? T.hover : (i % 2 === 0 ? T.surface : T.surface2);

              return (
                <div key={`${key}-${i}`} style={{ borderBottom: `1px solid ${T.border}` }}>
                  <div
                    onClick={() => setExpandedRow(isExp ? null : key)}
                    style={{
                      display: "grid", gridTemplateColumns: gridCols,
                      gap: 12, padding: "11px 18px", alignItems: "center",
                      background: rowBg, cursor: "pointer",
                      opacity: isPatched ? 0.45 : 1,
                      transition: "background 0.12s, opacity 0.2s",
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = T.hover}
                    onMouseLeave={(e) => e.currentTarget.style.background = rowBg}
                  >
                    <div><SevBadge level={v.severity} /></div>

                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: T.text, lineHeight: 1.4, marginBottom: 3, display: "flex", alignItems: "center", gap: 8 }}>
                        {v.title}
                        {isNew && (
                          <span style={{
                            fontSize: 9, fontWeight: 800, letterSpacing: 1.2,
                            background: "#0ea5e9", color: "#fff",
                            padding: "2px 7px", borderRadius: 3,
                            fontFamily: "'DM Mono', monospace",
                            boxShadow: "0 0 8px #0ea5e955",
                            whiteSpace: "nowrap", flexShrink: 0,
                          }}>NEW</span>
                        )}
                      </div>
                      <div style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>{v.pkg}</div>
                    </div>

                    <div>
                      <a href={nvdUrl(v.id)} target="_blank" rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{ color: T.accent, fontSize: 12, textDecoration: "none", fontFamily: "'DM Mono', monospace" }}>
                        {v.id}
                      </a>
                    </div>

                    <div><StatusBtn status={status} onClick={(e) => cycleStatus(e, key)} /></div>

                    {isBase && (
                      <div>
                        <a href={nvdUrl(v.id)} target="_blank" rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          style={{
                            color: "#4ade80", fontSize: 11, textDecoration: "none",
                            border: "1px solid #16653433", padding: "3px 10px",
                            borderRadius: 4, background: "#052e1699",
                            display: "inline-block", fontFamily: "'DM Mono', monospace",
                          }}>
                          {isGhsa(v.id) ? "GitHub ↗" : "NIST ↗"}
                        </a>
                      </div>
                    )}
                  </div>

                  {isExp && (
                    <div style={{
                      background: darkMode ? "#050d1a" : "#eef4ff",
                      borderTop: `1px solid ${T.border}`,
                      padding: "14px 22px 14px 40px",
                      fontSize: 12, color: T.subtext,
                    }}>
                      <div style={{ display: "flex", gap: 28, flexWrap: "wrap", marginBottom: 10 }}>
                        <div><span style={{ color: T.text, fontWeight: 600 }}>ID:</span> {v.id}</div>
                        <div><span style={{ color: T.text, fontWeight: 600 }}>Package:</span> {v.pkg}</div>
                        <div>
                          <span style={{ color: T.text, fontWeight: 600 }}>Status: </span>
                          <StatusBtn status={status} onClick={(e) => cycleStatus(e, key)} />
                          <span style={{ marginLeft: 8, fontSize: 10, color: T.subtext }}>(click to cycle)</span>
                        </div>
                      </div>
                      <div>
                        <span style={{ color: T.text, fontWeight: 600 }}>Links: </span>
                        <a href={nvdUrl(v.id)} target="_blank" rel="noreferrer"
                          style={{ color: T.accent, marginRight: 16, fontSize: 12 }}>
                          {isGhsa(v.id) ? "GitHub Advisory ↗" : "NIST NVD ↗"}
                        </a>
                        <a href={`https://www.google.com/search?q=${encodeURIComponent(v.id + " patch fix remediation")}`}
                          target="_blank" rel="noreferrer"
                          style={{ color: "#4ade80", fontSize: 12 }}>
                          Search patches ↗
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Pagination */}
        {!baseLoading && filtered.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", marginTop: 16, gap: 6 }}>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} style={{
              background: "transparent", color: page === 1 ? T.subtext : T.text,
              border: "none", padding: "4px 8px", borderRadius: 5,
              cursor: page === 1 ? "not-allowed" : "pointer",
              fontSize: 16, opacity: page === 1 ? 0.3 : 1, lineHeight: 1,
            }}>‹</button>

            {(() => {
              const pages = [];
              const win = 2;
              for (let p = 1; p <= totalPages; p++) {
                if (p === 1 || p === totalPages || (p >= page - win && p <= page + win)) {
                  pages.push(p);
                } else if (pages[pages.length - 1] !== "…") {
                  pages.push("…");
                }
              }
              return pages.map((p, i) =>
                p === "…" ? (
                  <span key={`e-${i}`} style={{ color: T.subtext, fontSize: 13, padding: "0 4px" }}>…</span>
                ) : (
                  <button key={p} onClick={() => setPage(p)} style={{
                    background: p === page ? T.accent : T.surface2,
                    color: p === page ? "#fff" : T.subtext,
                    border: `1px solid ${p === page ? T.accent : T.border}`,
                    borderRadius: "50%", width: 32, height: 32,
                    cursor: "pointer", fontSize: 13,
                    fontFamily: "'DM Mono', monospace", fontWeight: 600,
                    transition: "all 0.15s", display: "flex", alignItems: "center", justifyContent: "center",
                  }}>{p}</button>
                )
              );
            })()}

            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} style={{
              background: "transparent", color: page === totalPages ? T.subtext : T.text,
              border: "none", padding: "4px 8px", borderRadius: 5,
              cursor: page === totalPages ? "not-allowed" : "pointer",
              fontSize: 16, opacity: page === totalPages ? 0.3 : 1, lineHeight: 1,
            }}>›</button>
          </div>
        )}

        {!baseLoading && (
          <div style={{ marginTop: 12, fontSize: 11, color: T.subtext, textAlign: "right" }}>
            Click any row to expand · Click status badge to cycle Open → Patched → Ignored
          </div>
        )}
      </div>

      {/* Scan log drawer */}
      <ScanLogDrawer log={scanLog} show={showLog} onClose={() => setShowLog(false)} T={T} />
    </div>
  );
}
