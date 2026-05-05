import { useState, useMemo, useEffect, useRef } from "react";

// ── Parser: works on both base report and uploaded reports ─────────────────
function parseTrivyHtml(html) {
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
    vulns.push({ severity, id, pkg, title });
  });
  return vulns;
}

// ── Helpers ────────────────────────────────────────────────────────────────
const nvdUrl = (id) =>
  id.startsWith("GHSA-")
    ? `https://github.com/advisories/${id}`
    : `https://nvd.nist.gov/vuln/detail/${id}`;

const isGhsa = (id) => id.startsWith("GHSA-");

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4 };

const SEV_STYLE = {
  CRITICAL: { bg: "#e8193c", glow: "#e8193c55" },
  HIGH:     { bg: "#f97316", glow: "#f9731655" },
  MEDIUM:   { bg: "#eab308", glow: "#eab30855" },
  LOW:      { bg: "#6b7280", glow: "#6b728055" },
  NEGLIGIBLE:{ bg: "#374151", glow: "#37415155" },
};

const STATUS_CYCLE = ["open", "patched", "ignored"];
const STATUS_STYLE = {
  open:    { bg: "#1e293b", color: "#94a3b8", border: "#334155", label: "Open" },
  patched: { bg: "#052e16", color: "#4ade80", border: "#166534", label: "✓ Patched" },
  ignored: { bg: "#1c1917", color: "#a8a29e", border: "#44403c", label: "~ Ignored" },
};

// ── Sub-components ─────────────────────────────────────────────────────────
function SevBadge({ level }) {
  const s = SEV_STYLE[level] || { bg: "#374151", glow: "#37415155" };
  return (
    <span style={{
      background: s.bg,
      color: "#fff",
      padding: "3px 10px",
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 800,
      letterSpacing: 1.2,
      fontFamily: "'DM Mono', monospace",
      boxShadow: `0 0 8px ${s.glow}`,
      display: "inline-block",
      whiteSpace: "nowrap",
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

// ── Main App ───────────────────────────────────────────────────────────────
export default function App() {
  const [baseVulns, setBaseVulns]       = useState([]);
  const [uploadedVulns, setUploadedVulns] = useState(null);
  const [uploadedName, setUploadedName] = useState("");
  const [activeView, setActiveView]     = useState("base");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [searchQuery, setSearchQuery]   = useState("");
  const [patchStatus, setPatchStatus]   = useState({});
  const [expandedRow, setExpandedRow]   = useState(null);
  const [darkMode, setDarkMode]         = useState(true);
  const [pageSize, setPageSize]         = useState(20);
  const [page, setPage]                 = useState(1);
  const [baseLoading, setBaseLoading]   = useState(true);
  const [baseError, setBaseError]       = useState(false);
  const fileRef = useRef();

  // Load base report from public/
  useEffect(() => {
    fetch("/base-report.html")
      .then((r) => {
        if (!r.ok) throw new Error("Not found");
        return r.text();
      })
      .then((html) => {
        setBaseVulns(parseTrivyHtml(html));
        setBaseLoading(false);
      })
      .catch(() => {
        setBaseError(true);
        setBaseLoading(false);
      });
  }, []);

  const vulns = activeView === "base" ? baseVulns : (uploadedVulns || []);

  // Reset page on filter/search/view change
  useEffect(() => { setPage(1); }, [severityFilter, searchQuery, activeView, pageSize]);

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 };
    vulns.forEach((v) => { if (c[v.severity] !== undefined) c[v.severity]++; });
    return c;
  }, [vulns]);

  const filtered = useMemo(() => {
    let list = [...vulns];
    if (severityFilter !== "ALL") list = list.filter((v) => v.severity === severityFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((v) =>
        v.id?.toLowerCase().includes(q) ||
        v.pkg?.toLowerCase().includes(q) ||
        v.title?.toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    return list;
  }, [vulns, severityFilter, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paginated  = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploadedName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const parsed = parseTrivyHtml(ev.target.result);
      setUploadedVulns(parsed);
      setActiveView("uploaded");
      setSeverityFilter("ALL");
      setSearchQuery("");
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const cycleStatus = (e, key) => {
    e.stopPropagation();
    setPatchStatus((prev) => {
      const cur = prev[key] || "open";
      const next = STATUS_CYCLE[(STATUS_CYCLE.indexOf(cur) + 1) % STATUS_CYCLE.length];
      return { ...prev, [key]: next };
    });
  };

  // ── Theme ──────────────────────────────────────────────────────────────
  const T = darkMode ? {
    bg:       "#080f1a",
    surface:  "#0d1829",
    surface2: "#111f33",
    border:   "#1a2d48",
    text:     "#c8daf0",
    subtext:  "#4a6080",
    hover:    "#162035",
    accent:   "#3b82f6",
  } : {
    bg:       "#f1f5fb",
    surface:  "#ffffff",
    surface2: "#f7f9fd",
    border:   "#dde5f0",
    text:     "#0f1f38",
    subtext:  "#7a90b0",
    hover:    "#eef3fc",
    accent:   "#2563eb",
  };

  const isBase = activeView === "base";

  // ── Grid columns ───────────────────────────────────────────────────────
  const gridCols = isBase
    ? "100px minmax(0,1fr) 190px 110px 140px"
    : "100px minmax(0,1fr) 190px 110px";

  return (
    <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: "'DM Sans', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500;600&display=swap" rel="stylesheet" />

      {/* ── Topbar ── */}
      <div style={{
        position: "sticky", top: 0, zIndex: 200,
        background: T.surface, borderBottom: `1px solid ${T.border}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 28px", height: 52,
        boxShadow: darkMode ? "0 2px 20px #00000060" : "0 2px 10px #0000001a",
      }}>
        {/* Left */}
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: 12, fontWeight: 600, color: T.accent, letterSpacing: 2 }}>
            ▸ TRIVYDASH
          </span>
          <div style={{ width: 1, height: 24, background: T.border }} />
          <button onClick={() => { setActiveView("base"); setSeverityFilter("ALL"); setSearchQuery(""); }}
            style={{
              background: isBase ? `${T.accent}20` : "transparent",
              color: isBase ? T.accent : T.subtext,
              border: `1px solid ${isBase ? T.accent + "55" : "transparent"}`,
              padding: "4px 14px", borderRadius: 5, cursor: "pointer",
              fontSize: 12, fontWeight: 600, fontFamily: "inherit", transition: "all 0.2s",
            }}>Base Report</button>
          {uploadedVulns && (
            <button onClick={() => { setActiveView("uploaded"); setSeverityFilter("ALL"); setSearchQuery(""); }}
              style={{
                background: !isBase ? "#10b98120" : "transparent",
                color: !isBase ? "#10b981" : T.subtext,
                border: `1px solid ${!isBase ? "#10b98155" : "transparent"}`,
                padding: "4px 14px", borderRadius: 5, cursor: "pointer",
                fontSize: 12, fontWeight: 600, fontFamily: "inherit", transition: "all 0.2s",
              }}>↑ {uploadedName}</button>
          )}
        </div>

        {/* Right */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, package, title…"
            style={{
              background: T.surface2, border: `1px solid ${T.border}`,
              color: T.text, padding: "5px 14px", borderRadius: 6,
              fontSize: 12, fontFamily: "inherit", outline: "none", width: 240,
            }} />
          <button onClick={() => setDarkMode((d) => !d)} style={{
            background: T.surface2, border: `1px solid ${T.border}`,
            color: T.text, padding: "5px 10px", borderRadius: 6,
            cursor: "pointer", fontSize: 14, lineHeight: 1,
          }}>{darkMode ? "☀" : "☾"}</button>
          {/* Entries per page dropdown */}
          <select value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))} style={{
            background: T.surface2, border: `1px solid ${T.border}`,
            color: T.text, padding: "5px 10px", borderRadius: 6,
            fontSize: 12, fontFamily: "inherit", cursor: "pointer", outline: "none",
          }}>
            <option value={20}>20 entries</option>
            <option value={50}>50 entries</option>
            <option value={100}>100 entries</option>
          </select>
          <input ref={fileRef} type="file" accept=".html,.xml" style={{ display: "none" }} onChange={handleUpload} />
          <button onClick={() => fileRef.current.click()} style={{
            background: T.accent, color: "#fff", border: "none",
            padding: "6px 18px", borderRadius: 6, cursor: "pointer",
            fontSize: 12, fontWeight: 700, fontFamily: "inherit", letterSpacing: 0.3,
            boxShadow: `0 0 12px ${T.accent}55`,
          }}>↑ Upload Report</button>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ padding: "24px 28px", maxWidth: "100%", boxSizing: "border-box" }}>

        {/* Header */}
        <div style={{ marginBottom: 20, display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>
            Trivy Report — OpenSILEX
          </h1>
          <span style={{ fontSize: 12, color: T.subtext }}>
            {isBase ? "Base · 2026" : `Uploaded · ${uploadedName}`}
          </span>
          {!baseLoading && !baseError && (
            <span style={{
              background: `${T.accent}20`, color: T.accent,
              border: `1px solid ${T.accent}44`,
              borderRadius: 4, padding: "2px 12px", fontSize: 12, fontWeight: 700,
              fontFamily: "'DM Mono', monospace",
            }}>{vulns.length} vulns</span>
          )}
        </div>

        {/* Loading / error state */}
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
            ⚠ Could not load <code>base-report.html</code>. Make sure you placed it in the <code>public/</code> folder of your project.
          </div>
        )}

        {/* ── Severity pills ── */}
        {!baseLoading && (
          <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
            {[
              { key: "ALL",       label: `All (${vulns.length})` },
              { key: "CRITICAL",  label: `Critical (${counts.CRITICAL})` },
              { key: "HIGH",      label: `High (${counts.HIGH})` },
              { key: "MEDIUM",    label: `Medium (${counts.MEDIUM})` },
              { key: "LOW",       label: `Low (${counts.LOW})` },
              { key: "NEGLIGIBLE",label: `Negligible (${counts.NEGLIGIBLE})` },
            ].map(({ key, label }) => {
              const active = severityFilter === key;
              const sev = SEV_STYLE[key];
              return (
                <button key={key} onClick={() => setSeverityFilter(key)} style={{
                  background: active ? (sev?.bg || T.accent) : T.surface2,
                  color: active ? "#fff" : T.subtext,
                  border: `1px solid ${active ? (sev?.bg || T.accent) : T.border}`,
                  padding: "5px 16px", borderRadius: 20,
                  cursor: "pointer", fontSize: 12, fontWeight: 600,
                  fontFamily: "inherit", transition: "all 0.18s",
                  boxShadow: active && sev ? `0 0 10px ${sev.glow}` : "none",
                }}>{label}</button>
              );
            })}
          </div>
        )}

        {/* ── Table ── */}
        {!baseLoading && (
          <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden" }}>
            {/* Header row */}
            <div style={{
              display: "grid", gridTemplateColumns: gridCols,
              gap: 12, padding: "10px 18px",
              background: T.surface2, borderBottom: `1px solid ${T.border}`,
            }}>
              {["Severity", "Title / Package", "CVE / ID", "Status",
                ...(isBase ? ["Remediation"] : [])
              ].map((h) => (
                <span key={h} style={{
                  fontSize: 10, fontWeight: 700, color: T.subtext,
                  textTransform: "uppercase", letterSpacing: 1.5,
                  fontFamily: "'DM Mono', monospace",
                }}>{h}</span>
              ))}
            </div>

            {/* Data rows */}
            {paginated.length === 0 ? (
              <div style={{ padding: 48, textAlign: "center", color: T.subtext, fontSize: 13 }}>
                No vulnerabilities match the current filter.
              </div>
            ) : paginated.map((v, i) => {
              const key = `${v.id}|${v.pkg}`;
              const status = patchStatus[key] || "open";
              const isExp = expandedRow === key;
              const isPatched = status === "patched";
              const rowBg = isExp ? T.hover : (i % 2 === 0 ? T.surface : T.surface2);

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
                    {/* Severity */}
                    <div><SevBadge level={v.severity} /></div>

                    {/* Title + package */}
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: T.text, lineHeight: 1.4, marginBottom: 3 }}>
                        {v.title}
                      </div>
                      <div style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>
                        {v.pkg}
                      </div>
                    </div>

                    {/* CVE ID */}
                    <div>
                      <a href={nvdUrl(v.id)} target="_blank" rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{ color: T.accent, fontSize: 12, textDecoration: "none", fontFamily: "'DM Mono', monospace" }}>
                        {v.id}
                      </a>
                    </div>

                    {/* Status */}
                    <div>
                      <StatusBtn status={status} onClick={(e) => cycleStatus(e, key)} />
                    </div>

                    {/* Remediation (base only) */}
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

                  {/* Expanded detail */}
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

        {/* ── Pagination ── */}
        {!baseLoading && filtered.length > 0 && (
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "center",
            marginTop: 16, gap: 6,
          }}>
            {/* ‹ arrow */}
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} style={{
              background: "transparent", color: page === 1 ? T.subtext : T.text,
              border: "none", padding: "4px 8px", borderRadius: 5,
              cursor: page === 1 ? "not-allowed" : "pointer",
              fontSize: 16, opacity: page === 1 ? 0.3 : 1, lineHeight: 1,
            }}>‹</button>

            {/* Page number buttons */}
            {(() => {
              const pages = [];
              const window = 2;
              for (let p = 1; p <= totalPages; p++) {
                if (p === 1 || p === totalPages || (p >= page - window && p <= page + window)) {
                  pages.push(p);
                } else if (pages[pages.length - 1] !== "…") {
                  pages.push("…");
                }
              }
              return pages.map((p, i) =>
                p === "…" ? (
                  <span key={`ellipsis-${i}`} style={{ color: T.subtext, fontSize: 13, padding: "0 4px" }}>…</span>
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

            {/* › arrow */}
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} style={{
              background: "transparent", color: page === totalPages ? T.subtext : T.text,
              border: "none", padding: "4px 8px", borderRadius: 5,
              cursor: page === totalPages ? "not-allowed" : "pointer",
              fontSize: 16, opacity: page === totalPages ? 0.3 : 1, lineHeight: 1,
            }}>›</button>
          </div>
        )}

        {/* Footer hint */}
        {!baseLoading && (
          <div style={{ marginTop: 12, fontSize: 11, color: T.subtext, textAlign: "right" }}>
            Click any row to expand · Click status badge to cycle Open → Patched → Ignored
          </div>
        )}
      </div>
    </div>
  );
}
