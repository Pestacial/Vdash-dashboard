import { useState, useMemo, useEffect, useRef } from "react";

// ── AI / Agent configuration ──────────────────────────────────────────────────
const OPENROUTER_KEY = import.meta.env.VITE_OPENROUTER_KEY || "";
const AGENT_URL      = import.meta.env.VITE_AGENT_URL      || "http://100.95.217.28:8000";
const CONTAINER      = "sandbox-opensilex-docker-opensilexapp";

const AI_MODELS = [
  "openai/gpt-oss-120b:free",           // 131K context, works confirmed
  "nvidia/nemotron-3-super-120b-a12b:free", // 120B MoE, strong instruction following
  "meta-llama/llama-3.3-70b-instruct:free", // reliable fallback, good at JSON
];

// Builds a LEAN prompt — only essential fields, no redundant data
function buildAiPrompt(vulns) {
  // Separate deb vs jar up front — jars are always not_fixable
  const debVulns = vulns.filter(
    (v) => !(v.target && v.target.toLowerCase().includes("java")) &&
            !(v.pkg && v.pkg.toLowerCase().endsWith(".jar"))
  );
  const jarVulns = vulns.filter(
    (v) => (v.target && v.target.toLowerCase().includes("java")) ||
            (v.pkg && v.pkg.replace(/\s*\(.*?\)\s*$/, "").trim().toLowerCase().endsWith(".jar"))
  );

  // For deb packages: only send id, pkg, fixedVersion — nothing else
  const debItems = debVulns.map((v) => ({
    id:  v.id,
    pkg: v.pkg.replace(/\s*\(.*?\)\s*$/, "").trim(), // strip " (version)" suffix
    fix: v.fixedVersion || "",
  }));
  console.log("[AI] debVulns count:", debVulns.length, "jarVulns count:", jarVulns.length);
  console.log("[AI] sample debItem:", JSON.stringify(debItems.slice(0, 3), null, 2));

  return {
    debItems,
    jarVulns,
    prompt: `You are a Linux security expert. Fix Ubuntu deb package vulnerabilities in Docker container "${CONTAINER}".

Rules:
- If "fix" field is empty → not_fixable, reason: "no_fix_available"
- If "fix" field has a version → fixable with: docker exec ${CONTAINER} apt-get install -y --only-upgrade <pkg>=<fix>
- Group ALL fixable packages into as few apt-get install commands as possible
- ALWAYS include apt-get update as the very first command
- Return ONLY raw JSON — no markdown, no explanation, no text outside the JSON

JSON format (no extra fields):
{
  "summary": "X of Y deb vulnerabilities auto-fixable.",
  "fixable": [{"id":"CVE-X","pkg":"name","commands":["cmd1","cmd2"],"risk":"low"}],
  "not_fixable": [{"id":"CVE-X","pkg":"name","reason":"no_fix_available"}]
}

Packages to analyze:
${JSON.stringify(debItems)}`,
  };
}

// Calls OpenRouter — lean prompt, jar packages handled locally (no AI tokens wasted)
async function callAi(vulns) {
  const { debItems, jarVulns, prompt } = buildAiPrompt(vulns);

  // Build jar not_fixable entries locally — no AI call needed
  const jarNotFixable = jarVulns.map((v) => ({
    id:     v.id,
    pkg:    v.pkg.replace(/\s*\(.*?\)\s*$/, "").trim(),
    reason: "requires_rebuild",
    note:   "Java library inside opensilex.jar — requires source code rebuild to update.",
  }));

  for (let i = 0; i < AI_MODELS.length; i++) {
    const model = AI_MODELS[i];
    try {
      const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method:  "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${OPENROUTER_KEY}`,
          "HTTP-Referer":  "https://github.com/Pestacial/vuln-dashboard",
          "X-Title":       "PHIS Vuln Dashboard",
        },
        body: JSON.stringify({
          model,
          max_tokens: 8000,
          messages: [{ role: "user", content: prompt }],
          response_format: { type: "json_object" },
        }),
      });

      if (response.status === 429) {
        console.warn(`[AI] ${model} rate limited, trying next...`);
        continue;
      if (response.status === 429) {
        console.warn(`[AI] ${model} rate limited, waiting 4s then trying next...`);
        await new Promise(r => setTimeout(r, 4000));
        continue;
}
      }
      if (!response.ok) throw new Error(`OpenRouter ${response.status}: ${await response.text()}`);

      const data   = await response.json();
      let text     = data.choices?.[0]?.message?.content || "";
      console.log("[AI] RAW RESPONSE (first 1000 chars):", text.slice(0, 1000));
      const usage  = data.usage;
      console.log(`[AI] ${model} — tokens: prompt=${usage?.prompt_tokens} completion=${usage?.completion_tokens} total=${usage?.total_tokens}`);

      // Check if response was cut off (finish_reason = "length" means truncated)
      const finishReason = data.choices?.[0]?.finish_reason;
      if (finishReason === "length") {
        console.warn(`[AI] ${model} response truncated (finish_reason=length). Trying fallback...`);
        continue; // try next model instead of failing with a parse error
      }

      // Strip markdown fences if present
      text = text.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
      const jsonStart = text.indexOf("{");
      const jsonEnd   = text.lastIndexOf("}");
      if (jsonStart !== -1 && jsonEnd !== -1) text = text.slice(jsonStart, jsonEnd + 1);

      const parsed = JSON.parse(text);
      parsed._modelUsed = model;

      // Merge jar not_fixable into the AI's not_fixable list
      parsed.not_fixable = [...(parsed.not_fixable || []), ...jarNotFixable];
      parsed.summary     = `${(parsed.fixable || []).length} of ${debItems.length} deb vulnerabilities can be auto-fixed. ${jarNotFixable.length} Java JARs require source rebuild.`;

      return parsed;

    } catch (err) {
      if (i === AI_MODELS.length - 1) throw err;
      console.warn(`[AI] ${model} failed (${err.message}), trying fallback...`);
    }
  }
  throw new Error("All AI models failed. Try again in a few minutes.");
}

// Calls the Kali agent's /explain-local endpoint which calls Ollama
async function getOllamaExplanation(cve, pkg, commands) {
  const response = await fetch(`${AGENT_URL}/explain-local`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ cve, pkg, commands }),
  });
  if (!response.ok) throw new Error(`Agent error: ${response.status}`);
  const data = await response.json();
  return data.explanation || "No explanation returned.";
}



// ── Normalize pkg string for consistent key matching ─────────────────────
function normalizePkg(pkg) {
  // Remove epoch prefix e.g. "1:2.39.3" → "2.39.3" for consistent matching
  return pkg.replace(/\((\d+):/, "(");
}
function parseTrivyJson(text) {
  try {
    const data = JSON.parse(text);
    const vulns = [];
    // Support both single report {Results:[]} and array of reports [{Results:[]}]
    const reports = Array.isArray(data) ? data : [data];
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
    return vulns;
  } catch (e) {
    console.warn("JSON parse failed", e);
    return [];
  }
}

// ── Parser: handles simple HTML table AND scan2html (i9=[...]) formats ──────
function parseTrivyHtml(html) {
  // ── Format 1: scan2html — extract i9=[...] embedded JSON ──────────────
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

  // ── Format 2: simple HTML table (Severity | ID | Package | Title) ─────
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
  const [darkMode, setDarkMode]         = useState(false);
  const [pageSize, setPageSize]         = useState(20);
  const [page, setPage]                 = useState(1);
  const [baseLoading, setBaseLoading]   = useState(true);
  const [baseError, setBaseError]       = useState(false);
  const [sortCol, setSortCol]           = useState(null); // "severity"|"id"|"pkg"|"title"
  const [sortDir, setSortDir]           = useState(null); // "asc"|"desc"|null
  const fileRef = useRef();

    // ── AI Remediation state ──────────────────────────────────────────────────
  const [aiLoading,       setAiLoading]       = useState(false);
  const [aiError,         setAiError]         = useState("");
  const [aiResult,        setAiResult]        = useState(null);
  const [aiPanelOpen,     setAiPanelOpen]     = useState(false);
  const [backupStatus,    setBackupStatus]    = useState(null);   // null | "running" | "done" | "failed"
  const [remediateStatus, setRemediateStatus] = useState(null);   // null | "running" | { results }
  const [selectedFixes,   setSelectedFixes]   = useState(new Set());
  const [agentOnline,     setAgentOnline]     = useState(null);   // null | true | false
  const [aiModelUsed,     setAiModelUsed]     = useState("");
  // Per-fix Ollama consent modal
  const [consentFix,      setConsentFix]      = useState(null);   // the fix object being explained
  const [consentText,     setConsentText]     = useState("");     // Ollama's explanation
  const [consentLoading,  setConsentLoading]  = useState(false);
  const [consentApplying, setConsentApplying] = useState(false);
  const [consentResult,   setConsentResult]   = useState(null);

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
  useEffect(() => { setPage(1); }, [severityFilter, searchQuery, activeView, pageSize, sortCol, sortDir]);

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 };
    vulns.forEach((v) => { if (c[v.severity] !== undefined) c[v.severity]++; });
    return c;
  }, [vulns]);

  // ── Base CVE+pkg set for diff comparison ──────────────────────────────
  const baseIdSet = useMemo(() => {
    const s = new Set();
    baseVulns.forEach((v) => s.add(`${v.id}|${normalizePkg(v.pkg)}`));
    return s;
  }, [baseVulns]);

  const filtered = useMemo(() => {
    let list = [...vulns];
    if (severityFilter === "NEW") list = list.filter((v) => {
        const key = `${v.id}|${normalizePkg(v.pkg)}`;
        return !baseIdSet.has(key) && (patchStatus[key] || "open") !== "patched";
      });
    else if (severityFilter !== "ALL") list = list.filter((v) => v.severity === severityFilter);
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
        let va = a[sortCol] ?? "";
        let vb = b[sortCol] ?? "";
        if (sortCol === "severity") {
          va = SEVERITY_ORDER[a.severity] ?? 9;
          vb = SEVERITY_ORDER[b.severity] ?? 9;
          return sortDir === "asc" ? va - vb : vb - va;
        }
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
      const isJson = file.name.toLowerCase().endsWith(".json");
      const parsed = isJson ? parseTrivyJson(content) : parseTrivyHtml(content);

      // Build a set of CVE+pkg keys from the uploaded report
      const uploadedKeys = new Set(parsed.map((v) => `${v.id}|${normalizePkg(v.pkg)}`));

      // Auto-mark base vulns not present in the uploaded report as patched
      setPatchStatus((prev) => {
        const updated = { ...prev };
        baseVulns.forEach((v) => {
          const key = `${v.id}|${normalizePkg(v.pkg)}`;
          if (!uploadedKeys.has(key) && !prev[key]) {
            updated[key] = "patched";
          }
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
    if (sortCol !== col) { setSortCol(col); setSortDir("asc"); }
    else if (sortDir === "asc") setSortDir("desc");
    else if (sortDir === "desc") { setSortCol(null); setSortDir(null); }
  };

  const cycleStatus = (e, key) => {
    e.stopPropagation();
    setPatchStatus((prev) => {
      const cur = prev[key] || "open";
      const next = STATUS_CYCLE[(STATUS_CYCLE.indexOf(cur) + 1) % STATUS_CYCLE.length];
      return { ...prev, [key]: next };
    });
  };

    // ── Check if Kali agent is reachable ───────────────────────────────────────
  const checkAgent = async () => {
    try {
      const r = await fetch(`${AGENT_URL}/ping`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({}),
      });
      const ok = (await r.json()).status === "ok";
      setAgentOnline(ok);
      return ok;
    } catch {
      setAgentOnline(false);
      return false;
    }
  };

  // ── Send full report to Gemini for bulk analysis ────────────────────────────
  const handleAiAnalyze = async () => {
    if (!OPENROUTER_KEY) {
      setAiError("VITE_OPENROUTER_KEY is not set in Vercel environment variables.");
      setAiPanelOpen(true);
      return;
    }
    setAiLoading(true);
    setAiError("");
    // don't wipe previous result until new one arrives — keeps panel readable if user re-clicks
    // setAiResult(null);  // removed: result now only clears when new data comes in
    setAiPanelOpen(true);
    setBackupStatus(null);
    setRemediateStatus(null);
    setSelectedFixes(new Set());
    setAiModelUsed("");
    setConsentFix(null);

    checkAgent(); // check in background while Gemini thinks

    try {
      const result = await callAi(vulns);
      setAiResult(result);
      setAiModelUsed(result._modelUsed || "");
      setSelectedFixes(new Set((result.fixable || []).map((f) => f.id)));
    } catch (e) {
      setAiError(e.message);
    } finally {
      setAiLoading(false);
    }
  };

  // ── Create backup of container package state ────────────────────────────────
  const handleBackup = async () => {
    setBackupStatus("running");
    try {
      const r = await fetch(`${AGENT_URL}/backup`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({}),
      });
      const d = await r.json();
      setBackupStatus(d.success ? "done" : "failed");
    } catch {
      setBackupStatus("failed");
    }
  };

  // ── Apply all selected fixes in bulk ────────────────────────────────────────
  const handleApplyFixes = async () => {
    if (!aiResult) return;
    const seen = new Set();
    const cmds = [];
    let needsUpdate = false;
    (aiResult.fixable || [])
      .filter((f) => selectedFixes.has(f.id))
      .forEach((fix) => {
        (fix.commands || []).forEach((cmd) => {
          if (cmd.includes("apt-get update")) { needsUpdate = true; }
          else if (!seen.has(cmd)) { seen.add(cmd); cmds.push(cmd); }
        });
      });
    const finalCmds = [
      ...(needsUpdate ? [`docker exec ${CONTAINER} apt-get update -qq`] : []),
      ...cmds,
    ];
    if (finalCmds.length === 0) return;
    setRemediateStatus("running");
    try {
      const r = await fetch(`${AGENT_URL}/remediate`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ commands: finalCmds }),
      });
      setRemediateStatus(await r.json());
    } catch (e) {
      setRemediateStatus({ error: e.message, results: [], total: 0, succeeded: 0, failed: 0 });
    }
  };

  // ── Open per-fix Ollama consent modal ───────────────────────────────────────
  const handleExplainFix = async (fix) => {
    setConsentFix(fix);
    setConsentText("");
    setConsentLoading(true);
    setConsentApplying(false);
    setConsentResult(null);
    try {
      const explanation = await getOllamaExplanation(fix.id, fix.pkg, fix.commands);
      setConsentText(explanation);
    } catch (e) {
      setConsentText(`Could not reach agent: ${e.message}`);
    } finally {
      setConsentLoading(false);
    }
  };

  // ── Apply a single fix after Ollama consent ─────────────────────────────────
  const handleConsentApply = async () => {
    if (!consentFix) return;
    setConsentApplying(true);
    try {
      const r = await fetch(`${AGENT_URL}/remediate`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ commands: consentFix.commands }),
      });
      setConsentResult(await r.json());
    } catch (e) {
      setConsentResult({ error: e.message, results: [], total: 0, succeeded: 0, failed: 0 });
    } finally {
      setConsentApplying(false);
    }
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
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: 12, fontWeight: 600, color: T.accent, letterSpacing: 2 }}>
            ▸ VULNDASH
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
                    {/* ── AI Remediate button ── */}
          <button
            onClick={handleAiAnalyze}
            disabled={aiLoading || vulns.length === 0}
            title={vulns.length === 0 ? "Load a report first" : "Analyze with AI and get auto-fix commands"}
            style={{
              background:   aiLoading ? T.surface2 : "linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%)",
              color:        aiLoading ? T.subtext : "#fff",
              border:       "none",
              padding:      "6px 16px",
              borderRadius: 6,
              cursor:       aiLoading || vulns.length === 0 ? "not-allowed" : "pointer",
              fontSize:     12,
              fontWeight:   700,
              fontFamily:   "inherit",
              letterSpacing: 0.3,
              boxShadow:    aiLoading ? "none" : "0 0 14px #7c3aed55",
              transition:   "all 0.2s",
              display:      "flex",
              alignItems:   "center",
              gap:          6,
              opacity:      vulns.length === 0 ? 0.4 : 1,
            }}>
            {aiLoading
              ? <><span style={{ display: "inline-block", animation: "ai-spin 1s linear infinite" }}>⟳</span> Analyzing…</>
              : <>🤖 Remediate with AI</>}
          </button>
          <input ref={fileRef} type="file" accept=".html,.json" style={{ display: "none" }} onChange={handleUpload} />
          <button onClick={() => fileRef.current.click()} style={{
            background: T.accent, color: "#fff", border: "none",
            padding: "6px 18px", borderRadius: 6, cursor: "pointer",
            fontSize: 12, fontWeight: 700, fontFamily: "inherit", letterSpacing: 0.3,
            boxShadow: `0 0 12px ${T.accent}55`,
          }}>↑ Upload Report</button>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ padding: "16px 12px", width: "100%", boxSizing: "border-box" }}>

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
          <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap", paddingLeft: 2 }}>
            {[
              { key: "ALL",       label: `All (${vulns.length})` },
              ...(!isBase && uploadedVulns ? [{ key: "NEW", label: `New (${vulns.filter(v => { const k = `${v.id}|${normalizePkg(v.pkg)}`; return !baseIdSet.has(k) && (patchStatus[k] || "open") !== "patched"; }).length})` }] : []),
              { key: "CRITICAL",  label: `Critical (${counts.CRITICAL})` },
              { key: "HIGH",      label: `High (${counts.HIGH})` },
              { key: "MEDIUM",    label: `Medium (${counts.MEDIUM})` },
              { key: "LOW",       label: `Low (${counts.LOW})` },
              { key: "NEGLIGIBLE",label: `Negligible (${counts.NEGLIGIBLE})` },
            ].map(({ key, label }) => {
              const active = severityFilter === key;
              const sev = SEV_STYLE[key];
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

        {/* ── Table ── */}
        {!baseLoading && (
          <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden", width: "100%" }}>
            {/* Header row */}
            <div style={{
              display: "grid", gridTemplateColumns: gridCols,
              gap: 12, padding: "10px 18px",
              background: T.surface2, borderBottom: `1px solid ${T.border}`,
            }}>
              {[
                { label: "Severity", col: "severity" },
                { label: "Title / Package", col: "title" },
                { label: "CVE / ID", col: "id" },
                { label: "Status", col: null },
                ...(isBase ? [{ label: "Remediation", col: null }] : []),
              ].map(({ label, col }) => {
                const isActive = sortCol === col && col !== null;
                const upActive = isActive && sortDir === "asc";
                const downActive = isActive && sortDir === "desc";
                return (
                  <div key={label}
                    onClick={() => col && handleSort(col)}
                    style={{
                      display: "flex", alignItems: "center", gap: 4,
                      cursor: col ? "pointer" : "default",
                      userSelect: "none",
                    }}>
                    {col && (
                      <span style={{ display: "flex", flexDirection: "column", gap: 1, lineHeight: 1 }}>
                        <span style={{ fontSize: 8, color: upActive ? T.accent : T.subtext, lineHeight: 1 }}>▲</span>
                        <span style={{ fontSize: 8, color: downActive ? T.accent : T.subtext, lineHeight: 1 }}>▼</span>
                      </span>
                    )}
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: isActive ? T.accent : T.subtext,
                      textTransform: "uppercase", letterSpacing: 1.5,
                      fontFamily: "'DM Mono', monospace",
                    }}>{label}</span>
                  </div>
                );
              })}
            </div>

            {/* Data rows */}
            {paginated.length === 0 ? (
              <div style={{ padding: 48, textAlign: "center", color: T.subtext, fontSize: 13 }}>
                No vulnerabilities match the current filter.
              </div>
            ) : paginated.map((v, i) => {
              const key = `${v.id}|${normalizePkg(v.pkg)}`;
              const status = patchStatus[key] || "open";
              const isExp = expandedRow === key;
              const isPatched = status === "patched";
              const isNew = !isBase && !baseIdSet.has(key) && status !== "patched";
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
              {/* ── Spin keyframe ── */}
      <style>{`@keyframes ai-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>

      {/* ══════════════════════════════════════════════════════════════════════
          AI REMEDIATION PANEL — full-screen modal overlay
      ══════════════════════════════════════════════════════════════════════ */}
      {aiPanelOpen && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) setAiPanelOpen(false); }}
          style={{
            position:       "fixed",
            inset:          0,
            zIndex:         1000,
            background:     "rgba(0,0,0,0.78)",
            backdropFilter: "blur(5px)",
            display:        "flex",
            alignItems:     "flex-start",
            justifyContent: "center",
            padding:        "36px 16px 60px",
            overflowY:      "auto",
          }}>
          <div style={{
            background:   darkMode ? "#0d1829" : "#ffffff",
            border:       `1px solid ${T.border}`,
            borderRadius: 12,
            width:        "100%",
            maxWidth:     880,
            boxShadow:    "0 32px 80px rgba(0,0,0,0.65)",
          }}>

            {/* Header */}
            <div style={{
              display:        "flex",
              alignItems:     "center",
              justifyContent: "space-between",
              padding:        "16px 22px",
              borderBottom:   `1px solid ${T.border}`,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontSize: 22 }}>🤖</span>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: T.text }}>
                    AI Remediation Analysis
                  </div>
                  <div style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>
                    {vulns.length} vulnerabilities ·{" "}
                    {aiLoading ? "Analyzing…" : 
                    aiModelUsed ? `Model: ${aiModelUsed}` : 
                    `Models: ${AI_MODELS.join(" / ")}`}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                {/* Agent connectivity dot */}
                <div style={{
                  display: "flex", alignItems: "center", gap: 5,
                  fontSize: 11, fontFamily: "'DM Mono', monospace",
                  color: agentOnline === true ? "#4ade80" : agentOnline === false ? "#f87171" : T.subtext,
                }}>
                  <span style={{
                    width: 7, height: 7, borderRadius: "50%", display: "inline-block",
                    background: agentOnline === true ? "#4ade80" : agentOnline === false ? "#f87171" : "#6b7280",
                  }} />
                  {agentOnline === true ? "Agent online" : agentOnline === false ? "Agent offline" : "Checking…"}
                </div>
                <button onClick={() => setAiPanelOpen(false)}
                  style={{ background: "transparent", border: "none", color: T.subtext, fontSize: 22, cursor: "pointer" }}>
                  ×
                </button>
              </div>
            </div>

            {/* Body */}
            <div style={{ padding: "20px 22px" }}>

              {/* Loading state */}
              {aiLoading && (
                <div style={{ textAlign: "center", padding: "48px 0", color: T.subtext }}>
                  <div style={{ fontSize: 32, animation: "ai-spin 1.5s linear infinite", display: "inline-block", marginBottom: 16 }}>⟳</div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: T.text, marginBottom: 6 }}>Sending report…</div>
                  <div style={{ fontSize: 12 }}>Analyzing {vulns.length} vulnerabilities. This takes 10–25 seconds.</div>
                </div>
              )}

              {/* Error state */}
              {aiError && !aiLoading && (
                <div style={{
                  background: "#1a0505", border: "1px solid #7f1d1d", borderRadius: 8,
                  padding: "14px 18px", color: "#fca5a5", fontSize: 13,
                  fontFamily: "'DM Mono', monospace", lineHeight: 1.6,
                }}>⚠ {aiError}</div>
              )}

              {/* Results */}
              {aiResult && !aiLoading && (
                <>
                  {/* Summary box */}
                  <div style={{
                    background: darkMode ? "#0a1628" : "#f0f7ff",
                    border: `1px solid ${T.border}`, borderRadius: 8,
                    padding: "13px 18px", marginBottom: 20,
                  }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 6 }}>
                      AI Summary
                    </div>
                    <div style={{ fontSize: 13, color: T.text, lineHeight: 1.65 }}>{aiResult.summary}</div>
                    <div style={{ display: "flex", gap: 24, marginTop: 10 }}>
                      <span style={{ fontSize: 12 }}>
                        <span style={{ color: "#4ade80", fontWeight: 700 }}>{(aiResult.fixable || []).length}</span>
                        <span style={{ color: T.subtext }}> can be auto-fixed</span>
                      </span>
                      <span style={{ fontSize: 12 }}>
                        <span style={{ color: "#f87171", fontWeight: 700 }}>{(aiResult.not_fixable || []).length}</span>
                        <span style={{ color: T.subtext }}> require manual action</span>
                      </span>
                    </div>
                  </div>

                  {/* Fixable list */}
                  {(aiResult.fixable || []).length > 0 && (
                    <div style={{ marginBottom: 24 }}>
                      <div style={{
                        display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10,
                      }}>
                        <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace" }}>
                          Auto-fixable ({(aiResult.fixable || []).length}) — click 🤖 for per-fix Ollama explanation
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button onClick={() => setSelectedFixes(new Set((aiResult.fixable || []).map((f) => f.id)))}
                            style={{ fontSize: 11, color: "#4ade80", background: "transparent", border: `1px solid #4ade8044`, padding: "3px 10px", borderRadius: 4, cursor: "pointer" }}>
                            Select all
                          </button>
                          <button onClick={() => setSelectedFixes(new Set())}
                            style={{ fontSize: 11, color: T.subtext, background: "transparent", border: `1px solid ${T.border}`, padding: "3px 10px", borderRadius: 4, cursor: "pointer" }}>
                            Clear
                          </button>
                        </div>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {(aiResult.fixable || []).map((fix) => {
                          const selected = selectedFixes.has(fix.id);
                          const riskColor = fix.risk === "low" ? "#4ade80" : fix.risk === "medium" ? "#fbbf24" : "#f87171";
                          return (
                            <div key={fix.id} style={{
                              padding: "10px 14px", borderRadius: 8,
                              border: `1px solid ${selected ? "#4ade8044" : T.border}`,
                              background: selected ? (darkMode ? "#041a08" : "#f0fff4") : (darkMode ? "#0d1829" : "#fafafa"),
                            }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 5 }}>
                                <input type="checkbox" checked={selected}
                                  onChange={() => setSelectedFixes((prev) => {
                                    const next = new Set(prev);
                                    next.has(fix.id) ? next.delete(fix.id) : next.add(fix.id);
                                    return next;
                                  })}
                                  style={{ cursor: "pointer", accentColor: "#4ade80" }} />
                                <span style={{ fontSize: 12, color: "#4ade80", fontFamily: "'DM Mono', monospace" }}>{fix.id}</span>
                                <span style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace" }}>{fix.pkg}</span>
                                <span style={{ marginLeft: "auto", fontSize: 10, color: riskColor, fontFamily: "'DM Mono', monospace", border: `1px solid ${riskColor}44`, padding: "1px 7px", borderRadius: 3 }}>
                                  {fix.risk} risk
                                </span>
                                {/* 🤖 button → triggers Ollama per-fix explanation */}
                                <button onClick={() => handleExplainFix(fix)}
                                  title="Get Ollama plain-English explanation before consenting"
                                  style={{
                                    background: "linear-gradient(135deg, #7c3aed, #4f46e5)",
                                    color: "#fff", border: "none", borderRadius: 5,
                                    padding: "3px 9px", fontSize: 11, cursor: "pointer", fontWeight: 700,
                                  }}>🤖 Explain</button>
                              </div>
                              <div style={{ fontSize: 12, color: T.subtext, paddingLeft: 28, marginBottom: 5, lineHeight: 1.5 }}>{fix.plan}</div>
                              <div style={{ paddingLeft: 28 }}>
                                {(fix.commands || []).map((cmd, ci) => (
                                  <div key={ci} style={{
                                    fontSize: 10, fontFamily: "'DM Mono', monospace", color: "#7dd3fc",
                                    background: "#020b18", padding: "3px 10px", borderRadius: 4, marginTop: 3,
                                    overflowX: "auto", whiteSpace: "pre",
                                  }}>{cmd}</div>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Not-fixable list */}
                  {(aiResult.not_fixable || []).length > 0 && (
                    <div style={{ marginBottom: 22 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 8 }}>
                        Requires manual action ({(aiResult.not_fixable || []).length})
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        {(aiResult.not_fixable || []).slice(0, 40).map((nf) => (
                          <div key={nf.id} style={{
                            display: "flex", gap: 10, alignItems: "flex-start",
                            padding: "7px 12px", borderRadius: 6,
                            background: darkMode ? "#0d1829" : "#fafafa",
                            border: `1px solid ${T.border}`, flexWrap: "wrap",
                          }}>
                            <span style={{ fontSize: 12, color: "#f87171", fontFamily: "'DM Mono', monospace", flexShrink: 0 }}>{nf.id}</span>
                            <span style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace", flexShrink: 0 }}>{nf.pkg}</span>
                            <span style={{ fontSize: 11, color: T.subtext, marginLeft: "auto" }}>{nf.note}</span>
                          </div>
                        ))}
                        {(aiResult.not_fixable || []).length > 40 && (
                          <div style={{ fontSize: 11, color: T.subtext, padding: "4px 12px" }}>
                            …and {(aiResult.not_fixable || []).length - 40} more — refer to NIST links for manual steps
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Bulk apply section */}
                  {selectedFixes.size > 0 && (
                    <div style={{
                      background: darkMode ? "#0c1a0c" : "#fffbeb",
                      border: "1px solid #92400e55", borderRadius: 8,
                      padding: "16px 20px", marginTop: 6,
                    }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color: "#fbbf24", marginBottom: 8 }}>
                        ⚡ Bulk apply {selectedFixes.size} fix{selectedFixes.size !== 1 ? "es" : ""} to {CONTAINER}
                      </div>
                      <div style={{ fontSize: 12, color: T.subtext, marginBottom: 16, lineHeight: 1.65 }}>
                        Creates a package-list backup first, then runs all selected commands on the container.
                        The PHIS instance stays running during patching.
                      </div>

                      {/* Step 1: Backup */}
                      <div style={{ marginBottom: 10, display: "flex", alignItems: "center", gap: 10 }}>
                        <button onClick={handleBackup}
                          disabled={backupStatus === "running" || backupStatus === "done"}
                          style={{
                            background: backupStatus === "done" ? "#052e16" : backupStatus === "failed" ? "#3b0a0a" : "#1e3a5f",
                            color: backupStatus === "done" ? "#4ade80" : backupStatus === "failed" ? "#f87171" : "#7dd3fc",
                            border: `1px solid ${backupStatus === "done" ? "#16653488" : backupStatus === "failed" ? "#7f1d1d55" : "#1e40af55"}`,
                            padding: "7px 18px", borderRadius: 6, cursor: backupStatus === "running" || backupStatus === "done" ? "not-allowed" : "pointer",
                            fontSize: 12, fontWeight: 700, fontFamily: "inherit",
                          }}>
                          {backupStatus === "running" ? "⟳ Creating backup…"
                           : backupStatus === "done"   ? "✓ Backup saved to ~/phis-backups/"
                           : backupStatus === "failed" ? "✗ Failed — is agent running?"
                           : "Step 1 — Create Backup"}
                        </button>
                        {backupStatus === "failed" && (
                          <button onClick={() => setBackupStatus(null)}
                            style={{ fontSize: 11, color: T.subtext, background: "transparent", border: `1px solid ${T.border}`, padding: "4px 10px", borderRadius: 4, cursor: "pointer" }}>
                            Retry
                          </button>
                        )}
                      </div>

                      {/* Step 2: Apply */}
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <button onClick={handleApplyFixes}
                          disabled={backupStatus !== "done" || remediateStatus === "running"}
                          style={{
                            background: backupStatus !== "done" ? T.surface2 : remediateStatus?.succeeded !== undefined ? "#052e16" : "linear-gradient(135deg, #7c3aed, #4f46e5)",
                            color: backupStatus !== "done" ? T.subtext : "#fff",
                            border: "none", padding: "7px 18px", borderRadius: 6,
                            cursor: backupStatus !== "done" || remediateStatus === "running" ? "not-allowed" : "pointer",
                            fontSize: 12, fontWeight: 700, fontFamily: "inherit",
                            boxShadow: backupStatus === "done" && remediateStatus === null ? "0 0 14px #7c3aed55" : "none",
                            transition: "all 0.2s",
                          }}>
                          {remediateStatus === "running" ? "⟳ Applying fixes…"
                           : remediateStatus?.succeeded !== undefined ? `✓ Done: ${remediateStatus.succeeded}/${remediateStatus.total} succeeded`
                           : backupStatus !== "done" ? "Step 2 — Apply Fixes (backup first)"
                           : `Step 2 — Apply ${selectedFixes.size} Fix${selectedFixes.size !== 1 ? "es" : ""}`}
                        </button>
                      </div>

                      {/* Execution log */}
                      {remediateStatus && remediateStatus !== "running" && remediateStatus.results && (
                        <div style={{ marginTop: 14 }}>
                          <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 6 }}>
                            Execution log
                          </div>
                          <div style={{ background: "#020b18", borderRadius: 6, padding: "10px 14px", fontFamily: "'DM Mono', monospace", fontSize: 11, maxHeight: 220, overflowY: "auto" }}>
                            {remediateStatus.results.map((r, ri) => (
                              <div key={ri} style={{ marginBottom: 5 }}>
                                <span style={{ color: r.success ? "#4ade80" : "#f87171" }}>{r.success ? "✓" : "✗"}</span>
                                <span style={{ color: "#7dd3fc", marginLeft: 8 }}>{r.command}</span>
                                {r.stdout && <div style={{ color: "#94a3b8", paddingLeft: 18, marginTop: 2 }}>{r.stdout.slice(0, 200)}</div>}
                                {!r.success && r.stderr && <div style={{ color: "#f87171", paddingLeft: 18, marginTop: 2 }}>{r.stderr.slice(0, 200)}</div>}
                              </div>
                            ))}
                          </div>
                          {remediateStatus.failed > 0 && (
                            <div style={{ marginTop: 8, fontSize: 12, color: "#fbbf24" }}>
                              ⚠ {remediateStatus.failed} command(s) failed. See log above.
                            </div>
                          )}
                          {remediateStatus.succeeded > 0 && remediateStatus.failed === 0 && (
                            <div style={{ marginTop: 8, fontSize: 12, color: "#4ade80" }}>
                              ✓ All fixes applied. Run a new Trivy scan to verify the results.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          OLLAMA PER-FIX CONSENT MODAL
          Appears when user clicks 🤖 Explain on a single fix
      ══════════════════════════════════════════════════════════════════════ */}
      {consentFix && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget && !consentApplying) setConsentFix(null); }}
          style={{
            position:       "fixed",
            inset:          0,
            zIndex:         2000,
            background:     "rgba(0,0,0,0.85)",
            backdropFilter: "blur(6px)",
            display:        "flex",
            alignItems:     "center",
            justifyContent: "center",
            padding:        "20px",
          }}>
          <div style={{
            background:   darkMode ? "#0d1829" : "#ffffff",
            border:       `1px solid ${T.border}`,
            borderRadius: 12,
            width:        "100%",
            maxWidth:     560,
            boxShadow:    "0 32px 80px rgba(0,0,0,0.7)",
            overflow:     "hidden",
          }}>
            {/* Modal header */}
            <div style={{ padding: "14px 20px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: T.text }}>🤖 Ollama Explanation — Consent Required</div>
                <div style={{ fontSize: 11, color: T.subtext, fontFamily: "'DM Mono', monospace", marginTop: 2 }}>
                  {consentFix.id} · {consentFix.pkg}
                </div>
              </div>
              {!consentApplying && (
                <button onClick={() => setConsentFix(null)}
                  style={{ background: "transparent", border: "none", color: T.subtext, fontSize: 20, cursor: "pointer" }}>
                  ×
                </button>
              )}
            </div>

            {/* Modal body */}
            <div style={{ padding: "18px 20px" }}>

              {/* Ollama explanation */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 8 }}>
                  What Ollama says about this fix
                </div>
                {consentLoading ? (
                  <div style={{ display: "flex", alignItems: "center", gap: 10, color: T.subtext, fontSize: 13 }}>
                    <span style={{ animation: "ai-spin 1s linear infinite", display: "inline-block" }}>⟳</span>
                    Asking local Ollama for explanation…
                  </div>
                ) : (
                  <div style={{ fontSize: 13, color: T.text, lineHeight: 1.7, background: darkMode ? "#0a1628" : "#f8fafc", padding: "12px 14px", borderRadius: 8, border: `1px solid ${T.border}` }}>
                    {consentText}
                  </div>
                )}
              </div>

              {/* Commands that will run */}
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 6 }}>
                  Commands that will execute on {CONTAINER}
                </div>
                {(consentFix.commands || []).map((cmd, ci) => (
                  <div key={ci} style={{ fontSize: 11, fontFamily: "'DM Mono', monospace", color: "#7dd3fc", background: "#020b18", padding: "6px 12px", borderRadius: 5, marginTop: 4, overflowX: "auto", whiteSpace: "pre" }}>
                    {cmd}
                  </div>
                ))}
              </div>

              {/* Result after applying */}
              {consentResult && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: T.subtext, textTransform: "uppercase", letterSpacing: 1.5, fontFamily: "'DM Mono', monospace", marginBottom: 6 }}>
                    Execution result
                  </div>
                  <div style={{ background: "#020b18", borderRadius: 6, padding: "8px 12px", fontFamily: "'DM Mono', monospace", fontSize: 11 }}>
                    {(consentResult.results || []).map((r, ri) => (
                      <div key={ri} style={{ marginBottom: 4 }}>
                        <span style={{ color: r.success ? "#4ade80" : "#f87171" }}>{r.success ? "✓" : "✗"}</span>
                        <span style={{ color: "#7dd3fc", marginLeft: 8 }}>{r.command}</span>
                        {r.stdout && <div style={{ color: "#94a3b8", paddingLeft: 16 }}>{r.stdout.slice(0, 150)}</div>}
                        {!r.success && r.stderr && <div style={{ color: "#f87171", paddingLeft: 16 }}>{r.stderr.slice(0, 150)}</div>}
                      </div>
                    ))}
                  </div>
                  {consentResult.succeeded === consentResult.total && consentResult.total > 0 && (
                    <div style={{ fontSize: 12, color: "#4ade80", marginTop: 8 }}>✓ Fix applied successfully.</div>
                  )}
                </div>
              )}

              {/* Action buttons */}
              {!consentResult && (
                <div style={{ display: "flex", gap: 10 }}>
                  <button onClick={handleConsentApply}
                    disabled={consentLoading || consentApplying}
                    style={{
                      flex: 1,
                      background: consentLoading || consentApplying ? T.surface2 : "linear-gradient(135deg, #16a34a, #15803d)",
                      color: consentLoading || consentApplying ? T.subtext : "#fff",
                      border: "none", padding: "10px 0", borderRadius: 7,
                      cursor: consentLoading || consentApplying ? "not-allowed" : "pointer",
                      fontSize: 13, fontWeight: 700, fontFamily: "inherit",
                    }}>
                    {consentApplying ? "⟳ Applying…" : "✅ I Consent — Apply This Fix"}
                  </button>
                  <button onClick={() => setConsentFix(null)}
                    disabled={consentApplying}
                    style={{
                      background: "transparent", color: T.subtext,
                      border: `1px solid ${T.border}`, padding: "10px 20px",
                      borderRadius: 7, cursor: consentApplying ? "not-allowed" : "pointer",
                      fontSize: 13, fontWeight: 700, fontFamily: "inherit",
                    }}>
                    Cancel
                  </button>
                </div>
              )}
              {consentResult && (
                <button onClick={() => setConsentFix(null)}
                  style={{
                    width: "100%", background: T.surface2, color: T.subtext,
                    border: `1px solid ${T.border}`, padding: "10px 0",
                    borderRadius: 7, cursor: "pointer", fontSize: 13, fontWeight: 700, fontFamily: "inherit",
                  }}>
                  Close
                </button>
              )}
            </div>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}