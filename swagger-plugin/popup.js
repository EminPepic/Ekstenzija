let currentSwagger = null;
const BACKEND_URL = "http://localhost:3000";
//const BACKEND_URL = "https://swagger-tester-backend.onrender.com";
const RUN_TEST_URL = `${BACKEND_URL.replace(/\/+$/, "")}/run-test`;
const API_KEY_HEADER = (localStorage.getItem("swaggerTesterApiKeyHeader") || "x-api-key").trim();
const API_KEY = (localStorage.getItem("swaggerTesterApiKey") || "").trim();
const _lastRuns = {};
const _maxRunsPerMinute = 2;

const swaggerInput = document.getElementById("swaggerUrl");
const loadBtn = document.getElementById("loadSwagger");
const output = document.getElementById("output");
const timeline = document.getElementById("timeline");
const timelineList = document.getElementById("timelineList");
const backBtn = document.getElementById("backBtn");
const downloadBtn = document.getElementById("downloadBtn");
let isRunningTest = false;
let lastResultForDownload = null;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function shortenText(value, maxLen = 220) {
  const raw = String(value == null ? "" : value).replace(/\s+/g, " ").trim();
  if (raw.length <= maxLen) return raw;
  return `${raw.slice(0, maxLen)}...`;
}

function scoreToGrade10(securityScore) {
  const score = Number(securityScore);
  if (!Number.isFinite(score)) return "N/A";
  return String(Math.max(1, Math.min(10, Math.round(score / 10))));
}

function gradeToneClass(grade10) {
  const n = Number(grade10);
  if (!Number.isFinite(n)) return "is-neutral";
  if (n >= 8) return "is-good";
  if (n >= 5) return "is-mid";
  return "is-bad";
}

function formatDetailedReport(result) {
  const report = result?.report || {};
  const perf = report.performance || {};
  const summary = report.summary || {};
  const analysis = report.analysis || {};
  const endpoint = report.endpoint || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const lines = [];

  lines.push("API SECURITY TEST REPORT - DETALJNI IZVJESTAJ");
  lines.push("=".repeat(72));
  lines.push(`Naziv izvjestaja: ${report.title || "N/A"}`);
  lines.push(`Generisano: ${report.generatedAt ? new Date(report.generatedAt).toLocaleString() : "N/A"}`);
  lines.push(`Endpoint: ${endpoint.url || "N/A"}`);
  lines.push(`Metoda: ${endpoint.method || "N/A"}`);
  lines.push("");

  lines.push("SAZETAK");
  lines.push("-".repeat(72));
  lines.push(`Ukupno testova: ${summary.totalTests ?? "N/A"}`);
  lines.push(`Proslo: ${summary.passed ?? "N/A"}`);
  lines.push(`Palo: ${summary.failed ?? "N/A"}`);
  lines.push(`Neodredjeno: ${summary.inconclusive ?? 0}`);
  lines.push(`Security score: ${summary.securityScore ?? "N/A"}%`);
  lines.push(`Risk level: ${summary.riskLevel ?? "N/A"}`);
  lines.push("");

  lines.push("PERFORMANCE");
  lines.push("-".repeat(72));
  lines.push(`Avg latency: ${perf.avgLatencyMs ?? "N/A"} ms`);
  lines.push(`P50/P90/P99: ${perf.latencyP50 ?? "N/A"} / ${perf.latencyP90 ?? "N/A"} / ${perf.latencyP99 ?? "N/A"} ms`);
  lines.push(`Requests/sec: ${perf.requestsPerSec ?? "N/A"}`);
  lines.push(`Total requests: ${perf.totalRequests ?? "N/A"}`);
  lines.push(`Errors: ${perf.errorCount ?? "N/A"}`);
  lines.push(`Timeouts: ${perf.timeouts ?? "N/A"}`);
  lines.push(`2xx/4xx/5xx: ${perf.status2xx ?? "N/A"} / ${perf.status4xx ?? "N/A"} / ${perf.status5xx ?? "N/A"}`);
  lines.push("");

  lines.push("ANALIZA");
  lines.push("-".repeat(72));
  lines.push(`Naslov: ${analysis.headline || "N/A"}`);
  lines.push(`Sigurnost: ${analysis.securityLevel || "N/A"}`);
  lines.push(`Performanse: ${analysis.performanceLevel || "N/A"}`);
  lines.push(`Procjena sigurnosti: ${analysis.securityAssessment || "N/A"}`);
  lines.push(`Procjena performansi: ${analysis.performanceAssessment || "N/A"}`);
  lines.push(`Zakljucak: ${analysis.conclusion || analysis.summary || "N/A"}`);
  lines.push("Preporuke:");
  (analysis.recommendations || []).forEach((r, i) => lines.push(`  ${i + 1}. ${r}`));
  lines.push("");

  lines.push("DETALJNI NALAZI");
  lines.push("-".repeat(72));
  findings.forEach((finding, idx) => {
    lines.push(`${idx + 1}) ${finding.testType || "N/A"}`);
    lines.push(`   Status: ${finding.findingType || finding.status || "N/A"}`);
    lines.push(`   Severity: ${finding.severity || "N/A"}`);
    lines.push(`   Napomena: ${finding.note || "N/A"}`);
    lines.push(`   Poruka: ${finding.message || "N/A"}`);
    lines.push(`   HTTP status: ${finding.statusCode ?? "N/A"}`);
    lines.push(`   URL: ${finding.url || "N/A"}`);
    lines.push(`   Vrijeme: ${finding.timestamp ? new Date(finding.timestamp).toLocaleString() : "N/A"}`);
    lines.push("   Payload:");
    lines.push(`   ${shortenText(String(finding.payload || "").replace(/\r?\n/g, " "), 800)}`);
    lines.push("   Odgovor servera:");
    lines.push(`   ${shortenText(String(finding.rawResponse || "").replace(/\r?\n/g, " "), 2000) || "N/A"}`);
    lines.push("");
  });

  return lines.join("\n");
}

function toAsciiForPdf(text) {
  const map = {
    "š": "s", "Š": "S", "đ": "dj", "Đ": "Dj", "č": "c", "Č": "C", "ć": "c", "Ć": "C", "ž": "z", "Ž": "Z",
  };
  return String(text || "")
    .replace(/[šŠđĐčČćĆžŽ]/g, (ch) => map[ch] || ch)
    .replace(/[^\x20-\x7E\r\n\t]/g, " ");
}

function wrapLine(line, maxLen = 95) {
  const src = String(line || "");
  if (src.length <= maxLen) return [src];
  const out = [];
  let current = src;
  while (current.length > maxLen) {
    let cut = current.lastIndexOf(" ", maxLen);
    if (cut < Math.floor(maxLen * 0.6)) cut = maxLen;
    out.push(current.slice(0, cut));
    current = current.slice(cut).trimStart();
  }
  if (current.length) out.push(current);
  return out;
}

function escapePdfText(text) {
  return String(text || "")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function makePdfBlobFromText(text) {
  const ascii = toAsciiForPdf(text);
  const rawLines = ascii.split(/\r?\n/);
  const wrapped = rawLines.flatMap((line) => wrapLine(line, 95));
  const linesPerPage = 50;
  const pages = [];

  for (let i = 0; i < wrapped.length; i += linesPerPage) {
    pages.push(wrapped.slice(i, i + linesPerPage));
  }
  if (pages.length === 0) pages.push([""]);

  const objects = [];
  let objId = 1;

  const catalogId = objId++;
  const pagesId = objId++;
  const pageIds = [];
  const contentIds = [];
  const fontId = objId++;

  pages.forEach(() => {
    pageIds.push(objId++);
    contentIds.push(objId++);
  });

  objects[catalogId] = `${catalogId} 0 obj\n<< /Type /Catalog /Pages ${pagesId} 0 R >>\nendobj\n`;

  const kids = pageIds.map((id) => `${id} 0 R`).join(" ");
  objects[pagesId] = `${pagesId} 0 obj\n<< /Type /Pages /Kids [ ${kids} ] /Count ${pageIds.length} >>\nendobj\n`;

  objects[fontId] = `${fontId} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`;

  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const contentId = contentIds[index];
    const safeLines = pageLines.length > 0 ? pageLines : [""];
    const firstLine = `(${escapePdfText(safeLines[0])}) Tj`;
    const restLines = safeLines
      .slice(1)
      .map((line) => `T*\n(${escapePdfText(line)}) Tj`)
      .join("\n");
    const stream = `BT\n/F1 10 Tf\n12 TL\n40 800 Td\n${firstLine}${restLines ? `\n${restLines}` : ""}\nET\n`;
    objects[contentId] = `${contentId} 0 obj\n<< /Length ${stream.length} >>\nstream\n${stream}endstream\nendobj\n`;
    objects[pageId] = `${pageId} 0 obj\n<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 595 842] /Contents ${contentId} 0 R /Resources << /Font << /F1 ${fontId} 0 R >> >> >>\nendobj\n`;
  });

  let pdf = "%PDF-1.4\n";
  const offsets = [];
  for (let i = 1; i < objects.length; i++) {
    offsets[i] = pdf.length;
    pdf += objects[i];
  }

  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length}\n`;
  pdf += "0000000000 65535 f \n";
  for (let i = 1; i < objects.length; i++) {
    const off = String(offsets[i]).padStart(10, "0");
    pdf += `${off} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;

  return new Blob([pdf], { type: "application/pdf" });
}

function downloadDetailedReport() {
  if (!lastResultForDownload?.report) return;
  const content = formatDetailedReport(lastResultForDownload);
  const blob = makePdfBlobFromText(content);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.href = url;
  a.download = `api-security-report-${stamp}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

downloadBtn.onclick = downloadDetailedReport;

loadBtn.addEventListener("click", async () => {
  if (isRunningTest) return;
  const url = swaggerInput.value.trim();
  if (!url) return;

  try {
    output.style.display = "block";
    output.innerHTML = 'Ucitavanje Swagger dokumentacije<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>';
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const swagger = await response.json();
    if (!swagger?.paths || typeof swagger.paths !== "object") throw new Error("Nevalidan Swagger/OpenAPI dokument.");
    currentSwagger = swagger;
    showEndpoints(swagger);
  } catch (err) {
    output.innerHTML = `Greska pri ucitavanju Swagger dokumentacije: ${escapeHtml(err?.message || "Nepoznata greska")}`;
  }
});

function setRunState(active) {
  isRunningTest = active;
  loadBtn.disabled = active;
  swaggerInput.disabled = active;
  document.querySelectorAll(".endpoint-btn").forEach((btn) => {
    btn.disabled = active;
  });
}

function extractBaseUrl(swagger) {
  if (swagger.servers && swagger.servers.length > 0) return swagger.servers[0].url;
  return swagger.host ? `${swagger.schemes?.[0] || "https"}://${swagger.host}${swagger.basePath || ""}` : null;
}

function resolveRef(swagger, ref) {
  if (!ref || !ref.startsWith("#/")) return null;
  const parts = ref.replace(/^#\//, "").split("/");
  let node = swagger;
  for (const part of parts) {
    node = node?.[part];
    if (!node) return null;
  }
  return node;
}

function mergeAllOf(swagger, schema) {
  if (!schema?.allOf) return schema;
  const merged = { type: "object", properties: {}, required: [] };
  schema.allOf.forEach((sub) => {
    const resolved = sub.$ref ? resolveRef(swagger, sub.$ref) : sub;
    if (!resolved) return;
    const r = mergeAllOf(swagger, resolved);
    Object.assign(merged.properties, r.properties || {});
    merged.required = [...new Set([...(merged.required || []), ...(r.required || [])])];
  });
  return merged;
}

function schemaToExample(swagger, schema, depth = 0) {
  if (!schema || depth > 5) return "test";
  const source = schema.$ref ? resolveRef(swagger, schema.$ref) : schema;
  if (!source) return "test";
  const s = mergeAllOf(swagger, source);

  if (s.example !== undefined) return s.example;
  if (s.default !== undefined) return s.default;
  if (Array.isArray(s.enum) && s.enum.length > 0) return s.enum[0];

  if (s.type === "string") return "test";
  if (s.type === "integer" || s.type === "number") return 1;
  if (s.type === "boolean") return true;
  if (s.type === "array") return [schemaToExample(swagger, s.items || { type: "string" }, depth + 1)];

  const props = s.properties || {};
  const obj = {};
  Object.keys(props).forEach((key) => {
    obj[key] = schemaToExample(swagger, props[key], depth + 1);
  });

  (s.required || []).forEach((key) => {
    if (obj[key] === undefined) obj[key] = "test";
  });

  return obj;
}

function findFirstStringPath(obj, prefix = "") {
  if (!obj || typeof obj !== "object") return null;
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") return path;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const nested = findFirstStringPath(value, path);
      if (nested) return nested;
    }
  }
  return null;
}

function getEndpointContext(swagger, path, method) {
  const pathItem = swagger.paths[path] || {};
  const operation = pathItem[method] || {};
  const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])];

  const queryParams = allParams.filter((p) => p.in === "query").map((p) => p.name);
  const formDataParams = allParams.filter((p) => p.in === "formData").map((p) => ({ name: p.name, type: p.type || "string" }));
  const bodyFields = [];
  const bodyParam = allParams.find((p) => p.in === "body" && p.schema);
  let bodyTemplate = null;
  let injectFieldPath = null;

  if (bodyParam?.schema) {
    bodyTemplate = schemaToExample(swagger, bodyParam.schema);
    if (bodyTemplate && typeof bodyTemplate === "object" && !Array.isArray(bodyTemplate)) {
      bodyFields.push(...Object.keys(bodyTemplate));
      injectFieldPath = findFirstStringPath(bodyTemplate) || Object.keys(bodyTemplate)[0] || null;
    }
  }

  const pathParamValues = {};
  allParams.filter((p) => p.in === "path").forEach((p) => {
    pathParamValues[p.name] = p.name.toLowerCase().includes("id") ? "1" : "test";
  });

  return { queryParams, bodyFields, pathParamValues, bodyTemplate, injectFieldPath, formDataParams };
}

function showEndpoints(swagger) {
  let html = "<h3>Endpoint-i:</h3><ul>";

  for (const path in swagger.paths) {
    for (const method in swagger.paths[path]) {
      html += `<li><button class="endpoint-btn" data-path="${path}" data-method="${method}">${method.toUpperCase()} ${path}</button></li>`;
    }
  }

  html += "</ul>";
  output.style.display = "block";
  output.innerHTML = html;
  timeline.style.display = "none";
  backBtn.style.display = "none";

  document.querySelectorAll(".endpoint-btn").forEach((btn) => {
    btn.onclick = () => runTest(btn.dataset.path, btn.dataset.method);
  });
}

async function runTest(path, method) {
  if (isRunningTest) return;
  const baseUrl = extractBaseUrl(currentSwagger);
  if (!baseUrl) {
    output.innerHTML = "Ne mogu odrediti baseUrl.";
    return;
  }

  // Rate-limit: allow a small number of runs per minute per endpoint
  try {
    const key = `${baseUrl}|${path}|${method}`;
    const now = Date.now();
    _lastRuns[key] = _lastRuns[key] || [];
    // remove older than 60s
    _lastRuns[key] = _lastRuns[key].filter((t) => now - t < 60000);
    if (_lastRuns[key].length >= _maxRunsPerMinute) {
      output.innerHTML = "Ogranicenje: presli ste dozvoljeni broj pokretanja za ovaj endpoint (max per minute). Pokusajte kasnije.";
      return;
    }
    _lastRuns[key].push(now);
  } catch (e) {
    // non-fatal
  }

  const endpointContext = getEndpointContext(currentSwagger, path, method);
  output.style.display = "block";
  output.innerHTML = 'Testiranje u toku<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>';
  setRunState(true);

  try {
    const headers = { "Content-Type": "application/json" };
    if (API_KEY) headers[API_KEY_HEADER || "x-api-key"] = API_KEY;

    const response = await fetch(RUN_TEST_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ baseUrl, path, method, endpointContext }),
    });

    if (!response.ok) {
      let backendMessage = `Backend greska (HTTP ${response.status})`;
      try {
        const errData = await response.json();
        if (errData?.error) backendMessage = errData.error;
      } catch (e) {}
      throw new Error(backendMessage);
    }

    const result = await response.json();
    updateTimeline(result);
  } catch (err) {
    output.innerHTML = `Test nije pokrenut: ${escapeHtml(err?.message || "Backend nije pokrenut.")}`;
  } finally {
    setRunState(false);
  }
}

function updateTimeline(result) {
  const report = result.report || null;

  if (!report) {
    timelineList.innerHTML = "Nema report podataka.";
    output.style.display = "none";
    timeline.style.display = "block";
    backBtn.style.display = "block";
    return;
  }

  const perf = report.performance || {};
  const grade10 = scoreToGrade10(report.summary?.securityScore);
  const gradeTone = gradeToneClass(grade10);
  const findingsHtml = (report.findings || [])
    .map((finding) => `
      <article class="finding-item">
        <p><strong>Test:</strong> ${escapeHtml(shortenText(finding.testType, 90))}</p>
        <p><strong>Status:</strong> <span class="status-pill ${
          String(finding.status).toLowerCase() === "passed"
            ? "is-passed"
            : String(finding.status).toLowerCase() === "inconclusive"
            ? "is-inconclusive"
            : "is-failed"
        }">${escapeHtml(finding.findingType || finding.status)}</span></p>
        <p><strong>Severity:</strong> ${escapeHtml(finding.severity || "N/A")}</p>
      </article>
    `)
    .join("");

  const analysis = report.analysis || {};
  const analysisSummary = analysis.summary || "Analiza nije dostupna.";
  const recommendations = Array.isArray(analysis.recommendations) ? analysis.recommendations : [];
  const cleanConclusion = String(analysis.conclusion || analysisSummary).replace(/^Zakljucak:\s*/i, "");
  const interpretation = [analysis.securityAssessment, analysis.performanceAssessment]
    .filter((item) => typeof item === "string" && item.trim().length > 0)
    .join(" ");
  const recommendationsHtml = recommendations.length
    ? `<ul class="analysis-recommendations">${recommendations.slice(0, 2).map((r) => `<li>${escapeHtml(shortenText(r, 140))}</li>`).join("")}</ul>`
    : "<p>Nema dodatnih preporuka.</p>";

  timelineList.innerHTML = `
    <section class="report-shell">
      <header class="report-head">
        <h4>${escapeHtml(report.title)}</h4>
        <p><strong>Endpoint:</strong> ${escapeHtml(report.endpoint.url)}</p>
        <p><strong>${escapeHtml(report.endpoint.method)} | ${escapeHtml(new Date(report.generatedAt).toLocaleString())}</strong></p>
      </header>

      <section class="report-card">
        <div class="grade-row">
          <span class="grade-label">Ocjena testiranja</span>
          <span class="test-grade-pill ${escapeHtml(gradeTone)}">${escapeHtml(grade10)}/10</span>
        </div>
        <p><strong>Testovi:</strong> ${escapeHtml(report.summary.totalTests)} | <strong>Proslo:</strong> ${escapeHtml(report.summary.passed)} | <strong>Palo:</strong> ${escapeHtml(report.summary.failed)} | <strong>Neodredjeno:</strong> ${escapeHtml(report.summary.inconclusive ?? 0)}</p>
        <p><strong>Security score:</strong> ${escapeHtml(report.summary.securityScore)}% | <strong>Risk:</strong> ${escapeHtml(report.summary.riskLevel)}</p>
        <p><strong>Latency:</strong> ${escapeHtml(perf.avgLatencyMs ?? "N/A")} ms (P99 ${escapeHtml(perf.latencyP99 ?? "N/A")} ms) | <strong>RPS:</strong> ${escapeHtml(perf.requestsPerSec ?? "N/A")} | <strong>Errors:</strong> ${escapeHtml(perf.errorCount ?? "N/A")}</p>
      </section>

      <section class="report-card">
        <h5>Analiza rezultata (Automatska)</h5>
        <p><strong>${escapeHtml(shortenText(analysis.headline || "N/A", 120))}</strong></p>
        <p><strong>Sigurnost:</strong> ${escapeHtml(analysis.securityLevel || "N/A")} | <strong>Performanse:</strong> ${escapeHtml(analysis.performanceLevel || "N/A")}</p>
        <p><strong>Interpretacija:</strong> ${escapeHtml(shortenText(interpretation || analysisSummary, 260))}</p>
        <div><strong>Preporuke:</strong>${recommendationsHtml}</div>
        <p><strong>Zakljucak:</strong> ${escapeHtml(shortenText(cleanConclusion, 200))}</p>
      </section>

      <section class="report-card">
        <h5>Detaljni nalazi</h5>
        <div class="findings-list">${findingsHtml || "<p>Nema nalaza.</p>"}</div>
      </section>
    </section>
  `;

  output.style.display = "none";
  timeline.style.display = "block";
  backBtn.style.display = "block";
  downloadBtn.style.display = "block";
  lastResultForDownload = result;

  backBtn.onclick = () => {
    timeline.style.display = "none";
    output.style.display = "block";
    backBtn.style.display = "none";
    downloadBtn.style.display = "none";
    lastResultForDownload = null;
    if (currentSwagger) showEndpoints(currentSwagger);
  };
}
