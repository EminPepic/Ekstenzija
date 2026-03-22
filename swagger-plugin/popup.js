let currentSwagger = null;
//const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "http://localhost:3000").trim();
const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "https://swagger-tester-backend.onrender.com").trim();
const RUN_TEST_URL = `${BACKEND_URL.replace(/\/+$/, "")}/run-test`;
const REQUEST_API_KEY_URL = `${BACKEND_URL.replace(/\/+$/, "")}/request-api-key`;
const API_TOKEN_HEADER = "x-api-token";
const API_TOKEN_STORAGE_KEY = "swaggerTesterApiToken";
const API_TOKEN_MASK_STORAGE_KEY = "swaggerTesterApiMask";
const _lastRuns = {};
const _maxRunsPerMinute = 2;
const IS_LOCAL_BACKEND = /^(?:https?:\/\/)?(?:localhost|127\.0\.0\.1)(?::\d+)?(?:\/|$)/i.test(BACKEND_URL);

const DEFAULT_CONCURRENCY = 10;
const DEFAULT_DURATION = 5;

const swaggerInput = document.getElementById("swaggerUrl");
const swaggerFileInput = document.getElementById("swaggerFile");
const apiKeyInput = document.getElementById("apiKeyInput");
const requestApiKeyBtn = document.getElementById("requestApiKey");
const loadBtn = document.getElementById("loadSwagger");
const output = document.getElementById("output");
const timeline = document.getElementById("timeline");
const timelineList = document.getElementById("timelineList");
const backBtn = document.getElementById("backBtn");
const downloadBtn = document.getElementById("downloadBtn");
let isRunningTest = false;
let lastResultForDownload = null;
let currentApiToken = "";
let currentApiMask = "";
let currentMethodFilter = "GET";
let currentPathFilter = "";
let lastSwaggerUrl = "";

currentApiToken = String(localStorage.getItem(API_TOKEN_STORAGE_KEY) || "").trim();
currentApiMask = String(localStorage.getItem(API_TOKEN_MASK_STORAGE_KEY) || "").trim();
if (apiKeyInput) {
  apiKeyInput.value = currentApiMask || "";
}

if (requestApiKeyBtn) {
  requestApiKeyBtn.addEventListener("click", async () => {
    try {
      output.style.display = "block";
      output.innerHTML = 'Requesting API key<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>';
      const response = await fetch(REQUEST_API_KEY_URL, { method: "POST" });
      if (!response.ok) {
        const msg = `API key request failed (HTTP ${response.status})`;
        throw new Error(msg);
      }
      const data = await response.json();
      const token = String(data?.token || "").trim();
      const masked = String(data?.masked || "").trim();
      if (!token || !masked) {
        throw new Error("API key response was invalid.");
      }
      currentApiToken = token;
      currentApiMask = masked;
      localStorage.setItem(API_TOKEN_STORAGE_KEY, token);
      localStorage.setItem(API_TOKEN_MASK_STORAGE_KEY, masked);
      if (apiKeyInput) apiKeyInput.value = masked;
      output.innerHTML = "API key is ready. You can start tests.";
    } catch (err) {
      output.innerHTML = `API key request failed: ${escapeHtml(err?.message || "Unknown error")}`;
    }
  });
}

function getSavedApiToken() {
  return String(currentApiToken || "").trim();
}


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

  lines.push("API SECURITY TEST REPORT - DETAILED REPORT");
  lines.push("=".repeat(72));
  lines.push(`Report title: ${report.title || "N/A"}`);
  lines.push(`Generated: ${report.generatedAt ? new Date(report.generatedAt).toLocaleString() : "N/A"}`);
  lines.push(`Endpoint: ${endpoint.url || "N/A"}`);
  lines.push(`Method: ${endpoint.method || "N/A"}`);
  lines.push("");

  lines.push("SUMMARY");
  lines.push("-".repeat(72));
  lines.push(`Total tests: ${summary.totalTests ?? "N/A"}`);
  lines.push(`Passed: ${summary.passed ?? "N/A"}`);
  lines.push(`Failed: ${summary.failed ?? "N/A"}`);
  lines.push(`Inconclusive: ${summary.inconclusive ?? 0}`);
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

  lines.push("ANALYSIS");
  lines.push("-".repeat(72));
  lines.push(`Headline: ${analysis.headline || "N/A"}`);
  lines.push(`Security: ${analysis.securityLevel || "N/A"}`);
  lines.push(`Performance: ${analysis.performanceLevel || "N/A"}`);
  lines.push(`Security assessment: ${analysis.securityAssessment || "N/A"}`);
  lines.push(`Performance assessment: ${analysis.performanceAssessment || "N/A"}`);
  lines.push(`Conclusion: ${analysis.conclusion || analysis.summary || "N/A"}`);
  lines.push("Recommendations:");
  (analysis.recommendations || []).forEach((r, i) => lines.push(`  ${i + 1}. ${r}`));
  lines.push("");

  lines.push("DETAILED FINDINGS");
  lines.push("-".repeat(72));
  findings.forEach((finding, idx) => {
    lines.push(`${idx + 1}) ${finding.testType || "N/A"}`);
    lines.push(`   Status: ${finding.findingType || finding.status || "N/A"}`);
    lines.push(`   Severity: ${finding.severity || "N/A"}`);
    lines.push(`   Note: ${finding.note || "N/A"}`);
    lines.push(`   Message: ${finding.message || "N/A"}`);
    lines.push(`   HTTP status: ${finding.statusCode ?? "N/A"}`);
    lines.push(`   URL: ${finding.url || "N/A"}`);
    lines.push(`   Time: ${finding.timestamp ? new Date(finding.timestamp).toLocaleString() : "N/A"}`);
    lines.push("   Payload:");
    lines.push(`   ${shortenText(String(finding.payload || "").replace(/\r?\n/g, " "), 800)}`);
    lines.push("   Server response:");
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

function parseYamlScalar(raw) {
  const v = String(raw || "").trim();
  if (v === "") return "";
  const lower = v.toLowerCase();
  if (lower === "null" || lower === "~") return null;
  if (lower === "true") return true;
  if (lower === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1).replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\"/g, '"').replace(/\\'/g, "'");
  }
  if ((v.startsWith("[") && v.endsWith("]")) || (v.startsWith("{") && v.endsWith("}"))) {
    try {
      return JSON.parse(v);
    } catch (e) {
      return v;
    }
  }
  return v;
}

function parseYamlBasic(text) {
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  const root = {};
  const stack = [{ indent: -1, container: root, type: "object", parent: null, key: null }];

  function ensureArrayContainer(top) {
    if (Array.isArray(top.container)) return top.container;
    if (top.parent && top.key && top.type === "object" && Object.keys(top.container).length === 0) {
      top.parent[top.key] = [];
      top.container = top.parent[top.key];
      top.type = "array";
      return top.container;
    }
    if (stack.length === 1 && Object.keys(stack[0].container).length === 0) {
      stack[0].container = [];
      stack[0].type = "array";
      return stack[0].container;
    }
    return top.container;
  }

  function parseBlockScalar(startIndex, parentIndent, style) {
    let blockIndent = null;
    const out = [];
    let consumed = 0;
    for (let j = startIndex + 1; j < lines.length; j++) {
      const raw = lines[j];
      const trimmed = raw.trimEnd();
      if (!trimmed.trim()) {
        out.push("");
        consumed++;
        continue;
      }
      const indent = raw.match(/^\s*/)[0].length;
      if (indent <= parentIndent) break;
      if (blockIndent === null) blockIndent = indent;
      if (indent < blockIndent) break;
      out.push(raw.slice(blockIndent));
      consumed++;
    }
    const joined = style === ">" ? out.join(" ").replace(/\s+/g, " ").trim() : out.join("\n");
    return { value: joined, consumed };
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || !raw.trim() || raw.trim().startsWith("#")) continue;
    const indent = raw.match(/^\s*/)[0].length;
    let line = raw.trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();
    const top = stack[stack.length - 1];

    if (line.startsWith("-")) {
      const arr = ensureArrayContainer(top);
      const item = line.replace(/^-+\s?/, "");
      if (item === "") {
        const obj = {};
        arr.push(obj);
        stack.push({ indent, container: obj, type: "object", parent: arr, key: null });
        continue;
      }

      const kvMatch = item.match(/^([^:]+):\s*(.*)$/);
      if (kvMatch) {
        const key = kvMatch[1].trim();
        const valuePart = kvMatch[2];
        const obj = {};
        if (valuePart === "") {
          obj[key] = {};
          arr.push(obj);
          stack.push({ indent, container: obj[key], type: "object", parent: obj, key });
          continue;
        }
        if (valuePart === "|" || valuePart === ">") {
          const block = parseBlockScalar(i, indent, valuePart);
          i += block.consumed;
          obj[key] = block.value;
          arr.push(obj);
          continue;
        }
        obj[key] = parseYamlScalar(valuePart);
        arr.push(obj);
        continue;
      }

      if (item === "|" || item === ">") {
        const block = parseBlockScalar(i, indent, item);
        i += block.consumed;
        arr.push(block.value);
        continue;
      }

      arr.push(parseYamlScalar(item));
      continue;
    }

    const match = line.match(/^([^:]+):\s*(.*)$/);
    if (!match) continue;
    const key = match[1].trim();
    const valuePart = match[2];
    const parent = top.container;

    if (valuePart === "") {
      parent[key] = {};
      stack.push({ indent, container: parent[key], type: "object", parent, key });
      continue;
    }

    if (valuePart === "|" || valuePart === ">") {
      const block = parseBlockScalar(i, indent, valuePart);
      i += block.consumed;
      parent[key] = block.value;
      continue;
    }

    parent[key] = parseYamlScalar(valuePart);
  }

  return root;
}

async function parseSwagger(text) {
  const raw = String(text || "").trim();
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try {
      return JSON.parse(raw);
    } catch (e) {
      // fallthrough to YAML
    }
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    try {
      return parseYamlBasic(raw);
    } catch (err) {
      throw new Error("Unable to parse JSON/YAML");
    }
  }
}

loadBtn.addEventListener("click", async () => {
  if (isRunningTest) return;
  let swagger = null;

  // priority: file input over URL
  if (swaggerFileInput && swaggerFileInput.files && swaggerFileInput.files.length > 0) {
    const file = swaggerFileInput.files[0];
    lastSwaggerUrl = "";
    output.style.display = "block";
    output.innerHTML = `Loading from file ${escapeHtml(file.name)}<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>`;
    try {
      const text = await new Promise((res, rej) => {
        const reader = new FileReader();
        reader.onload = () => res(reader.result);
        reader.onerror = () => rej(reader.error);
        reader.readAsText(file);
      });
      swagger = await parseSwagger(text);
    } catch (err) {
      output.innerHTML = `Error parsing file: ${escapeHtml(err?.message || "unknown")}`;
      return;
    }
  } else {
    const url = swaggerInput.value.trim();
    if (!url) return;
    lastSwaggerUrl = url;
    output.style.display = "block";
    output.innerHTML = 'Loading Swagger document<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>';
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      swagger = await response.json();
    } catch (err) {
      output.innerHTML = `Error loading Swagger document: ${escapeHtml(err?.message || "Unknown error")}`;
      return;
    }
  }

  if (!swagger?.paths || typeof swagger.paths !== "object") {
    output.innerHTML = "Invalid Swagger/OpenAPI document.";
    return;
  }
  currentSwagger = swagger;
  showEndpoints(swagger);
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
  if (swagger.servers && swagger.servers.length > 0) {
    const server = swagger.servers[0];
    let url = String(server?.url || "").trim();
    if (!url) return null;
    if (server?.variables) {
      url = url.replace(/\{([^}]+)\}/g, (_, name) => {
        const v = server.variables?.[name];
        return v?.default != null ? String(v.default) : "";
      });
    }
    const isAbsolute = /^https?:\/\//i.test(url);
    if (!isAbsolute && lastSwaggerUrl) {
      try {
        url = new URL(url, lastSwaggerUrl).toString();
      } catch (e) {
        // ignore and fall through
      }
    }
    return url;
  }
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
  const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
  if (!methods.includes(currentMethodFilter)) currentMethodFilter = "GET";

  let html = `
    <div class="endpoint-controls">
      <h3>Endpoints</h3>
      <label class="method-select-label">Method</label>
      <div class="method-dropdown" id="methodDropdown">
        <button type="button" class="method-select" id="methodSelectBtn" aria-haspopup="listbox" aria-expanded="false">
          ${currentMethodFilter}
          <span class="select-caret" aria-hidden="true"></span>
        </button>
        <div class="method-options" id="methodOptions" role="listbox">
          ${methods
            .map(
              (m) =>
                `<div class="method-option ${m === currentMethodFilter ? "is-selected" : ""}" role="option" data-method="${m}">${m}</div>`
            )
            .join("")}
        </div>
      </div>
      <label class="method-select-label" for="pathFilter">Filter</label>
      <input id="pathFilter" class="path-filter" type="text" placeholder="e.g. /users or /auth" value="${currentPathFilter || ""}">
    </div>
    <ul>
  `;

  for (const path in swagger.paths) {
    for (const method in swagger.paths[path]) {
      const upper = method.toUpperCase();
      if (upper !== currentMethodFilter) continue;
      if (currentPathFilter) {
        const needle = currentPathFilter.toLowerCase();
        if (!path.toLowerCase().includes(needle)) continue;
      }
      html += `<li><button class="endpoint-btn" data-path="${path}" data-method="${method}">${upper} ${path}</button></li>`;
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

  const dropdown = document.getElementById("methodDropdown");
  const selectBtn = document.getElementById("methodSelectBtn");
  const options = document.getElementById("methodOptions");
  const pathFilter = document.getElementById("pathFilter");

  if (pathFilter) {
    pathFilter.addEventListener("input", (e) => {
      currentPathFilter = String(e.target.value || "");
      showEndpoints(swagger);
      const refocus = document.getElementById("pathFilter");
      if (refocus) {
        refocus.focus();
        const v = refocus.value;
        try {
          refocus.setSelectionRange(v.length, v.length);
        } catch (err) {}
      }
    });
  }

  if (dropdown && selectBtn && options) {
    const closeDropdown = () => {
      dropdown.classList.remove("is-open");
      selectBtn.setAttribute("aria-expanded", "false");
    };

    selectBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const willOpen = !dropdown.classList.contains("is-open");
      document.querySelectorAll(".method-dropdown.is-open").forEach((el) => el.classList.remove("is-open"));
      if (willOpen) {
        dropdown.classList.add("is-open");
        selectBtn.setAttribute("aria-expanded", "true");
        const outsideHandler = (evt) => {
          if (!dropdown.contains(evt.target)) closeDropdown();
        };
        document.addEventListener("click", outsideHandler, { once: true });
      } else {
        closeDropdown();
      }
    });

    options.querySelectorAll(".method-option").forEach((opt) => {
      opt.addEventListener("click", (e) => {
        const method = String(e.currentTarget.dataset.method || "GET").toUpperCase();
        currentMethodFilter = method;
        closeDropdown();
        showEndpoints(swagger);
      });
    });

  }
}

async function runTest(path, method) {
  if (isRunningTest) return;
  const baseUrl = extractBaseUrl(currentSwagger);
  if (!baseUrl) {
    output.innerHTML = "Unable to determine baseUrl.";
    return;
  }
  const apiToken = getSavedApiToken();
  if (!apiToken) {
    output.innerHTML = "Request an API key before starting the test.";
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
      output.innerHTML = "Limit exceeded: too many runs for this endpoint (max per minute). Please try again later.";
      return;
    }
    _lastRuns[key].push(now);
  } catch (e) {
    // non-fatal
  }

  const endpointContext = getEndpointContext(currentSwagger, path, method);
  output.style.display = "block";
  output.innerHTML = 'Testing in progress<span class="loading-dots"><span>.</span><span>.</span><span>.</span></span>';
  setRunState(true);

  try {
    const headers = { "Content-Type": "application/json" };
    headers[API_TOKEN_HEADER] = apiToken;
    const options = { connections: DEFAULT_CONCURRENCY, duration: DEFAULT_DURATION };

    async function sendRunTest() {
      return await fetch(RUN_TEST_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({ baseUrl, path, method, endpointContext, options, apiKeyToken: apiToken }),
      });
    }

    async function wait(ms) {
      return new Promise((res) => setTimeout(res, ms));
    }

    let response = await sendRunTest();

    if (!response.ok) {
      let backendMessage = `Backend error (HTTP ${response.status})`;
      if ([502, 503, 504].includes(response.status)) {
        output.innerHTML = "Backend is waking up (free hosting). Please wait...";
        await wait(25000);
        response = await sendRunTest();
        if (response.ok) {
          const result = await response.json();
          updateTimeline(result);
          return;
        }
        backendMessage = "Backend is unavailable or waking up (free hosting). Try again in 30-60 seconds.";
      }
      try {
        const errData = await response.json();
        if (errData?.error) backendMessage = errData.error;
      } catch (e) {}
      throw new Error(backendMessage);
    }

    const result = await response.json();
    updateTimeline(result);
  } catch (err) {
    const rawMsg = String(err?.message || "Backend is not running.");
    const isNetwork =
      /Failed to fetch|NetworkError|timeout|Fetch timeout|ECONNREFUSED|ENOTFOUND/i.test(rawMsg);
    if (isNetwork) {
      try {
        output.innerHTML = "Backend is waking up (free hosting). Please wait...";
        await wait(25000);
        const retryResponse = await sendRunTest();
        if (retryResponse.ok) {
          const result = await retryResponse.json();
          updateTimeline(result);
          return;
        }
      } catch (e) {}
    }
    const friendly = isNetwork
      ? "Backend is unavailable or waking up (free hosting). Try again in 30-60 seconds."
      : rawMsg;
    output.innerHTML = `Test not started: ${escapeHtml(friendly)}`;
  } finally {
    setRunState(false);
  }
}

function updateTimeline(result) {
  const report = result.report || null;

  if (!report) {
    timelineList.innerHTML = "No report data.";
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
  const analysisSummary = analysis.summary || "Analysis is not available.";
  const recommendations = Array.isArray(analysis.recommendations) ? analysis.recommendations : [];
  const cleanConclusion = String(analysis.conclusion || analysisSummary).replace(/^Conclusion:\s*/i, "");
  const interpretation = [analysis.securityAssessment, analysis.performanceAssessment]
    .filter((item) => typeof item === "string" && item.trim().length > 0)
    .join(" ");
  const recommendationsHtml = recommendations.length
    ? `<ul class="analysis-recommendations">${recommendations.slice(0, 2).map((r) => `<li>${escapeHtml(shortenText(r, 140))}</li>`).join("")}</ul>`
    : "<p>No additional recommendations.</p>";

  timelineList.innerHTML = `
    <section class="report-shell">
      <header class="report-head">
        <h4>${escapeHtml(report.title)}</h4>
        <p><strong>Endpoint:</strong> ${escapeHtml(report.endpoint.url)}</p>
        <p><strong>${escapeHtml(report.endpoint.method)} | ${escapeHtml(new Date(report.generatedAt).toLocaleString())}</strong></p>
      </header>

      <section class="report-card">
        <div class="grade-row">
          <span class="grade-label">Test score</span>
          <span class="test-grade-pill ${escapeHtml(gradeTone)}">${escapeHtml(grade10)}/10</span>
        </div>
        <p><strong>Tests:</strong> ${escapeHtml(report.summary.totalTests)} | <strong>Passed:</strong> ${escapeHtml(report.summary.passed)} | <strong>Failed:</strong> ${escapeHtml(report.summary.failed)} | <strong>Inconclusive:</strong> ${escapeHtml(report.summary.inconclusive ?? 0)}</p>
        <p><strong>Security score:</strong> ${escapeHtml(report.summary.securityScore)}% | <strong>Risk:</strong> ${escapeHtml(report.summary.riskLevel)}</p>
        <p><strong>Latency:</strong> ${escapeHtml(perf.avgLatencyMs ?? "N/A")} ms (P99 ${escapeHtml(perf.latencyP99 ?? "N/A")} ms) | <strong>RPS:</strong> ${escapeHtml(perf.requestsPerSec ?? "N/A")} | <strong>Errors:</strong> ${escapeHtml(perf.errorCount ?? "N/A")}</p>
      </section>

      <section class="report-card">
        <h5>Result Analysis (Automatic)</h5>
        <p><strong>${escapeHtml(shortenText(analysis.headline || "N/A", 120))}</strong></p>
        <p><strong>Security:</strong> ${escapeHtml(analysis.securityLevel || "N/A")} | <strong>Performance:</strong> ${escapeHtml(analysis.performanceLevel || "N/A")}</p>
        <p><strong>Interpretation:</strong> ${escapeHtml(shortenText(interpretation || analysisSummary, 260))}</p>
        <div><strong>Recommendations:</strong>${recommendationsHtml}</div>
        <p><strong>Conclusion:</strong> ${escapeHtml(shortenText(cleanConclusion, 200))}</p>
      </section>

      <section class="report-card">
        <h5>Detailed Findings</h5>
        <div class="findings-list">${findingsHtml || "<p>No findings.</p>"}</div>
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
