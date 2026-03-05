let currentSwagger = null;
const BACKEND_URL = "http://localhost:3000";
const _lastRuns = {};
const _maxRunsPerMinute = 2;

const swaggerInput = document.getElementById("swaggerUrl");
const loadBtn = document.getElementById("loadSwagger");
const output = document.getElementById("output");
const timeline = document.getElementById("timeline");
const timelineList = document.getElementById("timelineList");
const backBtn = document.getElementById("backBtn");

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

loadBtn.addEventListener("click", async () => {
  const url = swaggerInput.value.trim();
  if (!url) return;

  try {
    const swagger = await (await fetch(url)).json();
    currentSwagger = swagger;
    showEndpoints(swagger);
  } catch {
    output.innerHTML = "Greska pri ucitavanju Swagger dokumentacije.";
  }
});

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

  try {
    const response = await fetch(`${BACKEND_URL}/run-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseUrl, path, method, endpointContext }),
    });

    const result = await response.json();
    updateTimeline(result);
  } catch {
    output.innerHTML = "Backend nije pokrenut.";
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
  const findingsHtml = (report.findings || [])
    .map((finding) => `
      <article class="finding-item">
        <p><strong>Test:</strong> ${escapeHtml(finding.testType)}</p>
        <p><strong>Status:</strong> ${escapeHtml(finding.status)}</p>
        <p><strong>Napomena:</strong> ${escapeHtml(finding.note)}</p>
        <p><strong>Poruka:</strong> ${escapeHtml(finding.message)}</p>
        <p><strong>HTTP status:</strong> ${escapeHtml(finding.statusCode ?? "N/A")}</p>
        <p><strong>Vrijeme:</strong> ${escapeHtml(new Date(finding.timestamp).toLocaleString())}</p>
        <details>
          <summary>Prikazi payload</summary>
          <pre>${escapeHtml(finding.payload)}</pre>
        </details>
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
    ? `<ul class="analysis-recommendations">${recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
    : "<p>Nema dodatnih preporuka.</p>";

  timelineList.innerHTML = `
    <section class="report-shell">
      <header class="report-head">
        <h4>${escapeHtml(report.title)}</h4>
        <p><strong>Endpoint:</strong> ${escapeHtml(report.endpoint.url)}</p>
        <p><strong>Metoda:</strong> ${escapeHtml(report.endpoint.method)}</p>
        <p><strong>Generisano:</strong> ${escapeHtml(new Date(report.generatedAt).toLocaleString())}</p>
      </header>

      <section class="report-grid">
        <article class="report-card">
          <h5>Security sazetak</h5>
          <p><strong>Ukupno testova:</strong> ${escapeHtml(report.summary.totalTests)}</p>
          <p><strong>Proslo:</strong> ${escapeHtml(report.summary.passed)}</p>
          <p><strong>Palo:</strong> ${escapeHtml(report.summary.failed)}</p>
          <p><strong>Security score:</strong> ${escapeHtml(report.summary.securityScore)}%</p>
          <p><strong>Risk level:</strong> ${escapeHtml(report.summary.riskLevel)}</p>
        </article>

        <article class="report-card">
          <h5>Performance</h5>
          <p><strong>Avg latency:</strong> ${escapeHtml(perf.avgLatencyMs ?? "N/A")} ms</p>
          <p><strong>P50/P90/P99:</strong> ${escapeHtml(perf.latencyP50 ?? "N/A")} / ${escapeHtml(perf.latencyP90 ?? "N/A")} / ${escapeHtml(perf.latencyP99 ?? "N/A")} ms</p>
          <p><strong>Requests/sec:</strong> ${escapeHtml(perf.requestsPerSec ?? "N/A")}</p>
          <p><strong>Errors/Timeouts:</strong> ${escapeHtml(perf.errorCount ?? "N/A")} / ${escapeHtml(perf.timeouts ?? "N/A")}</p>
        </article>
      </section>

      <section class="report-card">
        <h5>Analiza rezultata (Automatska)</h5>
        <div class="analysis-grid">
          <p><strong>Naslov:</strong> ${escapeHtml(analysis.headline || "N/A")}</p>
          <p><strong>Sigurnost:</strong> ${escapeHtml(analysis.securityLevel || "N/A")}</p>
          <p><strong>Performanse:</strong> ${escapeHtml(analysis.performanceLevel || "N/A")}</p>
        </div>
        <p><strong>Interpretacija:</strong> ${escapeHtml(interpretation || analysisSummary)}</p>
        <div><strong>Preporuke:</strong>${recommendationsHtml}</div>
        <p><strong>Zakljucak:</strong> ${escapeHtml(cleanConclusion)}</p>
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

  backBtn.onclick = () => {
    timeline.style.display = "none";
    output.style.display = "block";
    backBtn.style.display = "none";
    if (currentSwagger) showEndpoints(currentSwagger);
  };
}
