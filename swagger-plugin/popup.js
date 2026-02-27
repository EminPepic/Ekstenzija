let currentSwagger = null;
const BACKEND_URL = "http://localhost:3000";

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
  const consumes = operation.consumes || swagger.consumes || [];

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

  return { queryParams, bodyFields, pathParamValues, bodyTemplate, injectFieldPath, consumes, formDataParams };
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

  // Performance podaci (Autocannon)
  const perf = report.performance || {};
  let perfHtml = `
    <ul>
      <li><strong>Avg latency:</strong> ${escapeHtml(perf.avgLatencyMs ?? 'N/A')} ms</li>
      <li><strong>Latency P50:</strong> ${escapeHtml(perf.latencyP50 ?? 'N/A')} ms</li>
      <li><strong>Latency P90:</strong> ${escapeHtml(perf.latencyP90 ?? 'N/A')} ms</li>
      <li><strong>Latency P99:</strong> ${escapeHtml(perf.latencyP99 ?? 'N/A')} ms</li>
      <li><strong>Requests/sec:</strong> ${escapeHtml(perf.requestsPerSec ?? 'N/A')}</li>
      <li><strong>Total requests:</strong> ${escapeHtml(perf.totalRequests ?? 'N/A')}</li>
      <li><strong>Errors:</strong> ${escapeHtml(perf.errorCount ?? 'N/A')}</li>
      <li><strong>Timeouts:</strong> ${escapeHtml(perf.timeouts ?? 'N/A')}</li>
      <li><strong>Total bytes transferred:</strong> ${escapeHtml(perf.totalBytes ?? 'N/A')}</li>
    </ul>
  `;

  let html = `<li>
      <strong>${escapeHtml(report.title)}</strong><br>
      <strong>Endpoint:</strong> ${escapeHtml(report.endpoint.url)}<br>
      <strong>Metoda:</strong> ${escapeHtml(report.endpoint.method)}<br>
      <strong>Generisano:</strong> ${escapeHtml(new Date(report.generatedAt).toLocaleString())}<br>
      <strong>Ukupno testova:</strong> ${escapeHtml(report.summary.totalTests)}<br>
      <strong>Proslo:</strong> ${escapeHtml(report.summary.passed)}<br>
      <strong>Palo:</strong> ${escapeHtml(report.summary.failed)}<br>
      <strong>Security score:</strong> ${escapeHtml(report.summary.securityScore)}%<br>
      <strong>Risk level:</strong> ${escapeHtml(report.summary.riskLevel)}<br>
      <strong>Performance detalji:</strong>${perfHtml}
    </li><hr>`;

  report.findings.forEach((finding) => {
    html += `<li>
      <strong>Test:</strong> ${escapeHtml(finding.testType)}<br>
      <strong>Status:</strong> ${escapeHtml(finding.status)}<br>
      <strong>Napomena:</strong> ${escapeHtml(finding.note)}<br>
      <strong>Payload:</strong><pre>${escapeHtml(finding.payload)}</pre>
      <strong>Poruka:</strong> ${escapeHtml(finding.message)}<br>
      <strong>HTTP status:</strong> ${escapeHtml(finding.statusCode ?? "N/A")}<br>
      <strong>URL:</strong> ${escapeHtml(finding.url)}<br>
      <strong>Vrijeme:</strong> ${escapeHtml(new Date(finding.timestamp).toLocaleString())}
    </li><hr>`;
  });

  timelineList.innerHTML = html;
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
