const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const autocannon = require("autocannon");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.get("/health", (req, res) => res.json({ ok: true }));

const testsByMode = {
  query: [
    { type: "Query Deep SQLi", value: "' OR 1=1 UNION SELECT null,null,null --" },
    { type: "Query Encoded XSS", value: encodeURIComponent("<script>alert(1)</script>") },
    { type: "Query NoSQL Injection", value: '{"$ne":null}' },
    { type: "Query Long Param Stress", value: "A".repeat(8000) },
  ],
  path: [
    { type: "Path SQLi Boolean", value: "1 OR 1=1" },
    { type: "Path Traversal Attempt", value: "../".repeat(8) + "etc/passwd" },
    { type: "Path Large Numeric", value: "9".repeat(500) },
  ],
  body: [
    { type: "Body SQLi In User Field", value: "admin' OR '1'='1' --" },
    { type: "Body XSS Script Payload", value: "<script>alert('xss')</script>" },
    { type: "Body Overlong Suspicious Input", value: "A".repeat(4096) + "../etc/passwd%00" },
  ],
  form: [
    { type: "Form SQLi In Field", value: "test' UNION SELECT null,null --" },
    { type: "Form HTML/JS Injection", value: "<img src=x onerror=alert(1)>" },
    { type: "Form Overlong + Traversal", value: "B".repeat(3000) + "..%2f..%2fwindows%2fwin.ini%00" },
  ],
};

function chooseMode(method, endpointContext) {
  const hasQuery = (endpointContext?.queryParams || []).length > 0;
  const hasPath = Object.keys(endpointContext?.pathParamValues || {}).length > 0;
  const hasForm = (endpointContext?.formDataParams || []).length > 0;
  const hasBody = Boolean(endpointContext?.bodyTemplate) || (endpointContext?.bodyFields || []).length > 0;

  if (hasForm) return "form";
  if (hasBody && method !== "GET" && method !== "DELETE") return "body";
  if (hasQuery) return "query";
  if (hasPath) return "path";
  return method === "GET" || method === "DELETE" ? "query" : "body";
}

function resolvePath(path, pathParams) {
  return path.replace(/\{([^}]+)\}/g, (_, key) => encodeURIComponent(pathParams[key] || "test"));
}

function joinUrl(baseUrl, path) {
  const cleanBase = String(baseUrl || "").replace(/\/+$/, "");
  const cleanPath = String(path || "").startsWith("/") ? String(path) : `/${String(path)}`;
  return `${cleanBase}${cleanPath}`;
}

function buildUrl(baseUrl, path, queryParams, value) {
  const target = new URL(joinUrl(baseUrl, path));
  if ((queryParams || []).length === 0) return target.toString();
  const payloadValue = typeof value === "string" ? value : JSON.stringify(value);
  queryParams.forEach((name) => target.searchParams.set(name, payloadValue));
  return target.toString();
}

function deepClone(value) {
  return value === null || value === undefined ? value : JSON.parse(JSON.stringify(value));
}

function setByPath(obj, path, value) {
  if (!obj || !path) return;
  const keys = path.split(".");
  let cursor = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (!cursor[key] || typeof cursor[key] !== "object") cursor[key] = {};
    cursor = cursor[key];
  }
  cursor[keys[keys.length - 1]] = value;
}

function buildMultipartBody(formParams, value) {
  const boundary = `----codex-boundary-${Date.now()}`;
  const lines = [];
  const fields = formParams || [];
  fields.forEach((field, idx) => {
    const currentValue = idx === 0 ? value : "test";
    lines.push(`--${boundary}`);
    if (field.type === "file") {
      lines.push(`Content-Disposition: form-data; name="${field.name}"; filename="test.txt"`);
      lines.push("Content-Type: text/plain");
      lines.push("");
      lines.push(String(currentValue));
    } else {
      lines.push(`Content-Disposition: form-data; name="${field.name}"`);
      lines.push("");
      lines.push(String(currentValue));
    }
  });
  lines.push(`--${boundary}--`, "");
  return { body: lines.join("\r\n"), contentType: `multipart/form-data; boundary=${boundary}` };
}

function buildRequest(method, mode, testValue, endpointContext) {
  const options = { method, headers: { "Content-Type": "application/json" } };
  if (mode === "form") {
    const form = buildMultipartBody(endpointContext?.formDataParams || [], testValue);
    options.headers["Content-Type"] = form.contentType;
    options.body = form.body;
    return options;
  }

  if (mode === "body" && method !== "GET" && method !== "DELETE") {
    const template = deepClone(endpointContext?.bodyTemplate);
    if (template && typeof template === "object" && !Array.isArray(template)) {
      const fieldPath = endpointContext?.injectFieldPath || endpointContext?.bodyFields?.[0] || null;
      setByPath(template, fieldPath, testValue);
      options.body = JSON.stringify(template);
    } else {
      const field = endpointContext?.bodyFields?.[0];
      options.body = JSON.stringify(field ? { [field]: testValue } : testValue);
    }
  }

  return options;
}

function evaluate(value, response, responseText) {
  if (!response) return { status: "Failed", note: "Nema odgovora servera.", message: "Server nije odgovorio." };
  if (response.status >= 500) return { status: "Failed", note: "Server je pao (5xx).", message: "Server error - payload izazvao gresku." };
  if ([413, 414, 415].includes(response.status)) return { status: "Passed", note: `Server je odbio payload (${response.status}).`, message: "Payload blokiran, zastita radi." };
  if (response.status >= 400 && response.status < 500) return { status: "Passed", note: `Server je odbio payload (${response.status}).`, message: "Payload blokiran." };
  if (response.status >= 200 && response.status < 300) {
    const valueStr = typeof value === "string" ? value : JSON.stringify(value);
    if (responseText && responseText.includes(valueStr)) return { status: "Failed", note: "Payload reflektovan u odgovoru.", message: "Payload je procesiran i reflektovan." };
    return { status: "Failed", note: "Server je prihvatio payload.", message: "Payload nije blokiran." };
  }
  return { status: "Failed", note: `Neocekivan status (${response.status}).`, message: "Neispravan odgovor servera." };
}

function runAutocannon(options) {
  return new Promise((resolve, reject) => {
    autocannon(options, (err, res) => {
      if (err) reject(err);
      else {
        res.errors = res.errors || 0;
        res.timeouts = res.timeouts || 0;
        res.latency = res.latency || {};
        res.requests = res.requests || {};
        res.throughput = res.throughput || {};
        res.bytes = res.bytes || {};
        res["1xx"] = res["1xx"] || 0;
        res["2xx"] = res["2xx"] || 0;
        res["3xx"] = res["3xx"] || 0;
        res["4xx"] = res["4xx"] || 0;
        res["5xx"] = res["5xx"] || 0;
        resolve(res);
      }
    });
  });
}

app.post("/run-test", async (req, res) => {
  const { baseUrl, path, method, endpointContext } = req.body;
  if (!baseUrl || !path || !method) return res.status(400).json({ error: "Nedostaju parametri" });

  const normalizedMethod = method.toUpperCase();
  const mode = chooseMode(normalizedMethod, endpointContext);
  const tests = testsByMode[mode] || testsByMode.body;
  const basePathParams = endpointContext?.pathParamValues || {};
  const defaultPath = resolvePath(path, basePathParams);
  const baseTargetUrl = joinUrl(baseUrl, defaultPath);
  const results = [];

  for (const test of tests) {
    try {
      const pathValues = { ...basePathParams };
      if (mode === "path") {
        const firstPathKey = Object.keys(pathValues)[0];
        if (firstPathKey) pathValues[firstPathKey] = test.value;
      }

      const resolvedPath = resolvePath(path, pathValues);
      const targetUrl = buildUrl(baseUrl, resolvedPath, mode === "query" ? endpointContext?.queryParams || [] : [], test.value);
      const options = buildRequest(normalizedMethod, mode, test.value, endpointContext);
      const response = await fetch(targetUrl, options);
      const text = await response.text().catch(() => "");
      const verdict = evaluate(test.value, response, text);

      results.push({
        type: test.type,
        payload: test.value,
        status: verdict.status,
        note: verdict.note,
        response: { message: verdict.message, raw: text, statusCode: response.status },
        timestamp: new Date().toISOString(),
        url: targetUrl,
        method: normalizedMethod,
      });
    } catch (err) {
      results.push({
        type: test.type,
        payload: test.value,
        status: "Failed",
        note: "Greska pri konekciji ili obradi payload-a.",
        response: { message: err.message, raw: "", statusCode: null },
        timestamp: new Date().toISOString(),
        url: baseTargetUrl,
        method: normalizedMethod,
      });
    }
  }

  const firstTest = tests[0] || { value: "test" };
  const loadPathValues = { ...basePathParams };
  if (mode === "path") {
    const firstPathKey = Object.keys(loadPathValues)[0];
    if (firstPathKey) loadPathValues[firstPathKey] = firstTest.value;
  }

  const loadResolvedPath = resolvePath(path, loadPathValues);
  const loadTargetUrl = buildUrl(
    baseUrl,
    loadResolvedPath,
    mode === "query" ? endpointContext?.queryParams || [] : [],
    firstTest.value
  );

  const options = buildRequest(normalizedMethod, mode, firstTest.value, endpointContext);
  const loadOpts = {
    url: loadTargetUrl,
    method: normalizedMethod,
    connections: normalizedMethod === "GET" ? 20 : 8,
    duration: 5,
    timeout: 10,
    headers: options.headers || {},
    body: options.body || undefined,
  };

  let load;
  try {
    load = await runAutocannon(loadOpts);
  } catch (err) {
    load = { latency: {}, requests: {}, throughput: {}, bytes: {}, errors: 1, timeouts: 0 };
  }

  const passed = results.filter((item) => item.status === "Passed").length;
  const failed = results.filter((item) => item.status === "Failed").length;
  const totalTests = results.length;
  const securityScore = totalTests === 0 ? 0 : Math.round((passed / totalTests) * 100);
  const totalLoadRequests = load.requests?.total || 0;
  const status2xx = load["2xx"] || 0;
  const successRatePct = totalLoadRequests === 0 ? "0.00" : ((status2xx / totalLoadRequests) * 100).toFixed(2);

  const report = {
    title: "API Security Test Report",
    generatedAt: new Date().toISOString(),
    endpoint: { url: baseTargetUrl, method: normalizedMethod },
    summary: { totalTests, passed, failed, securityScore, riskLevel: failed > 0 ? "High" : "Low" },
    performance: {
      avgLatencyMs: (load.latency?.average || 0).toFixed(2),
      latencyMinMs: (load.latency?.min || 0).toFixed(2),
      latencyP50: (load.latency?.p50 || 0).toFixed(2),
      latencyP90: (load.latency?.p90 || 0).toFixed(2),
      latencyP99: (load.latency?.p99 || 0).toFixed(2),
      latencyMaxMs: (load.latency?.max || 0).toFixed(2),
      requestsPerSec: (load.requests?.average || 0).toFixed(2),
      throughputKbPerSec: ((load.throughput?.average || 0) / 1024).toFixed(2),
      totalRequests: totalLoadRequests,
      status2xx: status2xx,
      status4xx: load["4xx"] || 0,
      status5xx: load["5xx"] || 0,
      successRatePct: successRatePct,
      errorCount: load.errors ?? 0,
      timeouts: load.timeouts ?? 0,
      totalBytes: load.bytes?.total || 0,
    },
    findings: results.map((item) => ({
      testType: item.type,
      status: item.status,
      note: item.note,
      message: item.response.message,
      statusCode: item.response.statusCode,
      url: item.url,
      timestamp: item.timestamp,
      payload: item.payload,
    })),
  };

  res.json({
    report,
    url: baseTargetUrl,
    method: normalizedMethod,
    avgLatency: load.latency?.average || 0,
    requestsPerSec: load.requests?.average || 0,
    totalRequests: load.requests?.total || 0,
    errorCount: load.errors ?? 0,
    timeoutCount: load.timeouts ?? 0,
    securityResults: results,
    status: "Zavrseno",
  });
});

app.listen(PORT, () => console.log(`Backend radi na portu ${PORT}`));
