const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const autocannon = require("autocannon");

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

const payloads = [
  { type: "SQL Injection", data: "' OR '1'='1" },
  { type: "XSS", data: "<script>alert('XSS')</script>" },
  { type: "NoSQL Injection", data: { "$gt": "" } },
  { type: "Large Input", data: "A".repeat(10000) },
  { type: "Command Injection", data: "; ls -la" },
];

function evaluateSecurityResult(payload, response, dataStr) {
  // Security tests pass only when malicious input is rejected.
  if (typeof payload.data === "string" && dataStr.includes(payload.data)) {
    return {
      status: "Failed",
      note: "Server je obradio stetan payload koji nije smio da obradi (reflektovan odgovor).",
      responseMessage: "Doslo je do greske: stetan payload je prosao.",
    };
  }

  if (response.status >= 400 && response.status < 500) {
    return {
      status: "Passed",
      note: "Server je odbio stetan test (4xx) i to je ispravno.",
      responseMessage: "Stetan payload je blokiran.",
    };
  }

  if (response.status >= 500) {
    return {
      status: "Failed",
      note: "Doslo je do greske servera (5xx) pri obradi stetnog testa.",
      responseMessage: "Test pada: server je pao na stetnom payload-u.",
    };
  }

  return {
    status: "Failed",
    note: "Server je obradio stetan payload koji nije smio da obradi.",
    responseMessage: "Doslo je do greske: stetan payload je prosao.",
  };
}

app.post("/run-test", async (req, res) => {
  const { baseUrl, path, method } = req.body;
  if (!baseUrl || !path || !method) {
    return res.status(400).json({ error: "Nedostaju parametri" });
  }

  let results = [];

  for (let payload of payloads) {
    let options = {
      method: method.toUpperCase(),
      headers: { "Content-Type": "application/json" },
    };
    if (method.toUpperCase() !== "GET") {
      options.body = JSON.stringify(payload.data);
    }

    try {
      const response = await fetch(baseUrl + path, options);
      const data = await response.json().catch(() => ({}));

      let status = "Failed";
      let note = "";
      let responseMessage = "";
      const dataStr = JSON.stringify(data);
      const evaluation = evaluateSecurityResult(payload, response, dataStr);

      status = evaluation.status;
      note = evaluation.note;
      responseMessage = evaluation.responseMessage;
      const truncatedResponse = JSON.stringify(data).length > 500
        ? JSON.stringify(data).slice(0, 500) + " ...[truncated]"
        : JSON.stringify(data);

      results.push({
        type: payload.type,
        payload: payload.data,
        status,
        note: note || "Server je uspešno obradio payload.",
        response: {
          message: responseMessage,
          data: truncatedResponse
        },
        timestamp: new Date().toISOString(),
        url: baseUrl + path,
        method: method.toUpperCase(),
      });

    } catch (err) {
      results.push({
        type: payload.type,
        payload: payload.data,
        status: "Failed",
        note: "Greška pri konekciji ili obradi payload-a.",
        response: { message: err.message, data: "" },
        timestamp: new Date().toISOString(),
        url: baseUrl + path,
        method: method.toUpperCase(),
      });
    }
  }

  const loadResult = await autocannon({
    url: baseUrl + path,
    method: method.toUpperCase(),
    connections: 10,
    duration: 5,
  });

  res.json({
    url: baseUrl + path,
    method: method.toUpperCase(),
    avgLatency: loadResult.latency.average,
    requestsPerSec: loadResult.requests.average,
    errorRate: loadResult.errors,
    securityResults: results,
    status: "Završeno",
  });
});

app.listen(PORT, () => console.log(`Backend radi na portu ${PORT}`));
