const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const autocannon = require("autocannon");

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

const payloads = [
  { type: "SQL Injection", data: "' OR '1'='1" },
  { type: "XSS", data: "<script>alert('XSS')</script>" },
  { type: "NoSQL Injection", data: { "$gt": "" } },
  { type: "Large Input", data: "A".repeat(10000) },
  { type: "Command Injection", data: "; ls -la" },
];

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

      let status = "Passed";
      let note = "";
      let responseMessage = "";

      const dataStr = JSON.stringify(data);

      if (payload.type === "XSS" && dataStr.includes(payload.data)) {
        status = "Vulnerable";
        note = "Payload reflektovan – moguća XSS ranjivost.";
        responseMessage = "XSS payload je uspešno izvršen!";
      }
      if (payload.type === "Command Injection" && dataStr.includes(payload.data)) {
        status = "Vulnerable";
        note = "Payload reflektovan – moguća Command Injection ranjivost.";
        responseMessage = "Command Injection payload je uspešno izvršen!";
      }
      if (payload.type === "SQL Injection" && dataStr.includes(payload.data)) {
        status = "Vulnerable";
        note = "Payload reflektovan – moguća SQL Injection ranjivost.";
        responseMessage = "SQL Injection payload je uspešno izvršen!";
      }
      if (payload.type === "Large Input") {
        status = response.ok ? "Passed" : "Failed";
        note = "Test velikog input-a, proveriti obradu servera.";
        responseMessage = response.ok ? "Server je obradio veliki input." : "Server nije obradio veliki input ispravno.";
      }
      if (payload.type === "NoSQL Injection") {
        status = response.ok ? "Passed" : "Failed";
        note = "NoSQL payload obrađen ili odbijen.";
        responseMessage = response.ok ? "NoSQL payload je uspešno obrađen." : "NoSQL payload je odbijen.";
      }

      if (!note && !response.ok && response.status >= 500) {
        note = "Server error: endpoint nije obradio payload, ne mora da znači ranjivost.";
        responseMessage = "Greška servera pri obradi payload-a.";
      }

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
