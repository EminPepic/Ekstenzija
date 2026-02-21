let currentSwagger = null;
const BACKEND_URL = "https://YOUR-BACKEND-URL";

const swaggerInput = document.getElementById("swaggerUrl");
const loadBtn = document.getElementById("loadSwagger");
const output = document.getElementById("output");
const timeline = document.getElementById("timeline");
const timelineList = document.getElementById("timelineList");
const backBtn = document.getElementById("backBtn");

loadBtn.addEventListener("click", async () => {
  const url = swaggerInput.value.trim();
  if (!url) return;

  try {
    const res = await fetch(url);
    const swagger = await res.json();
    currentSwagger = swagger;
    showEndpoints(swagger);
  } catch {
    output.innerHTML = "GreÅ¡ka pri uÄitavanju Swagger dokumentacije.";
  }
});

function extractBaseUrl(swagger) {
  if (swagger.servers && swagger.servers.length > 0) return swagger.servers[0].url;
  if (swagger.host) {
    const scheme = swagger.schemes ? swagger.schemes[0] : "https";
    const basePath = swagger.basePath || "";
    return `${scheme}://${swagger.host}${basePath}`;
  }
  return null;
}

function showEndpoints(swagger) {
  let html = "<h3>Endpoint-i:</h3><ul>";
  for (const path in swagger.paths) {
    for (const method in swagger.paths[path]) {
      html += `<li><button class="endpoint-btn" data-path="${path}" data-method="${method}">${method.toUpperCase()} ${path}</button></li>`;
    }
  }
  html += "</ul>";
  output.innerHTML = html;
  timeline.style.display = "none";  
  backBtn.style.display = "none";  

  document.querySelectorAll(".endpoint-btn").forEach(btn => {
    btn.onclick = () => runTest(btn.dataset.path, btn.dataset.method);
  });
}

async function runTest(path, method) {
  const baseUrl = extractBaseUrl(currentSwagger);
  if (!baseUrl) { output.innerHTML = "Ne mogu odrediti baseUrl."; return; }
  output.innerHTML = "Testiranje u toku...";

  try {
    const response = await fetch(`${BACKEND_URL}/run-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseUrl, path, method })
    });
    const result = await response.json();
    updateTimeline(result);
  } catch {
    output.innerHTML = "Backend nije pokrenut (localhost:3000).";
  }
}

function updateTimeline(result) {
  const testDate = new Date().toLocaleString();
  let html = `<li>
    <strong>Testiranje za URL:</strong> ${result.url}<br>
    <strong>Metoda:</strong> ${result.method}<br>
    <strong>Datum:</strong> ${testDate}<br>
    <strong>Avg Latency:</strong> ${result.avgLatency} ms<br>
    <strong>Requests/sec:</strong> ${result.requestsPerSec}<br>
    <strong>Error rate:</strong> ${result.errorRate}
  </li><hr>`;

  result.securityResults.forEach((test) => {
    html += `<li>
      <strong>Sigurnosni test:</strong> ${test.type}<br>
      <strong>Status:</strong> ${test.status}<br>
      <strong>Napomena:</strong> ${test.note}<br>
      <strong>Payload:</strong> ${JSON.stringify(test.payload)}<br>
      
      <details style="max-width:800px; background:#f0f0f0; padding:5px; margin:5px 0;">
        <summary style="cursor:pointer;">PrikaÅ¾i Response</summary>
        <pre style="max-height:300px; overflow:auto;">${JSON.stringify(test.response, null, 2)}</pre>
      </details>
      
      <strong>Vreme:</strong> ${new Date(test.timestamp).toLocaleString()}
    </li>`;
  });

  timelineList.innerHTML = html;
  timeline.style.display = "block";
  backBtn.style.display = "block";

  backBtn.onclick = () => {
  timeline.style.display = "none";       
  output.style.display = "block";        
  backBtn.style.display = "none";        

  if (currentSwagger) {
    showEndpoints(currentSwagger);
  }
};
}
