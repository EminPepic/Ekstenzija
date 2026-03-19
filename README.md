# Swagger Tester

**Swagger Tester** is an automatic API endpoint testing tool that combines a **Chrome extension** and a **Node.js backend service** deployed on Render.

The user provides a **Swagger / OpenAPI URL**, selects an endpoint, and receives a **security and performance report**.

# Project purpose

The tool enables fast **security profiling of API endpoints** directly from Swagger/OpenAPI documentation without manual request crafting.

Automatically:

* loads the API definition
* lists available endpoints and methods
* runs security tests
* performs a lightweight performance test
* generates a structured report

# Responsible use

Use this tool **only** on systems you own or have explicit permission to test. Do not use it against production services without authorization.

# How the app works

1. The user enters a **Swagger/OpenAPI URL** in the Chrome extension
2. The extension parses the document and lists endpoints
3. The user selects an **endpoint and HTTP method**
4. The data is sent to the backend service
5. The backend runs security and performance tests
6. A **complete report** is generated and displayed in the extension

# Quick start (local)

1. Backend
   - `cd Node-backend`
   - `npm install`
   - `set API_KEY=your_key_here`
   - `node app.js`

2. Chrome extension
   - Open `chrome://extensions`
   - Enable **Developer mode**
   - Click **Load unpacked** and select `swagger-plugin`
   - In the UI, set the backend URL (default is already set) and enter the API key

# Configuration

Backend environment variables:

* `API_KEY` – required for all requests
* `API_KEY_HEADER` – header name for the key (default: `x-api-key`)
* `FETCH_TIMEOUT_MS` – request timeout (default: 30000)
* `TIME_DELAY_THRESHOLD_MS` – extra delay threshold for time-based checks (default: 2500)
* `TIME_MIN_DELAY_MS` – minimum delay threshold for time-based checks (default: 4000)
* `DIFF_SIMILARITY_THRESHOLD` – similarity threshold for valid vs invalid comparison (default: 0.15)
* `MAX_CHAINED_TESTS` – number of chained payload tests (default: 12)
   
# Security tests

Common API vulnerabilities are tested:

* SQL Injection
* XSS
* Command Injection
* Path Traversal
* SSRF probe
* NoSQL Injection
* Template Injection
* CRLF/Header Injection
* Overlong and stress payloads

Payloads are adapted to parameter types:

* query
* path
* JSON body
* form-data

# Result evaluation logic

Results are evaluated based on:

* HTTP status
* response content
* comparison with a baseline response
* payload reflection
* SQL error markers
* response changes
* response time anomalies

Test status can be:

* **Passed** – payload was blocked or safely handled
* **Failed** – vulnerability indicators found
* **Inconclusive** – result is unclear

# Report includes

* total number of tests
* Passed / Failed / Inconclusive results
* security score and risk level
* detailed findings per test
* performance metrics (latency, requests/sec, errors)
* automatically generated conclusion and recommendations

# Project structure

swagger-plugin/  
Chrome extension (UI and test runner)

Node-backend/  
Express service for executing tests

render.yaml  
Render deployment configuration
```

# Backend deployment

Backend service:

https://swagger-tester-backend.onrender.com

Health check:

https://swagger-tester-backend.onrender.com/health

Running tests:
```
POST /run-test
```
*automatic API security and performance testing*.
