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

# API key access

Users request an API key from the Chrome extension by clicking **Request API key**.
The backend issues a short-lived token and the UI shows a masked value only.

# Operations (access & revocation)

Access is granted by setting the backend API_KEY value (comma-separated list).
The backend issues temporary tokens via an HttpOnly cookie (not readable by JS).

To revoke access:
* rotate API_KEY to invalidate all existing access

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
   - `set API_KEY=key1,key2`
   - `node app.js`

2. Chrome extension
   - Open `chrome://extensions`
   - Enable **Developer mode**
   - Click **Load unpacked** and select `swagger-plugin`
   - In the UI, set the backend URL (default is already set) and click **Request API key**

# Local vs Public (Render) usage

You have two ways to run the project, depending on what you want to test.

## Option A: Local backend (recommended for testing local services)

Use this if you want to test APIs that run on your own machine (localhost or private network).

Steps:
1. Start the backend locally (see **Quick start (local)** above).
2. In the extension UI, set the backend URL to:
   - `http://localhost:3000`
3. Now you can test local services like:
   - `http://localhost:5000`
   - `http://127.0.0.1:8080`

Why this works:
When the backend runs locally, `localhost` points to your own computer.

## Option B: Public backend (Render) for public URLs only

Use this if you want a zero-setup demo or to test public/staging URLs.

Important:
If the backend runs on Render, it **cannot access your local machine**.
So `localhost` or private network targets will not work.

Steps:
1. Keep the backend URL set to the Render service:
   - `https://swagger-tester-backend.onrender.com`
2. Only test public URLs (staging, sandbox, demo APIs).

## Switching default backend (optional)

The extension stores the backend URL in `localStorage`.
If you want to change the default:

- Open `swagger-plugin/popup.js`
- You will see:

```js
// const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "http://localhost:3000").trim();
const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "https://swagger-tester-backend.onrender.com").trim();
```

If you want localhost as default, comment/uncomment like this:

```js
const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "http://localhost:3000").trim();
// const BACKEND_URL = (localStorage.getItem("swaggerTesterBackendUrl") || "https://swagger-tester-backend.onrender.com").trim();
```

# Configuration

Backend environment variables:

* `API_KEY` - comma-separated list of server-side keys (not exposed to clients)
* `API_KEY_HEADER` - header name for the key (default: `x-api-key`)
* `API_TOKEN_TTL_MS` - token lifetime in ms (default: 15m)
* `FETCH_TIMEOUT_MS` - request timeout (default: 30000)
* `TIME_DELAY_THRESHOLD_MS` - extra delay threshold for time-based checks (default: 2500)
* `TIME_MIN_DELAY_MS` - minimum delay threshold for time-based checks (default: 4000)
* `DIFF_SIMILARITY_THRESHOLD` - similarity threshold for valid vs invalid comparison (default: 0.15)
* `MAX_CHAINED_TESTS` - number of chained payload tests (default: 12)

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

* **Passed** - payload was blocked or safely handled
* **Failed** - vulnerability indicators found
* **Inconclusive** - result is unclear

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










