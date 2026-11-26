// Meridian Systems Helpdesk -- a deliberately vulnerable Node.js app.
// No npm dependencies on purpose (just Node's built-in http/url) --
// MinIO's community binaries disappearing from distribution mid-
// project is a fresh enough lesson not to add an avoidable external
// dependency to a box that doesn't need one.
"use strict";
const http = require("http");
const fs = require("fs");

const FLAGS = JSON.parse(fs.readFileSync("/opt/app/flags.json", "utf8"));
const OPS_ACCOUNT = "ops-triage";
const OPS_PASSWORD = "Triage-Escalate-99!"; // fixed/narrative -- leaked via the auth-bypassed admin endpoint

// --- THE vulnerability: a naive recursive merge with no __proto__/
// constructor/prototype key filtering. For plain objects this merges
// `__proto__` right into Object.prototype itself (an ordinary,
// real-world prototype-pollution bug class, not contrived for this
// box -- the same missing-key-filter pattern shows up in real naive
// deep-merge implementations and in several real npm packages'
// pre-patch CVEs).
function merge(target, source) {
  for (const key in source) {
    if (source[key] !== null && typeof source[key] === "object") {
      if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function sendText(res, status, text, contentType = "text/plain") {
  res.writeHead(status, { "Content-Type": contentType, "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) req.destroy();
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/") {
    sendText(
      res, 200,
      `<!doctype html><html><head><title>Meridian Systems Helpdesk</title></head><body>
<h1>Meridian Systems -- Internal Helpdesk</h1>
<p>Log a ticket, check ticket status, or view the changelog.</p>
<!-- ${FLAGS["1"]} -->
<ul><li><a href="/tickets/1">Ticket #1</a></li><li><a href="/CHANGELOG.md">Changelog</a></li></ul>
</body></html>`,
      "text/html",
    );
    return;
  }

  if (req.method === "GET" && url.pathname === "/tickets/1") {
    sendText(
      res, 200,
      `Ticket #1 -- Welcome to the new helpdesk portal
================================================
Status: closed
Submitted by: onboarding-bot

Welcome flag: ${FLAGS["2"]}

Heads up: profile preferences now accept nested JSON (see the
changelog) -- handy for saving complex notification settings.`,
    );
    return;
  }

  if (req.method === "GET" && url.pathname === "/CHANGELOG.md") {
    sendText(
      res, 200,
      `# Changelog

## v2.4.0
- Profile preferences (POST /api/profile) now accept arbitrary nested
  JSON objects, merged into your saved settings. No more flat
  key-value pairs only!

Changelog flag: ${FLAGS["3"]}

(Internal note, should've been removed before this went out: the
merge is a plain recursive \`for...in\` walk, nothing special-cased.)`,
      "text/markdown",
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/profile") {
    let parsed;
    try {
      parsed = JSON.parse(await readBody(req));
    } catch {
      sendJson(res, 400, { error: "invalid JSON" });
      return;
    }
    const merged = merge({}, parsed);
    sendJson(res, 200, { merged, flag4: FLAGS["4"] });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/whoami") {
    const ctx = {}; // a fresh plain object every request -- its own
    // properties are never set to isAdmin anywhere in this app. If
    // this reads true, it can only be because Object.prototype itself
    // was polluted by a prior /api/profile request.
    const body = { isAdmin: !!ctx.isAdmin };
    if (ctx.isAdmin) body.flag5 = FLAGS["5"];
    sendJson(res, 200, body);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/users") {
    const ctx = {};
    if (!ctx.isAdmin) {
      sendJson(res, 403, { error: "forbidden" });
      return;
    }
    sendJson(res, 200, {
      flag6: FLAGS["6"],
      users: [{ username: OPS_ACCOUNT, password: OPS_PASSWORD, note: "also this account's SSH login on the helpdesk host -- never rotated" }],
    });
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(5000, "0.0.0.0");
