/**
 * Coordination Server — Bulletin Board for Distributed Party Testing.
 *
 * Runs on ONE machine (Laptop 1). Expose via ngrok so other laptops can reach it:
 *   ngrok http 3000
 *
 * This is a PUBLIC BULLETIN BOARD:
 * - Public data (commitments, proofs, Paillier PKs, deltas) → posted openly
 * - Sub-shares f_i(j) → pass through server (trusted for testing)
 *   For production: encrypt sub-shares with the recipient's NaCl public key first.
 *
 * Endpoints:
 *   POST /set/:topic    { "value": "..." }  — store any string value under a topic
 *   GET  /get/:topic?wait=1               — fetch value (long-polls up to 120s if wait=1)
 *   DELETE /clear                         — wipe all state (before each test run)
 *   GET  /list                            — list all stored keys (debug)
 *
 * Usage:
 *   cd client && npx tsx src/coord-server.ts
 *   # then: ngrok http 3000
 */

import * as http from "http";

const PORT = parseInt(process.env.PORT ?? "3000");

// In-memory KV store: topic → value string
const store = new Map<string, string>();

// Pending long-pollers: topic → list of waiting ServerResponse objects
const waiters = new Map<string, http.ServerResponse[]>();

/** Wake up all waiters for a topic with the newly stored value. */
function notifyWaiters(topic: string, value: string) {
  const pending = waiters.get(topic) ?? [];
  waiters.delete(topic);
  for (const res of pending) {
    if (!res.writableEnded) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, value }));
    }
  }
}

function parseBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  // Parse URL
  const base = `http://localhost:${PORT}`;
  let url: URL;
  try {
    url = new URL(req.url ?? "/", base);
  } catch {
    res.writeHead(400);
    res.end(JSON.stringify({ error: "bad url" }));
    return;
  }

  const parts = url.pathname.replace(/^\//, "").split("/");
  const action = parts[0];
  const topic = parts.slice(1).join("/");

  // CORS — allow any origin (needed for ngrok tunneling)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // ---------- POST /set/:topic ----------
  if (req.method === "POST" && action === "set" && topic) {
    let body: string;
    try {
      body = await parseBody(req);
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "body read failed" }));
      return;
    }

    let parsed: { value?: string };
    try {
      parsed = JSON.parse(body);
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "json parse failed" }));
      return;
    }

    if (typeof parsed.value !== "string") {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "value must be a string" }));
      return;
    }

    store.set(topic, parsed.value);
    console.log(`  [SET] ${topic}  (${parsed.value.length} chars)`);
    notifyWaiters(topic, parsed.value);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ---------- GET /get/:topic ----------
  if (req.method === "GET" && action === "get" && topic) {
    const shouldWait = url.searchParams.get("wait") === "1";
    const existing = store.get(topic);

    if (existing !== undefined) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, value: existing }));
      return;
    }

    if (!shouldWait) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not found" }));
      return;
    }

    // Long-poll: register as a waiter, send response when value arrives
    if (!waiters.has(topic)) waiters.set(topic, []);
    waiters.get(topic)!.push(res);
    console.log(`  [WAIT] ${topic}  (${(waiters.get(topic)?.length ?? 0)} waiting)`);

    // Timeout after 120s
    const timer = setTimeout(() => {
      const list = waiters.get(topic) ?? [];
      const idx = list.indexOf(res);
      if (idx >= 0) list.splice(idx, 1);
      if (list.length === 0) waiters.delete(topic);
      if (!res.writableEnded) {
        res.writeHead(408, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "timeout — no value posted within 120s" }));
      }
    }, 120_000);

    req.on("close", () => clearTimeout(timer));
    return;
  }

  // ---------- DELETE /clear ----------
  if (req.method === "DELETE" && action === "clear") {
    const keyCount = store.size;
    const waiterCount = [...waiters.values()].reduce((s, arr) => s + arr.length, 0);
    store.clear();
    // Send timeout to all pending waiters before clearing
    for (const list of waiters.values()) {
      for (const r of list) {
        if (!r.writableEnded) {
          r.writeHead(410, { "Content-Type": "application/json" });
          r.end(JSON.stringify({ ok: false, error: "cleared" }));
        }
      }
    }
    waiters.clear();
    console.log(`  [CLEAR] wiped ${keyCount} keys, cancelled ${waiterCount} waiters`);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, cleared: keyCount }));
    return;
  }

  // ---------- GET /list ----------
  if (req.method === "GET" && action === "list") {
    const keys = [...store.keys()].sort();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, count: keys.length, keys }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: `unknown route: ${req.method} ${url.pathname}` }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n  Kosh — Coordination Server (Bulletin Board)`);
  console.log(`  ============================================`);
  console.log(`  Listening on http://0.0.0.0:${PORT}\n`);
  console.log(`  Next steps:`);
  console.log(`    1. Run: ngrok http ${PORT}`);
  console.log(`    2. Copy the ngrok HTTPS URL`);
  console.log(`    3. Share it with Laptop 2 and Laptop 3 as COORD_URL\n`);
  console.log(`  Endpoints:`);
  console.log(`    POST   /set/:topic     { "value": "..." }   — post a value`);
  console.log(`    GET    /get/:topic?wait=1                  — fetch (long-poll)`);
  console.log(`    DELETE /clear                              — wipe all state`);
  console.log(`    GET    /list                               — debug: list keys\n`);
  console.log(`  Waiting for parties...\n`);
});
