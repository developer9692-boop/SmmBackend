// ============================================================
// AstroPulse Backend — server.js
// Node.js + Express + File-based JSON database
//
// Features
//  • Public service catalog        GET  /api/services
//  • Admin: SMM API providers      /api/admin/providers   (read-only, configured in .env; test only)
//  • Admin: services linked to a provider service ID   /api/admin/services
//      - DELETE /api/admin/services        -> remove ALL services at once
//      - DELETE /api/admin/services/:id    -> remove one service
//  • Admin: forward an order to the provider, check status, request refill
//  • Legacy orders API             /api/orders
//
// Admin routes are protected by the admin's Firebase login (Bearer token)
// checked against ADMIN_EMAILS in .env. ADMIN_KEY is an optional fallback.
// Requires Node 18+ (built-in fetch).
// ============================================================

const express = require("express");
const cors    = require("cors");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

// Load .env from the project folder (no extra dependency needed)
(function loadEnv() {
  try {
    const file = path.join(__dirname, ".env");
    if (!fs.existsSync(file)) return;
    for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!m) continue;
      let v = m[2].trim();
      if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1);
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    }
  } catch { /* ignore */ }
})();

const app       = express();
const PORT      = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";

const DATA_DIR = path.join(__dirname, "data");
const DB       = path.join(__dirname, "orders.json");           // legacy orders
const FILES = {
  providers: path.join(DATA_DIR, "providers.json"),
  services:  path.join(DATA_DIR, "services.json"),
  sent:      path.join(DATA_DIR, "provider-orders.json")        // log of orders forwarded to providers
};

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Never serve source, data or secret files (providers.json holds API keys)
const BLOCKED = /^\/(data|node_modules|\.git)(\/|$)|^\/(server\.js|package(-lock)?\.json|orders\.json|readme\.md|\.env[^/]*)$/i;
app.use((req, res, next) => {
  let p;
  try { p = decodeURIComponent(req.path).replace(/\\/g, "/"); }
  catch { return res.status(400).end(); }
  if (BLOCKED.test(p)) return res.status(404).end();
  next();
});
app.use(express.static(__dirname));       // serve HTML files

// ── Storage helpers ─────────────────────────────────────────
function readJson(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

/** Atomic write: write to temp file, then rename */
function writeJson(file, data) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
  fs.renameSync(tmp, file);
}

// The SMM API is configured ONLY in the server .env file:
//   SMM_API_URL=https://provider.example.com/api/v2
//   SMM_API_KEY=your-provider-key
//   SMM_API_NAME=Provider name (optional)
// It cannot be added, edited or deleted from the admin panel.
const ENV_PROVIDER_ID = "env_provider";
function envProvider() {
  const url = String(process.env.SMM_API_URL || "").trim();
  const key = String(process.env.SMM_API_KEY || "").trim();
  if (!url || !key) return null;
  return {
    id: ENV_PROVIDER_ID,
    name: String(process.env.SMM_API_NAME || "SMM Provider").trim() || "SMM Provider",
    url, key,
    active: true,
    createdAt: null
  };
}
const readProviders = () => { const p = envProvider(); return p ? [p] : []; };
// Every service is fulfilled by the single .env provider
const readServices  = () => {
  const list = readJson(FILES.services);
  return envProvider() ? list.map(s => ({ ...s, providerId: ENV_PROVIDER_ID })) : list;
};
const writeServices = (d) => writeJson(FILES.services, d);
const readSent       = () => readJson(FILES.sent);
const writeSent      = (d) => writeJson(FILES.sent, d);

function readOrders() {
  if (!fs.existsSync(DB)) fs.writeFileSync(DB, "[]", "utf8");
  return readJson(DB);
}
function writeOrders(orders) { writeJson(DB, orders); }

function genId() {
  return "AP-" + Math.random().toString(36).toUpperCase().slice(2, 8);
}
function nowIST() {
  return new Date().toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: true
  });
}

/** Wrap async route handlers so errors reach our error handler */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ── Admin auth ───────────────────────────────────────────────
// Admins are verified with their Firebase login token (no key typed in the panel).
//   FIREBASE_API_KEY=<same apiKey as in firebase-config.js>
//   ADMIN_EMAILS=you@gmail.com,other@gmail.com
// ADMIN_KEY (x-admin-key header) still works as an optional fallback for scripts.
const FIREBASE_API_KEY = String(process.env.FIREBASE_API_KEY || "").trim();
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
const FIREBASE_READY = !!FIREBASE_API_KEY && ADMIN_EMAILS.length > 0;

function sha(s) { return crypto.createHash("sha256").update(String(s)).digest(); }

const tokenCache = new Map();   // idToken -> { email, exp }
async function verifyFirebaseAdmin(token) {
  const hit = tokenCache.get(token);
  if (hit && hit.exp > Date.now()) return hit.email;

  let r;
  try {
    r = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(FIREBASE_API_KEY),
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken: token }) }
    );
  } catch { throw new HttpError(502, "Could not reach Firebase to verify the admin login"); }
  if (!r.ok) return null;
  const d = await r.json();
  const u = d.users && d.users[0];
  if (!u || !u.email || u.disabled || !u.emailVerified) return null;
  const email = String(u.email).toLowerCase();
  if (!ADMIN_EMAILS.includes(email)) return null;

  if (tokenCache.size > 200) tokenCache.clear();
  tokenCache.set(token, { email, exp: Date.now() + 5 * 60 * 1000 });
  return email;
}

async function requireAdmin(req, res, next) {
  try {
    if (!FIREBASE_READY && !ADMIN_KEY) {
      return res.status(503).json({
        error: "Admin auth is not configured. Set FIREBASE_API_KEY and ADMIN_EMAILS in the server .env file."
      });
    }

    const bearer = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (bearer && FIREBASE_READY) {
      const email = await verifyFirebaseAdmin(bearer);
      if (email) { req.adminEmail = email; return next(); }
    }

    const given = req.get("x-admin-key") || "";
    if (ADMIN_KEY && given && crypto.timingSafeEqual(sha(given), sha(ADMIN_KEY))) return next();

    return res.status(401).json({ error: "Not authorized as admin" });
  } catch (err) {
    next(err);
  }
}

// ── Provider helpers ────────────────────────────────────────
function maskKey(key) {
  const k = String(key || "");
  return k.length > 4 ? "••••" + k.slice(-4) : "••••";
}

function publicProvider(p, services) {
  return {
    id: p.id,
    name: p.name,
    url: p.url,
    keyHint: maskKey(p.key),
    active: p.active !== false,
    locked: true,
    source: "env",
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
    serviceCount: services.filter(s => s.providerId === p.id).length
  };
}

function cleanUrl(value) {
  const url = String(value || "").trim();
  let parsed;
  try { parsed = new URL(url); } catch { throw new HttpError(400, "Enter a valid API URL, e.g. https://cheapsmmmarket.com/api/v2"); }
  if (!/^https?:$/.test(parsed.protocol)) throw new HttpError(400, "API URL must start with http:// or https://");
  return parsed.toString();
}

function findProvider() {
  const provider = envProvider();
  if (!provider) throw new HttpError(503, "SMM API is not configured. Set SMM_API_URL and SMM_API_KEY in the server .env file and restart.");
  return provider;
}

/** Standard SMM panel API v2 call (POST, form-encoded, key + action) */
async function providerCall(provider, params) {
  const body = new URLSearchParams({ key: provider.key, ...params });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 25000);
  let resp, text;
  try {
    resp = await fetch(provider.url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: ctrl.signal
    });
    text = await resp.text();
  } catch (err) {
    throw new HttpError(502, err.name === "AbortError"
      ? "Provider API timed out"
      : "Could not reach provider API: " + err.message);
  } finally {
    clearTimeout(timer);
  }

  let data;
  try { data = JSON.parse(text); }
  catch { throw new HttpError(502, `Provider returned an invalid response (HTTP ${resp.status})`); }

  if (data && !Array.isArray(data) && data.error) throw new HttpError(502, "Provider error: " + data.error);
  if (!resp.ok) throw new HttpError(502, `Provider returned HTTP ${resp.status}`);
  return data;
}

// Cache of provider service lists (they can be thousands of rows)
const svcCache = new Map();     // providerId -> { at, list }
const SVC_TTL  = 5 * 60 * 1000;

async function getProviderServices(provider, force = false) {
  const hit = svcCache.get(provider.id);
  if (!force && hit && Date.now() - hit.at < SVC_TTL) return hit.list;
  const list = await providerCall(provider, { action: "services" });
  if (!Array.isArray(list)) throw new HttpError(502, "Provider did not return a service list");
  svcCache.set(provider.id, { at: Date.now(), list });
  return list;
}

function trimProviderService(s) {
  return {
    service:  s.service,
    name:     s.name,
    category: s.category,
    type:     s.type,
    rate:     s.rate,
    min:      s.min,
    max:      s.max,
    refill:   s.refill,
    cancel:   s.cancel
  };
}

// ── Service helpers ─────────────────────────────────────────
function normalizeService(body, existing) {
  const b = body || {};
  const str = (v, d = "") => (v === undefined || v === null ? (d == null ? "" : d) : String(v).trim());
  const num = (v) => Number(v);

  const svc = {
    id:                existing ? existing.id : (b.id === "" || b.id == null ? null : num(b.id)),
    platform:          str(b.platform, existing && existing.platform).toLowerCase(),
    name:              str(b.name, existing && existing.name),
    providerId:        str(b.providerId, existing && existing.providerId),
    providerServiceId: str(b.providerServiceId, existing && existing.providerServiceId),
    start:             str(b.start, existing && existing.start),
    speed:             str(b.speed, existing && existing.speed),
    refill:            str(b.refill, existing && existing.refill),
    drop:              str(b.drop, existing && existing.drop),
    quality:           str(b.quality, existing && existing.quality),
    type:              str(b.type, (existing && existing.type) || "Default") || "Default",
    rate:              b.rate === undefined ? (existing && existing.rate) : num(b.rate),
    min:               b.min  === undefined ? (existing && existing.min)  : num(b.min),
    max:               b.max  === undefined ? (existing && existing.max)  : num(b.max),
    active:            b.active === undefined ? (existing ? existing.active !== false : true) : !!b.active
  };

  if (!svc.platform)          throw new HttpError(400, "Platform is required");
  if (!svc.name)              throw new HttpError(400, "Service name is required");
  if (!svc.providerId)        throw new HttpError(400, "Select an API provider");
  if (!svc.providerServiceId) throw new HttpError(400, "Provider service ID is required");
  if (!(svc.rate > 0))        throw new HttpError(400, "Rate per 1K must be greater than 0");
  if (!Number.isInteger(svc.min) || svc.min < 1) throw new HttpError(400, "Minimum must be a whole number of at least 1");
  if (!Number.isInteger(svc.max) || svc.max < svc.min) throw new HttpError(400, "Maximum must be a whole number not lower than minimum");
  if (svc.id !== null && (!Number.isInteger(svc.id) || svc.id < 1)) throw new HttpError(400, "Service ID must be a positive whole number");

  if (!readProviders().some(p => p.id === svc.providerId)) throw new HttpError(400, "Selected API provider does not exist");
  return svc;
}

function publicService(s) {
  // Customers never see which provider fulfils a service
  const { providerId, providerServiceId, ...rest } = s;
  return rest;
}

// ============================================================
// PUBLIC ROUTES
// ============================================================

// GET /api/services — active services for the storefront
app.get("/api/services", (req, res) => {
  let list = readServices().filter(s => s.active !== false);
  if (req.query.platform) {
    const p = String(req.query.platform).toLowerCase();
    list = list.filter(s => s.platform === p);
  }
  res.json(list.map(publicService));
});

// ============================================================
// ADMIN — API PROVIDERS
// ============================================================
const admin = express.Router();
admin.use(requireAdmin);

// Quick auth check used by the admin panel "Connect" button
admin.get("/ping", (req, res) => res.json({ success: true }));

admin.get("/providers", (req, res) => {
  const services = readServices();
  res.json(readProviders().map(p => publicProvider(p, services)));
});

// Providers are configured in .env only: add / edit / delete are blocked.
const lockedProvider = (req, res) => {
  throw new HttpError(403, "The SMM API is configured in the server .env file (SMM_API_URL / SMM_API_KEY). It cannot be changed from the panel.");
};
admin.post("/providers", lockedProvider);
admin.put("/providers/:id", lockedProvider);
admin.patch("/providers/:id", lockedProvider);
admin.delete("/providers/:id", lockedProvider);

// Test an API (fetch balance)
admin.post("/providers/:id/test", wrap(async (req, res) => {
  const provider = findProvider(req.params.id);
  const data = await providerCall(provider, { action: "balance" });
  res.json({ success: true, balance: data.balance, currency: data.currency });
}));

// Look up one provider service by its ID (to auto-fill name / min / max)
admin.get("/providers/:id/services/:serviceId", wrap(async (req, res) => {
  const provider = findProvider(req.params.id);
  const list = await getProviderServices(provider, req.query.refresh === "true");
  const found = list.find(s => String(s.service) === String(req.params.serviceId));
  if (!found) throw new HttpError(404, `Service ${req.params.serviceId} was not found on ${provider.name}`);
  res.json({ success: true, service: trimProviderService(found) });
}));

// Full provider service list (for browsing)
admin.get("/providers/:id/services", wrap(async (req, res) => {
  const provider = findProvider(req.params.id);
  const list = await getProviderServices(provider, req.query.refresh === "true");
  res.json(list.map(trimProviderService));
}));

// ============================================================
// ADMIN — SERVICES
// ============================================================
admin.get("/services", (req, res) => {
  res.json(readServices());
});

admin.post("/services", (req, res) => {
  const services = readServices();
  const svc = normalizeService(req.body, null);

  if (svc.id === null) {
    svc.id = services.reduce((m, s) => Math.max(m, Number(s.id) || 0), 1000) + 1;   // auto ID
  } else if (services.some(s => Number(s.id) === svc.id)) {
    throw new HttpError(409, `Service ID ${svc.id} already exists`);
  }

  svc.createdAt = new Date().toISOString();
  services.push(svc);
  writeServices(services);
  res.status(201).json({ success: true, service: svc });
});

admin.put("/services/:id", (req, res) => {
  const services = readServices();
  const idx = services.findIndex(s => String(s.id) === String(req.params.id));
  if (idx === -1) throw new HttpError(404, "Service not found");

  const updated = normalizeService(req.body, services[idx]);
  updated.createdAt = services[idx].createdAt;
  updated.updatedAt = new Date().toISOString();
  services[idx] = updated;
  writeServices(services);
  res.json({ success: true, service: updated });
});

// DELETE /api/admin/services — remove ALL services at once.
// Platforms (Instagram, Facebook, ...) are not stored on the server, so they are not affected.
admin.delete("/services", (req, res) => {
  const count = readServices().length;
  writeServices([]);
  console.log(`[SERVICES] All services removed (${count}) by ${req.adminEmail || "admin key"}`);
  res.json({ success: true, removed: count });
});

// DELETE /api/admin/services/:id — remove one service
admin.delete("/services/:id", (req, res) => {
  const services = readServices();
  const next = services.filter(s => String(s.id) !== String(req.params.id));
  if (next.length === services.length) throw new HttpError(404, "Service not found");
  writeServices(next);
  res.json({ success: true });
});

// ============================================================
// ADMIN — FORWARD ORDERS TO THE PROVIDER
// ============================================================
const inFlight = new Set();

// POST /api/admin/provider-order
// body: { reference, serviceId, link, quantity, comments? }
admin.post("/provider-order", wrap(async (req, res) => {
  const { reference, serviceId, link, comments } = req.body;
  const quantity = Number(req.body.quantity);
  const ref = String(reference || "").trim();

  if (!ref)  throw new HttpError(400, "reference (your order ID) is required");
  if (!link) throw new HttpError(400, "Order link is required");

  const service = readServices().find(s => String(s.id) === String(serviceId));
  if (!service) throw new HttpError(404, `Service ${serviceId} not found`);
  const provider = findProvider(service.providerId);
  if (provider.active === false) throw new HttpError(400, `API provider "${provider.name}" is disabled`);

  const hasComments = typeof comments === "string" && comments.trim().length > 0;
  if (!hasComments) {
    if (!Number.isInteger(quantity) || quantity < service.min || quantity > service.max) {
      throw new HttpError(400, `Quantity must be between ${service.min} and ${service.max}`);
    }
  }

  // Duplicate protection — never spend provider balance twice for one order
  const sent = readSent();
  const prior = sent.find(e => e.reference === ref);
  if (prior) throw new HttpError(409, `Order already sent to provider (provider order #${prior.providerOrderId})`);
  if (inFlight.has(ref)) throw new HttpError(409, "This order is already being sent");
  inFlight.add(ref);

  try {
    const params = { action: "add", service: service.providerServiceId, link: String(link).trim() };
    if (hasComments) params.comments = comments.trim();
    else params.quantity = quantity;

    const data = await providerCall(provider, params);
    if (!data || data.order === undefined || data.order === null) {
      throw new HttpError(502, "Provider did not return an order ID");
    }

    sent.push({
      reference: ref,
      serviceId: service.id,
      providerId: provider.id,
      providerServiceId: service.providerServiceId,
      providerOrderId: data.order,
      link: String(link).trim(),
      quantity: hasComments ? null : quantity,
      sentAt: new Date().toISOString()
    });
    writeSent(sent);

    console.log(`[PROVIDER] ${ref} → ${provider.name} order #${data.order}`);
    res.json({ success: true, providerOrderId: data.order, providerId: provider.id, providerName: provider.name });
  } finally {
    inFlight.delete(ref);
  }
}));

// POST /api/admin/provider-status  body: { providerId, orderId }
admin.post("/provider-status", wrap(async (req, res) => {
  const provider = findProvider(String(req.body.providerId || ""));
  if (!req.body.orderId) throw new HttpError(400, "orderId is required");
  const data = await providerCall(provider, { action: "status", order: req.body.orderId });
  res.json({ success: true, ...data });
}));

// POST /api/admin/provider-refill  body: { providerId, orderId }
admin.post("/provider-refill", wrap(async (req, res) => {
  const provider = findProvider(String(req.body.providerId || ""));
  if (!req.body.orderId) throw new HttpError(400, "orderId is required");
  const data = await providerCall(provider, { action: "refill", order: req.body.orderId });
  res.json({ success: true, ...data });
}));

app.use("/api/admin", admin);

// ============================================================
// LEGACY ORDERS API (file based)
// ============================================================

// GET /api/orders — admin only (contains customer IPs / transaction IDs)
app.get("/api/orders", requireAdmin, (req, res) => {
  const orders = readOrders().reverse();
  res.json(orders);
});

// POST /api/orders — create a new order (public)
app.post("/api/orders", (req, res) => {
  try {
    const { platform, service, link, quantity, price, transactionId, coupon, device, browser, os, ip } = req.body;

    if (!platform || !service || !link || !quantity || !transactionId) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const order = {
      _id:           genId(),
      platform:      platform   || "",
      service:       service    || "",
      link:          link       || "",
      quantity:      quantity   || 0,
      amount:        price      || 0,
      coupon:        coupon     || "",
      transactionId: transactionId,
      device:        device     || "Unknown",
      browser:       browser    || "Unknown",
      os:            os         || "Unknown",
      ip:            ip         || "Unknown",
      status:        "Pending",
      createdAt:     new Date().toISOString(),
      createdAtIST:  nowIST()
    };

    const orders = readOrders();
    orders.push(order);
    writeOrders(orders);

    console.log(`[POST] New order saved — ID: ${order._id}, Platform: ${platform}`);
    res.status(201).json({ success: true, order });
  } catch (err) {
    console.error("[POST] Error:", err.message);
    res.status(500).json({ error: "Failed to save order" });
  }
});

function patchOrder(req, res) {
  const { id }     = req.params;
  const { status } = req.body;
  const orders     = readOrders();
  const idx        = orders.findIndex(o => o._id === id);

  if (idx === -1) return res.status(404).json({ error: "Order not found" });

  orders[idx].status    = status || orders[idx].status;
  orders[idx].updatedAt = new Date().toISOString();
  writeOrders(orders);

  console.log(`[PATCH] Order ${id} → ${status}`);
  res.json({ success: true, order: orders[idx] });
}
app.patch("/api/orders/:id", requireAdmin, patchOrder);
app.put("/api/orders/:id",   requireAdmin, patchOrder);

app.delete("/api/orders/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  let orders   = readOrders();
  const before = orders.length;
  orders       = orders.filter(o => o._id !== id);

  if (orders.length === before) return res.status(404).json({ error: "Order not found" });

  writeOrders(orders);
  console.log(`[DELETE] Order ${id} removed`);
  res.json({ success: true });
});

// ── Health check ─────────────────────────────────────────────
// Open /api in a browser to confirm THIS version of server.js is the one running.
app.get("/api", (req, res) => {
  res.json({
    ok: true,
    name: "AstroPulse API",
    version: "bulk-delete-services",
    adminAuthConfigured: FIREBASE_READY || !!ADMIN_KEY
  });
});

// ── Error handler ────────────────────────────────────────────
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {          // eslint-disable-line no-unused-vars
  const status = err.status || 500;
  if (status >= 500) console.error(`[ERROR] ${req.method} ${req.originalUrl} —`, err.message);
  res.status(status).json({ error: status === 500 ? "Internal server error" : err.message });
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  AstroPulse server running at http://localhost:${PORT}`);
  if (!FIREBASE_READY && !ADMIN_KEY) {
    console.warn("⚠️   Admin API disabled. Set FIREBASE_API_KEY and ADMIN_EMAILS in .env");
  }
  const ep = envProvider();
  if (!ep) {
    console.warn("⚠️   SMM API not configured. Add SMM_API_URL and SMM_API_KEY to .env");
  } else {
    try { new URL(ep.url); console.log(`🔗  SMM API: ${ep.name} (${ep.url})`); }
    catch { console.warn("⚠️   SMM_API_URL in .env is not a valid URL"); }
  }
  if (typeof fetch !== "function") {
    console.warn("⚠️   This Node version has no built-in fetch. Use Node 18 or newer.");
  }
});
