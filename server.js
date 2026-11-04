// ============================================================
// AstroPulse Backend — server.js
// Node.js + Express + File-based JSON database
//
// Features
//  • Public service catalog        GET  /api/services
//  • Admin: SMM API providers      /api/admin/providers   (add / edit / delete / test)
//  • Admin: services linked to a provider service ID   /api/admin/services
//  • Admin: forward an order to the provider, check status, request refill
//  • Legacy orders API             /api/orders
//
// Admin routes are protected by the ADMIN_KEY environment variable
// (sent by the admin panel in the "x-admin-key" header).
// Requires Node 18+ (built-in fetch).
// ============================================================

const express = require("express");
const cors    = require("cors");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

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

const readProviders  = () => readJson(FILES.providers);
const writeProviders = (d) => writeJson(FILES.providers, d);
const readServices   = () => readJson(FILES.services);
const writeServices  = (d) => writeJson(FILES.services, d);
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
function sha(s) { return crypto.createHash("sha256").update(String(s)).digest(); }

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    return res.status(503).json({
      error: "ADMIN_KEY is not set on the server. Start the server with ADMIN_KEY=your-secret npm start"
    });
  }
  const given = req.get("x-admin-key") || "";
  if (!crypto.timingSafeEqual(sha(given), sha(ADMIN_KEY))) {
    return res.status(401).json({ error: "Invalid admin key" });
  }
  next();
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

function findProvider(id) {
  const provider = readProviders().find(p => p.id === id);
  if (!provider) throw new HttpError(404, "API provider not found");
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

admin.post("/providers", (req, res) => {
  const name = String(req.body.name || "").trim();
  const key  = String(req.body.key || "").trim();
  if (!name) throw new HttpError(400, "Provider name is required");
  if (!key)  throw new HttpError(400, "API key is required");
  const url = cleanUrl(req.body.url);

  const providers = readProviders();
  const provider = {
    id: "p_" + crypto.randomBytes(4).toString("hex"),
    name, url, key,
    active: true,
    createdAt: new Date().toISOString()
  };
  providers.push(provider);
  writeProviders(providers);
  res.status(201).json({ success: true, provider: publicProvider(provider, readServices()) });
});

admin.put("/providers/:id", (req, res) => {
  const providers = readProviders();
  const idx = providers.findIndex(p => p.id === req.params.id);
  if (idx === -1) throw new HttpError(404, "API provider not found");
  const p = providers[idx];

  if (req.body.name !== undefined) {
    const name = String(req.body.name).trim();
    if (!name) throw new HttpError(400, "Provider name is required");
    p.name = name;
  }
  if (req.body.url !== undefined) p.url = cleanUrl(req.body.url);
  const newKey = String(req.body.key || "").trim();
  if (newKey) p.key = newKey;                     // blank key = keep the existing one
  if (req.body.active !== undefined) p.active = !!req.body.active;
  p.updatedAt = new Date().toISOString();

  writeProviders(providers);
  svcCache.delete(p.id);
  res.json({ success: true, provider: publicProvider(p, readServices()) });
});

admin.delete("/providers/:id", (req, res) => {
  const providers = readProviders();
  const provider = providers.find(p => p.id === req.params.id);
  if (!provider) throw new HttpError(404, "API provider not found");

  const services = readServices();
  const linked = services.filter(s => s.providerId === provider.id);
  if (linked.length && req.query.force !== "true") {
    return res.status(409).json({
      error: `${linked.length} service(s) use this API. Deleting it will also delete those services.`,
      serviceCount: linked.length
    });
  }

  writeProviders(providers.filter(p => p.id !== provider.id));
  if (linked.length) writeServices(services.filter(s => s.providerId !== provider.id));
  svcCache.delete(provider.id);
  res.json({ success: true, deletedServices: linked.length });
});

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
app.get("/api", (req, res) => {
  res.json({ ok: true, name: "AstroPulse API", adminKeyConfigured: !!ADMIN_KEY });
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
  if (!ADMIN_KEY) {
    console.warn("⚠️   ADMIN_KEY is not set — admin API routes are disabled.");
    console.warn("    Start with:  ADMIN_KEY=your-long-secret npm start");
  }
  if (typeof fetch !== "function") {
    console.warn("⚠️   This Node version has no built-in fetch. Use Node 18 or newer.");
  }
});
