// ============================================================
// AstroPulse Backend — server.js
// Node.js + Express + File-based JSON database
//
// Features
//  • Public service catalog        GET  /api/services
//  • PERMANENT services             fixed-services.json (always loaded, cannot be deleted;
//      admin can still edit price/limits or hide them). Admin-added services are separate.
//  • Admin: SMM API providers      /api/admin/providers   (up to 5; add / edit / delete / test)
//  • Admin: bulk-add services      POST /api/admin/services/bulk
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
  fixedOverrides: path.join(DATA_DIR, "fixed-overrides.json"),   // admin edits of permanent services
  sent:      path.join(DATA_DIR, "provider-orders.json")        // log of orders forwarded to providers
};

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Middleware ───────────────────────────────────────────────
app.use(cors());
app.disable("x-powered-by");
if (process.env.TRUST_PROXY) app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);   // set TRUST_PROXY=1 only if behind Nginx/Cloudflare/host proxy (real IP for rate limits)
// Security headers for every response (CSP limited to rules that cannot break the page)
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(self)",
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",      // keeps Google sign-in popup working
    "Content-Security-Policy": "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'"
  });
  if (req.secure || req.get("x-forwarded-proto") === "https") res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "200kb" }));   // SMM API v2 clients post form data

// Never serve source, data or secret files (providers.json holds API keys)
const BLOCKED = /^\/(data|node_modules|\.git)(\/|$)|^\/(server\.js|package(-lock)?\.json|orders\.json|fixed-services\.json|readme\.md|\.env[^/]*)$|^\/[^/]*(service-?account|firebase-adminsdk)[^/]*\.json$/i;
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

// Providers (max 5 in total)
//  • Optional "env" provider from .env (locked, cannot be edited in the panel):
//      SMM_API_URL=https://provider.example.com/api/v2
//      SMM_API_KEY=your-provider-key
//      SMM_API_NAME=Provider name (optional)
//  • Any others are added from the admin panel and stored in data/providers.json
const MAX_PROVIDERS = 5;
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
const readStoredProviders  = () => readJson(FILES.providers);
const writeStoredProviders = (d) => writeJson(FILES.providers, d);
const readProviders = () => { const p = envProvider(); return [...(p ? [p] : []), ...readStoredProviders()]; };
// Older services saved without a providerId belong to the .env provider
// Admin-added services only (data/services.json)
const readOwnServices = () => {
  const list = readJson(FILES.services);
  return envProvider() ? list.map(s => s.providerId ? s : { ...s, providerId: ENV_PROVIDER_ID }) : list;
};
const writeServices = (d) => writeJson(FILES.services, d);   // always pass ONLY admin-added services

// ── Permanent services (fixed-services.json) ────────────────
// Loaded on every start, never stored in services.json, so they can't be wiped or deleted.
// Admin may edit price / limits / text or hide them; those edits live in data/fixed-overrides.json.
const FIXED_FILE = path.join(__dirname, "fixed-services.json");
const FIXED_EDITABLE = ["platform", "name", "start", "speed", "refill", "drop", "quality", "type", "rate", "min", "max", "active"];
let fixedBase = null;
function loadFixedBase() {
  if (fixedBase) return fixedBase;
  const raw = readJson(FIXED_FILE, []);
  fixedBase = (Array.isArray(raw) ? raw : []).map(r => ({
    id:                Number(r.id),
    platform:          String(r.platform || "").trim().toLowerCase(),
    name:              String(r.name || "").trim(),
    providerName:      String(r.provider || "").trim(),
    providerServiceId: String(r.provider_service_id ?? r.providerServiceId ?? "").trim(),
    start:             String(r.start || ""),
    speed:             String(r.speed || ""),
    refill:            String(r.refill || ""),
    drop:              String(r.drop || ""),
    quality:           String(r.quality || ""),
    type:              String(r.type || "Default") || "Default",
    rate:              Number(r.rate_per_1k ?? r.rate),
    min:               Number(r.min),
    max:               Number(r.max),
    active:            String(r.status || "Active").toLowerCase() === "active"
  })).filter(s => Number.isInteger(s.id) && s.id > 0 && s.platform && s.name && s.providerServiceId && s.rate > 0);
  return fixedBase;
}
const normKey = (v) => String(v || "").toLowerCase().replace(/[^a-z0-9]/g, "");
// Find the panel provider that fulfils the permanent services (by name, then by API URL,
// then the only provider if there is just one). Re-adding the provider restores it automatically.
function resolveFixedProviderId(name, providers) {
  const n = normKey(name);
  const p = providers.find(x => normKey(x.name) === n)
         || (n && providers.find(x => normKey(x.url).includes(n)))
         || (providers.length === 1 ? providers[0] : null);
  return p ? p.id : "";
}
function readFixedServices() {
  const providers = readProviders();
  const ov = readJson(FILES.fixedOverrides, {});
  return loadFixedBase().map(b => {
    const { providerName, ...rest } = b;
    return { ...rest, ...(ov[b.id] || {}), providerId: resolveFixedProviderId(providerName, providers), fixed: true };
  });
}
// Everything the panel sells: permanent services + admin-added services
const readServices = () => {
  const fixed = readFixedServices();
  const ids = new Set(fixed.map(s => Number(s.id)));
  const keys = new Set(fixed.map(s => s.providerId + "|" + s.providerServiceId));
  return [...fixed, ...readOwnServices().filter(s => !ids.has(Number(s.id)) && !keys.has(s.providerId + "|" + s.providerServiceId))];
};
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
    locked: p.id === ENV_PROVIDER_ID,
    source: p.id === ENV_PROVIDER_ID ? "env" : "panel",
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
  const list = readProviders();
  if (!list.length) throw new HttpError(503, "No SMM API provider is configured. Add one in the admin panel.");
  const provider = list.find(p => p.id === String(id || ""));
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
function normalizeService(body, existing, opts = {}) {
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
  if (!svc.providerId && !opts.fixed) throw new HttpError(400, "Select an API provider");
  if (!svc.providerServiceId && !opts.fixed) throw new HttpError(400, "Provider service ID is required");
  if (!(svc.rate > 0))        throw new HttpError(400, "Rate per 1K must be greater than 0");
  if (!Number.isInteger(svc.min) || svc.min < 1) throw new HttpError(400, "Minimum must be a whole number of at least 1");
  if (!Number.isInteger(svc.max) || svc.max < svc.min) throw new HttpError(400, "Maximum must be a whole number not lower than minimum");
  if (svc.id !== null && (!Number.isInteger(svc.id) || svc.id < 1)) throw new HttpError(400, "Service ID must be a positive whole number");

  if (!opts.fixed && !readProviders().some(p => p.id === svc.providerId)) throw new HttpError(400, "Selected API provider does not exist");
  return svc;
}

function publicService(s) {
  // Customers never see which provider fulfils a service
  const { providerId, providerServiceId, fixed, ...rest } = s;
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

const lockedProvider = () => {
  throw new HttpError(403, "This provider comes from the server .env file and cannot be changed from the panel.");
};

// Add a provider (max 5 in total)
admin.post("/providers", (req, res) => {
  const all = readProviders();
  if (all.length >= MAX_PROVIDERS) throw new HttpError(400, `You can add at most ${MAX_PROVIDERS} API providers.`);

  const name = String(req.body.name || "").trim();
  const key  = String(req.body.key || "").trim();
  const url  = cleanUrl(req.body.url);
  if (!name) throw new HttpError(400, "Provider name is required");
  if (!key)  throw new HttpError(400, "API key is required");
  if (all.some(p => p.name.toLowerCase() === name.toLowerCase())) throw new HttpError(409, "A provider with this name already exists");
  if (all.some(p => p.url === url && p.key === key)) throw new HttpError(409, "This API URL and key were already added");

  const provider = {
    id: "prov_" + crypto.randomBytes(4).toString("hex"),
    name, url, key, active: true,
    createdAt: new Date().toISOString()
  };
  const stored = readStoredProviders();
  stored.push(provider);
  writeStoredProviders(stored);
  res.status(201).json({ success: true, provider: publicProvider(provider, readServices()) });
});

// Edit a provider (leave key blank to keep the current one)
admin.put("/providers/:id", (req, res) => {
  if (req.params.id === ENV_PROVIDER_ID) return lockedProvider();
  const stored = readStoredProviders();
  const idx = stored.findIndex(p => p.id === req.params.id);
  if (idx === -1) throw new HttpError(404, "API provider not found");

  const cur = stored[idx];
  const name = req.body.name === undefined ? cur.name : String(req.body.name).trim();
  const url  = req.body.url  === undefined ? cur.url  : cleanUrl(req.body.url);
  const key  = req.body.key ? String(req.body.key).trim() : cur.key;
  if (!name) throw new HttpError(400, "Provider name is required");
  if (readProviders().some(p => p.id !== cur.id && p.name.toLowerCase() === name.toLowerCase())) {
    throw new HttpError(409, "A provider with this name already exists");
  }
  stored[idx] = {
    ...cur, name, url, key,
    active: req.body.active === undefined ? cur.active !== false : !!req.body.active,
    updatedAt: new Date().toISOString()
  };
  writeStoredProviders(stored);
  svcCache.delete(cur.id);
  res.json({ success: true, provider: publicProvider(stored[idx], readServices()) });
});

// Delete a provider. If services use it, ?removeServices=true deletes those services too.
admin.delete("/providers/:id", (req, res) => {
  if (req.params.id === ENV_PROVIDER_ID) return lockedProvider();
  const stored = readStoredProviders();
  if (!stored.some(p => p.id === req.params.id)) throw new HttpError(404, "API provider not found");

  const own = readOwnServices();   // permanent services are never deleted; they re-link by provider name
  const used = own.filter(s => s.providerId === req.params.id);
  if (used.length && req.query.removeServices !== "true") {
    throw new HttpError(409, `${used.length} service(s) use this provider. Remove them first or confirm deleting them too.`);
  }
  if (used.length) writeServices(own.filter(s => s.providerId !== req.params.id));
  writeStoredProviders(stored.filter(p => p.id !== req.params.id));
  svcCache.delete(req.params.id);
  res.json({ success: true, removedServices: used.length });
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
  if (services.some(s => s.providerId === svc.providerId && String(s.providerServiceId) === String(svc.providerServiceId) && s.fixed)) {
    throw new HttpError(409, "This provider service is already part of the permanent services");
  }
  const own = readOwnServices();
  own.push(svc);
  writeServices(own);
  res.status(201).json({ success: true, service: svc });
});

// POST /api/admin/services/bulk — add many provider services at once.
// body: { items: [{ providerId, providerServiceId, platform, name, rate, min, max, ... }] }
// Services already added (same provider + provider service ID) are skipped.
admin.post("/services/bulk", (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  if (!items.length) throw new HttpError(400, "No services selected");
  if (items.length > 500) throw new HttpError(400, "Add at most 500 services at a time");

  const services = readServices();   // permanent + added (used for ID and duplicate checks)
  const own = readOwnServices();
  let nextId = services.reduce((m, s) => Math.max(m, Number(s.id) || 0), 1000) + 1;
  const added = [], skipped = [], errors = [];

  for (const item of items) {
    const label = `${item && item.providerServiceId}`;
    try {
      const dupe = services.some(s => s.providerId === String(item.providerId) &&
                                      String(s.providerServiceId) === String(item.providerServiceId));
      if (dupe) { skipped.push(label); continue; }
      const svc = normalizeService({ ...item, id: undefined }, null);
      svc.id = nextId++;
      svc.createdAt = new Date().toISOString();
      services.push(svc);
      own.push(svc);
      added.push(svc.id);
    } catch (err) {
      errors.push({ providerServiceId: label, error: err.message });
    }
  }
  if (added.length) writeServices(own);
  res.status(added.length ? 201 : 200).json({ success: true, added: added.length, skipped: skipped.length, errors });
});

admin.put("/services/:id", (req, res) => {
  const services = readServices();
  const idx = services.findIndex(s => String(s.id) === String(req.params.id));
  if (idx === -1) throw new HttpError(404, "Service not found");

  const cur = services[idx];
  if (cur.fixed) {
    // Permanent service: provider link is locked; only price / limits / text / visibility can change
    const upd = normalizeService({ ...req.body, providerId: cur.providerId, providerServiceId: cur.providerServiceId }, cur, { fixed: true });
    const ov = readJson(FILES.fixedOverrides, {});
    ov[cur.id] = Object.fromEntries(FIXED_EDITABLE.map(k => [k, upd[k]]));
    writeJson(FILES.fixedOverrides, ov);
    return res.json({ success: true, service: readServices().find(s => Number(s.id) === Number(cur.id)) });
  }

  const own = readOwnServices();
  const oi = own.findIndex(s => String(s.id) === String(req.params.id));
  const updated = normalizeService(req.body, services[idx]);
  updated.createdAt = services[idx].createdAt;
  updated.updatedAt = new Date().toISOString();
  own[oi] = updated;
  writeServices(own);
  res.json({ success: true, service: updated });
});

// DELETE /api/admin/services — remove ALL services at once.
// Platforms (Instagram, Facebook, ...) are not stored on the server, so they are not affected.
admin.delete("/services", (req, res) => {
  const count = readOwnServices().length;   // permanent services are never removed
  writeServices([]);
  console.log(`[SERVICES] All services removed (${count}) by ${req.adminEmail || "admin key"}`);
  res.json({ success: true, removed: count });
});

// DELETE /api/admin/services/:id — remove one service
admin.delete("/services/:id", (req, res) => {
  const fixed = readFixedServices().find(s => String(s.id) === String(req.params.id));
  if (fixed) {
    if (req.query.reset === "true") {   // restore the original price / limits of a permanent service
      const ov = readJson(FILES.fixedOverrides, {});
      delete ov[fixed.id];
      writeJson(FILES.fixedOverrides, ov);
      return res.json({ success: true, reset: true });
    }
    throw new HttpError(403, "This is a permanent service and cannot be removed. Edit it and set Status to Hidden to hide it from the store.");
  }
  const own = readOwnServices();
  const next = own.filter(s => String(s.id) !== String(req.params.id));
  if (next.length === own.length) throw new HttpError(404, "Service not found");
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
// RESELLER API — other SMM panels connect with a personal API key
//
//   Key management (signed-in customer, Firebase Bearer token)
//     GET    /api/user/api-key     -> { exists, hint, createdAt, lastUsedAt }   (key itself is never returned)
//     POST   /api/user/api-key     -> creates / replaces the key; plaintext shown ONCE in this response
//     DELETE /api/user/api-key     -> revokes the key
//
//   Standard SMM panel API v2   POST /api/v2   (key, action = services | balance | add | status)
//     add     : price is taken from the caller's wallet. Enough funds -> sent straight to the provider.
//               Not enough funds, or provider rejects -> order FAILS and nothing is charged.
//     status  : a key can only ever see its own orders.
//
//   Security: keys are random 192-bit values stored only as SHA-256 hashes; every wallet change is a
//   Firestore transaction with a fixed ledger ID (no double charge / double refund); rate limits per
//   IP and per key; the provider (name, URL, key, service IDs, errors) is never exposed to callers.
//   Needs:  npm i firebase-admin   +   FIREBASE_SERVICE_ACCOUNT_FILE=./firebase-service-account.json  (.env)
// ============================================================
const PROXY_SECRET = String(process.env.PROXY_SECRET || "").trim();
let fsdb = null, FV = null;
function firestore() {
  if (fsdb) return fsdb;
  let cred = null;
  try {
    const raw  = String(process.env.FIREBASE_SERVICE_ACCOUNT || "").trim();
    const file = String(process.env.FIREBASE_SERVICE_ACCOUNT_FILE || "").trim();
    cred = raw ? JSON.parse(raw) : (file ? JSON.parse(fs.readFileSync(path.resolve(__dirname, file), "utf8")) : null);
  } catch { cred = null; }
  if (!cred) throw new HttpError(503, "The reseller API is not configured on the server yet.");
  let admin;
  try { admin = require("firebase-admin"); }
  catch { throw new HttpError(503, "The reseller API needs the firebase-admin package on the server."); }
  if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(cred) });
  fsdb = admin.firestore(); FV = admin.firestore.FieldValue;
  return fsdb;
}

// tiny in-memory rate limiter
const buckets = new Map();
function hit(name, limit, windowMs) {
  const now = Date.now();
  let b = buckets.get(name);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(name, b); }
  if (buckets.size > 5000) for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
  return ++b.n <= limit;
}
const noStore = (req, res, next) => { res.set("Cache-Control", "no-store"); next(); };
const hashKey = (k) => crypto.createHash("sha256").update(String(k)).digest("hex");
const rupees  = (paise) => (paise / 100).toFixed(2);
function priceInPaise(qty, ratePer1k) {           // same rule as wallet.js
  const ratePaise = Math.round(Number(ratePer1k) * 100);
  if (!Number.isInteger(qty) || qty <= 0 || !(ratePaise > 0)) return NaN;
  return Math.max(1, Math.round((qty * ratePaise) / 1000));
}

// ── Signed-in customer (Firebase ID token) ──────────────────
const userTokenCache = new Map();
async function verifyFirebaseUser(token) {
  const hitC = userTokenCache.get(token);
  if (hitC && hitC.exp > Date.now()) return hitC.user;
  if (!FIREBASE_API_KEY) throw new HttpError(503, "FIREBASE_API_KEY is not set in the server .env file.");
  let r;
  try {
    r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(FIREBASE_API_KEY),
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken: token }) });
  } catch { throw new HttpError(502, "Could not verify your login. Try again."); }
  if (!r.ok) return null;
  const u = ((await r.json()).users || [])[0];
  if (!u || !u.localId || u.disabled) return null;
  const user = { uid: u.localId, email: String(u.email || ""), name: u.displayName || (u.email ? String(u.email).split("@")[0] : "User") };
  if (userTokenCache.size > 500) userTokenCache.clear();
  userTokenCache.set(token, { user, exp: Date.now() + 60 * 1000 });
  return user;
}
async function requireUser(req, res, next) {
  try {
    const token = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    const user = token ? await verifyFirebaseUser(token) : null;
    if (!user) return res.status(401).json({ error: "Please sign in again." });
    req.user = user; next();
  } catch (err) { next(err); }
}

const userApi = express.Router();
userApi.use(noStore, requireUser);

userApi.get("/api-key", wrap(async (req, res) => {
  const snap = await firestore().collection("apiUsers").doc(req.user.uid).get();
  if (!snap.exists) return res.json({ exists: false });
  const d = snap.data();
  const ts = (t) => (t && t.toDate ? t.toDate().toISOString() : null);
  res.json({ exists: true, hint: d.last4 || "", createdAt: ts(d.createdAt), lastUsedAt: ts(d.lastUsedAt) });
}));

userApi.post("/api-key", wrap(async (req, res) => {
  if (!hit("keygen:" + req.user.uid, 5, 60 * 60 * 1000)) throw new HttpError(429, "Too many key changes. Try again in an hour.");
  const db = firestore();
  const key = "ap_" + crypto.randomBytes(24).toString("hex");
  const hash = hashKey(key);
  const userRef = db.collection("apiUsers").doc(req.user.uid);
  await db.runTransaction(async (t) => {
    const old = await t.get(userRef);
    if (old.exists && old.data().keyHash) t.delete(db.collection("apiKeys").doc(old.data().keyHash));   // old key stops working
    t.set(db.collection("apiKeys").doc(hash), { uid: req.user.uid, createdAt: FV.serverTimestamp() });
    t.set(userRef, { keyHash: hash, last4: key.slice(-4), email: req.user.email, createdAt: FV.serverTimestamp(), lastUsedAt: null });
  });
  console.log(`[RESELLER] API key created for ${req.user.email}`);
  res.status(201).json({ key, hint: key.slice(-4) });     // the ONLY time the plaintext key exists outside the customer's copy
}));

userApi.delete("/api-key", wrap(async (req, res) => {
  const db = firestore();
  const userRef = db.collection("apiUsers").doc(req.user.uid);
  await db.runTransaction(async (t) => {
    const s = await t.get(userRef);
    if (s.exists) { if (s.data().keyHash) t.delete(db.collection("apiKeys").doc(s.data().keyHash)); t.delete(userRef); }
  });
  res.json({ success: true });
}));
app.use("/api/user", userApi);

// ── Wallet helpers (same ledger shape as wallet.js) ─────────
async function refundOrder(orderId, refundPaise, patch, note) {
  const db = firestore();
  const orderRef = db.collection("orders").doc(orderId);
  const txRef = db.collection("walletTx").doc("R" + orderId);     // fixed ID: can only ever refund once
  return db.runTransaction(async (t) => {
    const os = await t.get(orderRef);
    if (!os.exists) return false;
    const o = os.data();
    if (o.refunded) return false;
    const userRef = db.collection("users").doc(o.userId);
    const us = await t.get(userRef);
    const bal = us.exists ? Number(us.data().balance) || 0 : 0;
    const after = bal + refundPaise;
    t.set(userRef, { balance: after, updatedAt: FV.serverTimestamp() }, { merge: true });
    t.set(txRef, { userId: o.userId, userEmail: o.userEmail || "", type: "refund", amount: refundPaise, balanceAfter: after,
      orderDocId: orderId, orderId, approvedBy: "system", note, createdAt: FV.serverTimestamp() });
    t.update(orderRef, { ...patch, refunded: true, refundTx: txRef.id, refundPaise, updatedAt: FV.serverTimestamp() });
    return true;
  });
}

async function apiAddOrder(user, b) {
  const service = readServices().find(s => String(s.id) === String(b.service) && s.active !== false);
  if (!service) return { error: "Incorrect service ID" };
  const link = String(b.link || "").trim();
  if (!link || link.length > 500 || /[\u0000-\u001f]/.test(link)) return { error: "Incorrect link" };

  const comments = typeof b.comments === "string" ? b.comments.replace(/\r/g, "").trim() : "";
  const quantity = comments ? comments.split("\n").filter(l => l.trim()).length : Number(b.quantity);
  if (!Number.isInteger(quantity) || quantity < service.min || quantity > service.max) {
    return { error: `Quantity must be between ${service.min} and ${service.max}` };
  }
  if (comments.length > 20000) return { error: "Comments are too long" };
  const provider = readProviders().find(p => p.id === service.providerId);
  if (!provider || provider.active === false) return { error: "Service is temporarily unavailable" };
  const amount = priceInPaise(quantity, service.rate);
  if (!Number.isSafeInteger(amount)) return { error: "Could not price this order" };

  const db = firestore();
  const orderId = "ASTR" + crypto.randomInt(10000000, 100000000);
  const userRef = db.collection("users").doc(user.uid);
  const orderRef = db.collection("orders").doc(orderId);
  const txRef = db.collection("walletTx").doc("D" + orderId);

  try {
    await db.runTransaction(async (t) => {
      const [os, us] = await Promise.all([t.get(orderRef), t.get(userRef)]);
      if (os.exists) throw new HttpError(409, "Please try again");
      const bal = us.exists ? Number(us.data().balance) || 0 : 0;
      if (bal < amount) throw Object.assign(new HttpError(402, "Not enough funds"), { funds: true });
      const after = bal - amount;
      t.update(userRef, { balance: after, lastTx: txRef.id, updatedAt: FV.serverTimestamp() });
      t.set(txRef, { userId: user.uid, userEmail: user.email, type: "debit", amount, balanceAfter: after,
        orderDocId: orderId, orderId, note: "API order " + orderId, createdAt: FV.serverTimestamp() });
      t.set(orderRef, { orderId, userId: user.uid, userEmail: user.email, userName: user.name,
        platform: service.platform ? service.platform[0].toUpperCase() + service.platform.slice(1) : "",
        service: service.name, serviceId: service.id, refill: service.refill || "", quantity, link,
        commentType: comments ? "Custom comments" : "", source: "api", status: "pending", paymentMethod: "wallet",
        amountPaise: amount, amountPaid: "₹" + (amount / 100).toLocaleString("en-IN", { minimumFractionDigits: 2 }),
        walletTx: txRef.id, createdAt: FV.serverTimestamp(), updatedAt: FV.serverTimestamp() });
    });
  } catch (err) {
    if (err.funds) return { error: "Not enough funds. Add funds to your Astropulse wallet." };
    throw err;
  }

  // Wallet charged → send straight to the provider
  try {
    const params = { action: "add", service: service.providerServiceId, link };
    if (comments) params.comments = comments; else params.quantity = quantity;
    const data = await providerCall(provider, params);
    if (!data || data.order === undefined || data.order === null) throw new HttpError(502, "Provider did not return an order ID");
    await orderRef.update({ providerOrderId: String(data.order), providerId: provider.id,
      providerServiceId: service.providerServiceId, providerSentAt: FV.serverTimestamp() });
    const sent = readSent();
    sent.push({ reference: orderId, serviceId: service.id, providerId: provider.id, providerServiceId: service.providerServiceId,
      providerOrderId: data.order, link, quantity, sentAt: new Date().toISOString(), source: "api" });
    writeSent(sent);
    console.log(`[RESELLER] ${orderId} ${user.email} → ${provider.name} #${data.order}`);
    return { order: orderId };
  } catch (err) {
    console.error(`[RESELLER] ${orderId} provider error:`, err.message);
    if (/timed out|invalid response/i.test(err.message)) {
      // The provider may have accepted it: keep the charge, flag for the admin instead of risking a double spend
      await orderRef.update({ needsReview: true, providerSync: "unknown", updatedAt: FV.serverTimestamp() });
      return { order: orderId };
    }
    await refundOrder(orderId, amount, { status: "declined", failed: true, failReason: "provider" }, "Refund: order failed " + orderId);
    return { error: "Order failed. You have not been charged." };
  }
}

const statusCache = new Map();
async function apiOrderStatus(uid, orderId) {
  const id = String(orderId || "").trim();
  if (!/^[A-Za-z0-9_-]{4,40}$/.test(id)) return { error: "Incorrect order ID" };
  const ref = firestore().collection("orders").doc(id);
  const snap = await ref.get();
  if (!snap.exists || snap.data().userId !== uid) return { error: "Incorrect order ID" };   // never reveal other users' orders
  let o = snap.data();
  const out = (status, start, remains) => ({ charge: rupees(Math.max(0, (o.amountPaise || 0) - (o.refundPaise || 0))),
    start_count: String(start || 0), status, remains: String(remains), currency: "INR" });

  if (o.status === "declined") return out("Canceled", 0, o.quantity || 0);
  if (!o.providerOrderId || !o.providerId) return out("Pending", 0, o.quantity || 0);

  let d = statusCache.get(id);
  if (!d || d.at < Date.now() - 15000) {
    try { d = { at: Date.now(), data: await providerCall(findProvider(o.providerId), { action: "status", order: o.providerOrderId }) }; statusCache.set(id, d); }
    catch { return out(o.status === "completed" ? "Completed" : "In progress", 0, o.status === "completed" ? 0 : o.quantity || 0); }
    if (statusCache.size > 2000) statusCache.clear();
  }
  const st = String((d.data && d.data.status) || "Pending").slice(0, 30);
  const start = Number(d.data && d.data.start_count) || 0;
  let remains = Math.max(0, Math.min(o.quantity || 0, Math.round(Number(d.data && d.data.remains) || 0)));

  if (/cancel/i.test(st) && !o.refunded) {
    await refundOrder(id, o.amountPaise, { status: "declined", failReason: "canceled" }, "Refund: order canceled " + id);
    o = { ...o, refundPaise: o.amountPaise, status: "declined" };
  } else if (/partial/i.test(st) && !o.refunded) {
    const back = o.quantity ? Math.floor(o.amountPaise * remains / o.quantity) : 0;
    if (back > 0) await refundOrder(id, back, { status: "completed", partial: true }, "Partial refund " + id);
    else await ref.update({ status: "completed", partial: true });
    o = { ...o, refundPaise: back };
  } else if (/complete/i.test(st) && o.status !== "completed") {
    await ref.update({ status: "completed", updatedAt: FV.serverTimestamp() });
  }
  if (/complete/i.test(st)) remains = 0;
  return out(st, start, remains);
}

// ── POST /api/v2 — the endpoint other panels call ───────────
const apiLastUsed = new Map();
app.all("/api/v2", noStore, async (req, res) => {
  const send = (obj, status = 200) => res.status(status).json(obj);
  try {
    if (req.method === "GET") {
      return send({ name: "Astropulse API", version: "v2", status: "online", method: "POST",
        actions: ["services", "balance", "add", "status"],
        usage: "Send key and action in the POST body. Create your key from Menu → API on the website." });
    }
    if (req.method !== "POST") return send({ error: "Send a POST request with key and action." });
    // Real caller IP: trusted from the Vercel proxy only when it proves itself with PROXY_SECRET
    const proxied = PROXY_SECRET && req.get("x-astro-proxy") && crypto.timingSafeEqual(sha(req.get("x-astro-proxy")), sha(PROXY_SECRET));
    const ip = (proxied && String(req.get("x-astro-client-ip") || "").slice(0, 64)) || req.ip || "";
    if (!hit("ip:" + ip, 120, 60 * 1000)) return send({ error: "Too many requests. Slow down." }, 429);
    const b = req.body && typeof req.body === "object" ? req.body : {};
    const key = String(b.key || "").trim();
    if (!hit("bad:" + ip, 25, 10 * 60 * 1000)) return send({ error: "Too many invalid attempts. Try again later." }, 429);

    const db = firestore();
    const ks = /^ap_[0-9a-f]{48}$/.test(key) ? await db.collection("apiKeys").doc(hashKey(key)).get() : null;
    if (!ks || !ks.exists) return send({ error: "Invalid API key" });
    buckets.get("bad:" + ip).n--;                                   // only failed attempts count
    const uid = ks.data().uid;
    if (!hit("key:" + uid, 60, 60 * 1000)) return send({ error: "Rate limit reached (60 requests per minute)." }, 429);
    if ((apiLastUsed.get(uid) || 0) < Date.now() - 60000) {
      apiLastUsed.set(uid, Date.now());
      db.collection("apiUsers").doc(uid).update({ lastUsedAt: FV.serverTimestamp() }).catch(() => {});
    }

    const action = String(b.action || "").toLowerCase();
    if (action === "services") {
      const providers = readProviders();
      return send(readServices()
        .filter(s => s.active !== false && providers.some(p => p.id === s.providerId && p.active !== false))
        .map(s => ({ service: s.id, name: s.name, type: s.type || "Default",
          category: s.platform ? s.platform[0].toUpperCase() + s.platform.slice(1) : "Other",
          rate: Number(s.rate).toFixed(2), min: String(s.min), max: String(s.max), refill: false, cancel: false })));
    }
    const us = await db.collection("users").doc(uid).get();
    const email = us.exists ? String(us.data().email || "") : "";
    if (action === "balance") return send({ balance: rupees(us.exists ? Number(us.data().balance) || 0 : 0), currency: "INR" });
    if (action === "add") {
      if (!hit("add:" + uid, 30, 60 * 1000)) return send({ error: "Too many orders per minute." }, 429);
      return send(await apiAddOrder({ uid, email, name: email ? email.split("@")[0] : "API user" }, b));
    }
    if (action === "status") {
      if (b.orders !== undefined) {
        const ids = String(b.orders).split(",").map(x => x.trim()).filter(Boolean).slice(0, 100);
        if (!ids.length) return send({ error: "Incorrect order ID" });
        const result = {};
        for (const id of ids) result[id] = await apiOrderStatus(uid, id);
        return send(result);
      }
      return send(await apiOrderStatus(uid, b.order));
    }
    return send({ error: "Incorrect action" });
  } catch (err) {
    if (err instanceof HttpError) return send({ error: err.message }, err.status === 429 ? 429 : 200);
    console.error("[RESELLER] error:", err.message);
    return send({ error: "Server error. Please try again." });
  }
});

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
    version: "multi-provider-bulk-add+reseller-api",
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
console.log(`[SERVICES] ${loadFixedBase().length} permanent services loaded from fixed-services.json`);
app.listen(PORT, () => {
  console.log(`✅  AstroPulse server running at http://localhost:${PORT}`);
  if (!FIREBASE_READY && !ADMIN_KEY) {
    console.warn("⚠️   Admin API disabled. Set FIREBASE_API_KEY and ADMIN_EMAILS in .env");
  }
  const ep = envProvider();
  if (!ep) {
    console.log(`ℹ️   ${readStoredProviders().length} provider(s) added from the admin panel (max ${MAX_PROVIDERS}).`);
  } else {
    try { new URL(ep.url); console.log(`🔗  SMM API: ${ep.name} (${ep.url})`); }
    catch { console.warn("⚠️   SMM_API_URL in .env is not a valid URL"); }
  }
  if (typeof fetch !== "function") {
    console.warn("⚠️   This Node version has no built-in fetch. Use Node 18 or newer.");
  }
});
