// ============================================================
// AstroPulse Backend — server.js
// Node.js + Express + File-based JSON database
// ============================================================

const express = require("express");
const cors    = require("cors");
const fs      = require("fs");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;
const DB   = path.join(__dirname, "orders.json");

// ── Middleware ───────────────────────────────────────────────
app.use(cors());                          // allow all origins
app.use(express.json());                  // parse JSON bodies
app.use(express.static(__dirname));       // serve HTML files

// ── Helpers ─────────────────────────────────────────────────

/** Read orders array from disk */
function readOrders() {
  if (!fs.existsSync(DB)) fs.writeFileSync(DB, "[]", "utf8");
  try {
    return JSON.parse(fs.readFileSync(DB, "utf8"));
  } catch {
    return [];
  }
}

/** Write orders array to disk */
function writeOrders(orders) {
  fs.writeFileSync(DB, JSON.stringify(orders, null, 2), "utf8");
}

/** Generate unique order ID like AP-7F3A2C */
function genId() {
  return "AP-" + Math.random().toString(36).toUpperCase().slice(2, 8);
}

/** IST timestamp string */
function nowIST() {
  return new Date().toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: true
  });
}

// ── Routes ───────────────────────────────────────────────────

// GET /api/orders — return all orders, newest first
app.get("/api/orders", (req, res) => {
  try {
    const orders = readOrders().reverse();   // newest first
    console.log(`[GET] /api/orders — ${orders.length} orders`);
    res.json(orders);
  } catch (err) {
    console.error("[GET] Error:", err.message);
    res.status(500).json({ error: "Failed to read orders" });
  }
});

// POST /api/orders — create a new order
app.post("/api/orders", (req, res) => {
  try {
    const { platform, service, link, quantity, price, transactionId, coupon, device, browser, os, ip } = req.body;

    // Basic validation
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

// PATCH /api/orders/:id — update order status
app.patch("/api/orders/:id", (req, res) => {
  try {
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
  } catch (err) {
    console.error("[PATCH] Error:", err.message);
    res.status(500).json({ error: "Failed to update order" });
  }
});

// Also support PUT for compatibility
app.put("/api/orders/:id", (req, res) => {
  req.method = "PATCH";
  app.handle(req, res);
});

// DELETE /api/orders/:id — permanently delete an order
app.delete("/api/orders/:id", (req, res) => {
  try {
    const { id } = req.params;
    let orders   = readOrders();
    const before = orders.length;
    orders       = orders.filter(o => o._id !== id);

    if (orders.length === before) return res.status(404).json({ error: "Order not found" });

    writeOrders(orders);
    console.log(`[DELETE] Order ${id} removed`);
    res.json({ success: true });
  } catch (err) {
    console.error("[DELETE] Error:", err.message);
    res.status(500).json({ error: "Failed to delete order" });
  }
});

// ── Health check ─────────────────────────────────────────────
app.get("/", (req, res) => {
  res.send(`
    <h2>🚀 AstroPulse API is running</h2>
    <p>Endpoints:</p>
    <ul>
      <li>GET    /api/orders</li>
      <li>POST   /api/orders</li>
      <li>PATCH  /api/orders/:id</li>
      <li>DELETE /api/orders/:id</li>
    </ul>
  `);
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  AstroPulse server running at http://localhost:${PORT}`);
  // Make sure orders.json exists
  if (!fs.existsSync(DB)) {
    fs.writeFileSync(DB, "[]", "utf8");
    console.log("📁  orders.json created.");
  }
});
