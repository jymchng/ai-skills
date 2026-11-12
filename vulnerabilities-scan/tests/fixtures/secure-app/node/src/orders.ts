// Secure look-alike of node/src/orders.ts.
import { execFile } from "child_process";
import * as fs from "fs";
import * as jwt from "jsonwebtoken";
import * as path from "path";

const allowedOrigins = ["https://app.example.com"];
const ALLOWED_HOSTS = new Set(["api.partner.example"]);

function validateUrl(candidate: string): string | null {
  try {
    return ALLOWED_HOSTS.has(new URL(candidate).host) ? candidate : null;
  } catch {
    return null;
  }
}

const corsOptions = { origin: allowedOrigins };

export async function listOrders(req: any, res: any) {
  // Bound parameter, not string interpolation.
  const rows = db.query("SELECT * FROM orders WHERE name = $1", [req.query.term]);
  res.json(rows);
}

export async function showOrder(req: any, res: any) {
  // The tenant is part of the query, so the id alone cannot escape it.
  const order = Order.findOne({ id: req.params.id, ownerId: req.user.tenantId });
  res.json(order);
}

export async function convert(req: any, res: any) {
  // Argument vector via execFile, no shell.
  execFile("convert", [req.query.file, "/tmp/out.png"]);
  res.end("ok");
}

export async function download(req: any, res: any) {
  // Resolved and confined to the data root before the read.
  const base = path.resolve("/srv/data");
  const target = path.resolve(base, req.query.name);
  if (!target.startsWith(base)) {
    return res.status(400).end("invalid");
  }
  fs.readFileSync(target);
  res.end("ok");
}

export async function preview(req: any, res: any) {
  // Only allow-listed hosts are reached.
  const target = validateUrl(req.query.url);
  if (!target) {
    return res.status(400).end("blocked");
  }
  const body = await fetch(target);
  res.end(await body.text());
}

export async function greeting(req: any, res: any) {
  // Escaped before it reaches the response.
  res.send(escapeHtml(req.query.name));
}

export function paint() {
  // textContent cannot execute markup.
  document.getElementById("out").textContent = location.hash;
}

export function session(token: string) {
  // Signature verified with an explicit algorithm allow-list.
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
}

export function hashPassword(password: string) {
  // Adaptive hash.
  return bcrypt.hash(password, 12);
}

export async function checkout(req: any, res: any) {
  // The amount is recomputed server-side from the stored cart.
  const total = calculateTotal(req.body.cartId);
  res.json({ total });
}

export async function promote(req: any, res: any) {
  // The role is read from the caller's stored record.
  if (!req.user.isAdmin) {
    return res.status(403).end("forbidden");
  }
  res.json({ role: req.user.role });
}
