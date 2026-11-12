// Intentionally vulnerable TypeScript handlers for the fixture.
import { exec } from "child_process";
import * as fs from "fs";
import * as jwt from "jsonwebtoken";

export async function listOrders(req: any, res: any) {
  // js-sql-concat (typescript): template literal inside the query
  const rows = db.query(`SELECT * FROM orders WHERE name = '${req.query.term}'`);
  res.json(rows);
}

export async function showOrder(req: any, res: any) {
  // idor: record looked up by a client-supplied id
  const order = Order.findById(req.params.id);
  res.json(order);
}

export async function convert(req: any, res: any) {
  // cmd-js-exec: request data composed into a shell command
  exec(`convert ${req.query.file} /tmp/out.png`);
  res.end("ok");
}

export async function download(req: any, res: any) {
  // path-traversal: request data used to build the path
  fs.readFileSync("/srv/data/" + req.query.name);
  res.end("ok");
}

export async function preview(req: any, res: any) {
  // ssrf: outbound request to a request-supplied URL
  const body = await fetch(req.query.url);
  res.end(await body.text());
}

export async function greeting(req: any, res: any) {
  // xss-response-request: request data written into the response body
  res.send(req.query.name);
}

export function paint() {
  // xss-innerhtml: DOM sink assigned from the URL
  document.getElementById("out").innerHTML = location.hash;
}

export function session(token: string) {
  // weak-jwt-validation: decoded without verifying the signature
  return jwt.decode(token);
}

export function hashPassword(password: string) {
  // weak-password-hashing: fast hash for a password
  const digest = createHash("md5").update(password).digest("hex");
  return digest;
}

export async function checkout(req: any, res: any) {
  // business-logic: the payable amount is chosen by the client
  const total = req.body.total;
  res.json({ total });
}

export async function promote(req: any, res: any) {
  // missing-authorization: role taken from the request
  const role = req.body.role;
  res.json({ role });
}
