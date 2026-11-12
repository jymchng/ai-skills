// Secure look-alike of node/src/app.js.
const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const helmet = require("helmet");

const app = express();

// An explicit origin allow-list, credentials limited to those origins.
const allowedOrigins = ["https://app.example.com"];
app.use(cors({ origin: allowedOrigins }));
app.use(helmet());

app.get("/orders", requireAuth, (req, res) => {
  // Bound parameters.
  db.query("SELECT * FROM orders WHERE name = $1", [req.query.term]);
  res.send("ok");
});

app.get("/run", requireAuth, (req, res) => {
  // No shell, fixed argv shape.
  execFile("convert", [req.query.file, "/tmp/out.png"]);
  res.send("ok");
});
