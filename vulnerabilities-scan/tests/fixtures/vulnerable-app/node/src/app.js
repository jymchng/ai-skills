// Intentionally vulnerable plain JavaScript for the fixture.
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const app = express();

// permissive-cors: every origin accepted with a bare cors()
app.use(cors());

app.get("/orders", (req, res) => {
  // js-sql-concat (javascript): concatenated statement
  db.query("SELECT * FROM orders WHERE name = '" + req.query.term + "'");
  res.send("ok");
});

app.get("/run", (req, res) => {
  // cmd-js-exec: request data composed into a shell command
  exec("convert " + req.query.file + " /tmp/out.png");
  res.send("ok");
});

app.get("/fetch", async (req, res) => {
  // ssrf: outbound request to a request-supplied URL
  const upstream = await fetch(req.query.url);
  res.send(await upstream.text());
});
