import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { seed } from "./db.js";
import { vulnerable } from "./routes/vulnerable.js";
import { safe } from "./routes/safe.js";

seed();

const app = new Hono();
app.use("*", cors({ origin: "http://localhost:3000" })); // for the Next.js playground

app.get("/", (c) =>
  c.json({
    name: "SQL Injection teaching lab",
    warning: "Intentionally vulnerable under /vuln. Run locally only.",
    endpoints: {
      vulnerable: ["POST /vuln/login", "GET /vuln/products?q=", "GET /vuln/user?id="],
      safe: ["POST /safe/login", "GET /safe/products?q=", "GET /safe/user?id="],
    },
  }),
);

app.route("/vuln", vulnerable);
app.route("/safe", safe);

const port = Number(process.env.PORT ?? 8080);
serve({ fetch: app.fetch, port }, (i) =>
  console.log(`SQLi lab on http://localhost:${i.port}  (vulnerable routes under /vuln)`),
);
