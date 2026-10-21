import { Hono } from "hono";
import { authRoutes } from "./auth.routes.js";
import { fileRoutes } from "./file.routes.js";
import type { AppEnv } from "../types/index.js";

export const routes = new Hono<AppEnv>()
  .get("/health", (c) => c.json({ ok: true }))
  .route("/auth", authRoutes)
  .route("/files", fileRoutes);
