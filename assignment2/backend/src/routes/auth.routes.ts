import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { authController } from "../controllers/auth.controller.js";
import { AppError } from "../lib/errors.js";
import { requireAuth } from "../middleware/auth.js";
import { rateLimit } from "../middleware/rate-limit.js";
import { loginSchema } from "../validation/auth.validation.js";
import type { AppEnv } from "../types/index.js";

export const authRoutes = new Hono<AppEnv>()
  .post(
    "/login",
    rateLimit({ name: "login attempts", limit: 10, windowMs: 15 * 60_000 }), // brute-force guard
    zValidator("json", loginSchema, (r) => {
      if (!r.success) throw new AppError(400, "Invalid username or password.", "VALIDATION_ERROR");
    }),
    (c) => authController.login(c),
  )
  .post("/logout", (c) => authController.logout(c))
  .get("/me", requireAuth, (c) => authController.me(c));
