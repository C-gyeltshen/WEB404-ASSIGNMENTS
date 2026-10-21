import type { Context } from "hono";
import { endSession, startSession } from "../middleware/auth.js";
import { authService } from "../services/auth.service.js";
import type { AppEnv } from "../types/index.js";
import type { LoginInput } from "../validation/auth.validation.js";

type LoginCtx = Context<AppEnv, string, { out: { json: LoginInput } }>;

export const authController = {
  async login(c: LoginCtx) {
    const user = await authService.login(c.req.valid("json"));
    await startSession(c, user);
    return c.json({ user });
  },

  async logout(c: Context<AppEnv>) {
    endSession(c);
    return c.body(null, 204);
  },

  async me(c: Context<AppEnv>) {
    return c.json({ user: c.get("user") });
  },
};
