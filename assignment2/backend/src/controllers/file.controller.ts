import type { Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import { fileService } from "../services/file.service.js";
import type { AppEnv } from "../types/index.js";

/**
 * Controllers translate HTTP <-> service calls. No business logic here:
 * they read already-validated input, call the service, and shape the response.
 */
type UploadCtx = Context<AppEnv, string, { out: { form: { file: File } } }>;
type IdCtx = Context<AppEnv, string, { out: { param: { id: string } } }>;

function clientIp(c: Context): string | null {
  try {
    return getConnInfo(c).remote.address ?? null;
  } catch {
    return null;
  }
}

export const fileController = {
  async upload(c: UploadCtx) {
    const { file } = c.req.valid("form");
    const dto = await fileService.upload(c.get("user"), file, clientIp(c));
    return c.json({ file: dto }, 201);
  },

  async list(c: Context<AppEnv>) {
    return c.json(await fileService.list(c.get("user")));
  },

  async downloadUrl(c: IdCtx) {
    const { id } = c.req.valid("param");
    return c.json(await fileService.getDownloadUrl(c.get("user"), id));
  },

  async remove(c: IdCtx) {
    const { id } = c.req.valid("param");
    await fileService.remove(c.get("user"), id);
    return c.body(null, 204);
  },
};
