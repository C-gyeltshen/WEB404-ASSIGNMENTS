import "dotenv/config";
import { z } from "zod";

/**
 * Validate environment variables at startup. The app refuses to boot with a
 * missing or malformed secret instead of failing later at request time.
 */
const schema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().int().positive().default(8787),

  // Browser origin allowed to call this API (CORS + CSRF origin check)
  FRONTEND_ORIGIN: z.url(),

  // Signs the session cookie. Generate with: openssl rand -hex 32
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),

  // Prisma runtime connection (Supabase transaction pooler, port 6543)
  DATABASE_URL: z.string().startsWith("postgres"),

  // Supabase Storage (REST)
  SUPABASE_URL: z.url(),
  SUPABASE_SECRET_KEY: z.string().min(20),
  SUPABASE_STORAGE_BUCKET: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_-]{1,62}$/, "Bucket name: lowercase letters, digits, - and _"),

  // Upload limits
  MAX_FILE_SIZE_MB: z.coerce.number().positive().max(50).default(5),
  USER_QUOTA_MB: z.coerce.number().positive().default(50),
  UPLOADS_PER_MINUTE: z.coerce.number().int().positive().default(10),
  SIGNED_URL_TTL_SECONDS: z.coerce.number().int().min(10).max(3600).default(60),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(`  ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

export const env = {
  ...parsed.data,
  SUPABASE_URL: parsed.data.SUPABASE_URL.replace(/\/+$/, ""),
  MAX_FILE_SIZE_BYTES: Math.floor(parsed.data.MAX_FILE_SIZE_MB * 1024 * 1024),
  USER_QUOTA_BYTES: Math.floor(parsed.data.USER_QUOTA_MB * 1024 * 1024),
  isProd: parsed.data.NODE_ENV === "production",
};
