import "dotenv/config";
import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
    seed: "tsx prisma/seed.ts",
  },
  datasource: {
    // CLI commands (migrate) use the DIRECT connection (port 5432).
    // The running app uses the pooled DATABASE_URL (see src/lib/prisma.ts).
    url: env("DIRECT_URL"),
  },
});
