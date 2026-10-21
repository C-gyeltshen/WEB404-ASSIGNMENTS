/**
 * Creates two demo users so you can test that users can't reach each other's files.
 * Run: npm run db:seed
 */
import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../src/generated/prisma/client.js";
import { hashPassword } from "../src/lib/password.js";

const password = process.env.DEMO_PASSWORD ?? "SecureUpload-2026";
const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: process.env.DIRECT_URL! }) });

for (const username of ["alice", "bob"]) {
  await prisma.user.upsert({
    where: { username },
    update: { passwordHash: await hashPassword(password) },
    create: { username, passwordHash: await hashPassword(password) },
  });
  console.log(`seeded user: ${username}`);
}
await prisma.$disconnect();
