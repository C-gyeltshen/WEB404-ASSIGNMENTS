import { prisma } from "../lib/prisma.js";
import type { AuditEntry, CreateFileRecord } from "../types/index.js";

/**
 * Database access for file metadata. Every read/delete takes the ownerId
 * and filters on it IN THE QUERY: that is the IDOR protection. A request for
 * someone else's file simply finds nothing.
 */
export const fileRepository = {
  create(data: CreateFileRecord) {
    return prisma.file.create({ data });
  },

  listByOwner(ownerId: string) {
    return prisma.file.findMany({
      where: { ownerId },
      orderBy: { createdAt: "desc" },
      take: 200,
    });
  },

  findOwned(id: string, ownerId: string) {
    return prisma.file.findFirst({ where: { id, ownerId } });
  },

  async deleteOwned(id: string, ownerId: string): Promise<boolean> {
    const { count } = await prisma.file.deleteMany({ where: { id, ownerId } });
    return count === 1;
  },

  async totalBytesForOwner(ownerId: string): Promise<number> {
    const agg = await prisma.file.aggregate({ where: { ownerId }, _sum: { sizeBytes: true } });
    return agg._sum.sizeBytes ?? 0;
  },
};

export const auditRepository = {
  log(entry: AuditEntry) {
    // Attack filenames are logged as-is for investigation, but control characters
    // are made visible: Postgres rejects \0, and raw newlines would allow log forging.
    const fileName = entry.fileName
      .replace(/[\x00-\x1f\x7f]/g, (ch) => `\\x${ch.charCodeAt(0).toString(16).padStart(2, "0")}`)
      .slice(0, 255);
    return prisma.uploadAudit.create({ data: { ...entry, fileName } });
  },
};
