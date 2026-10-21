import { prisma } from "../lib/prisma.js";

export const userRepository = {
  findByUsername(username: string) {
    return prisma.user.findUnique({ where: { username } });
  },

  findById(id: string) {
    return prisma.user.findUnique({ where: { id }, select: { id: true, username: true } });
  },
};
