import { z } from "zod";

export const loginSchema = z.object({
  username: z.string().trim().min(1).max(50).regex(/^[a-zA-Z0-9_.-]+$/),
  password: z.string().min(1).max(200),
});

export type LoginInput = z.infer<typeof loginSchema>;
