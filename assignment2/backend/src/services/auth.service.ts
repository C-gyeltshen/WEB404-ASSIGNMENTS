import { AppError } from "../lib/errors.js";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { userRepository } from "../repositories/user.repository.js";
import type { AuthUser } from "../types/index.js";
import type { LoginInput } from "../validation/auth.validation.js";

// Hash used when the username doesn't exist, so a login attempt takes the
// same time either way (prevents username enumeration by timing).
const dummyHash = hashPassword("timing-equaliser");

export const authService = {
  async login({ username, password }: LoginInput): Promise<AuthUser> {
    const user = await userRepository.findByUsername(username);
    const ok = await verifyPassword(password, user?.passwordHash ?? (await dummyHash));
    if (!user || !ok) throw new AppError(401, "Invalid username or password.", "BAD_CREDENTIALS");
    return { id: user.id, username: user.username };
  },

  async findUser(id: string): Promise<AuthUser | null> {
    return userRepository.findById(id);
  },
};
