/**
 * Stand-in "user database". Passwords are plaintext only to keep the lab
 * focused on JWTs; a real app hashes them (see the file-upload project).
 */
export interface User {
  id: string;
  username: string;
  password: string;
  role: "user" | "admin";
}

const USERS: User[] = [
  { id: "1", username: "alice", password: "alice-pass-123", role: "user" },
  { id: "2", username: "bob", password: "bob-pass-456", role: "user" },
  { id: "3", username: "admin", password: "S3cr3t-Adm1n!", role: "admin" },
];

export function findByLogin(username: string, password: string): User | undefined {
  return USERS.find((u) => u.username === username && u.password === password);
}

export function findById(id: string): User | undefined {
  return USERS.find((u) => u.id === id);
}
