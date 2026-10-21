import Database from "better-sqlite3";

/**
 * In-memory SQLite database, re-seeded every time the server starts.
 * Nothing here touches a real database or the network: this is a throwaway
 * teaching sandbox. Delete it and it is gone.
 */
export const db = new Database(":memory:");

/**
 * SQLite has no SLEEP() function. Real databases do (MySQL: SLEEP(),
 * PostgreSQL: pg_sleep(), MSSQL: WAITFOR DELAY). We register one so the
 * time-based blind demo behaves like it would against a real DB. This is
 * ONLY so the lab is realistic; it is not what makes the app vulnerable.
 */
db.function("sleep", (seconds: unknown) => {
  const ms = Math.min(Number(seconds) * 1000 || 0, 5000); // capped so the lab can't hang
  const end = Date.now() + ms;
  while (Date.now() < end) {
    /* busy-wait: stands in for the DB blocking on SLEEP() */
  }
  return 0;
});

export function seed(): void {
  db.exec(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS products;

    CREATE TABLE users (
      id        INTEGER PRIMARY KEY,
      username  TEXT NOT NULL,
      password  TEXT NOT NULL,     -- plaintext ON PURPOSE, to show what leaks
      email     TEXT NOT NULL,
      role      TEXT NOT NULL,
      api_token TEXT NOT NULL      -- the "secret" an attacker is usually after
    );

    INSERT INTO users (id, username, password, email, role, api_token) VALUES
      (1, 'alice', 'alice-pass-123',  'alice@example.com', 'user',  'tok_alice_7f3a9b'),
      (2, 'bob',   'bob-pass-456',    'bob@example.com',   'user',  'tok_bob_12c4de'),
      (3, 'admin', 'S3cr3t-Adm1n!',   'admin@example.com', 'admin', 'tok_admin_ff00aa');

    CREATE TABLE products (
      id    INTEGER PRIMARY KEY,
      name  TEXT NOT NULL,
      price REAL NOT NULL
    );

    INSERT INTO products (id, name, price) VALUES
      (1, 'Keyboard', 49.9),
      (2, 'Mouse',    19.5),
      (3, 'Monitor',  199.0),
      (4, 'Webcam',   79.0);
  `);
}
