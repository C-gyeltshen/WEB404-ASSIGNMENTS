import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure Upload",
  description: "Secure file upload demo: Next.js + Hono + Prisma + Supabase Storage",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
