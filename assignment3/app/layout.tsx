import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Secure Web CLI",
  description: "A web-based command line with command-injection safeguards",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
