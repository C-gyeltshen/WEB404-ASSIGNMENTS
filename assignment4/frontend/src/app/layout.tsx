import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SQL Injection Lab",
  description: "Educational SQL injection lab: vulnerable vs safe endpoints",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en"><body>{children}</body></html>
  );
}
