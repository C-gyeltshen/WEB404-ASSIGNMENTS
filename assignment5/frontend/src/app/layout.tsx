import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "JWT Attack Lab",
  description: "Educational JWT lab: insecure vs secure token handling",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
