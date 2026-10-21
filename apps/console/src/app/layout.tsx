import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

// The request CSP nonce must cover Next's inline hydration scripts.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Open Institutional Custody",
  description:
    "Local test setup and watch-only treasury discovery. No signing authority.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
