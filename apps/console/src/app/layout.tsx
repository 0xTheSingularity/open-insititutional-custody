import type { Metadata } from "next";
import { headers } from "next/headers";
import { ThemeProvider } from "next-themes";
import type { ReactNode } from "react";
import "./globals.css";

// The request CSP nonce must cover Next's inline hydration scripts.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Open Institutional Custody",
  description: "Setup and watch-only treasury discovery. No signing authority.",
};

export default async function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
          storageKey="oic-color-theme"
          nonce={nonce}
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
