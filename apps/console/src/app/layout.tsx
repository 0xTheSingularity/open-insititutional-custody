import type { Metadata } from "next";
import localFont from "next/font/local";
import { headers } from "next/headers";
import { ThemeProvider } from "next-themes";
import type { ReactNode } from "react";
import "./globals.css";

const clash = localFont({
  src: "../../public/fonts/clash-grotesk-var.woff2",
  variable: "--font-clash",
  weight: "200 700",
  display: "swap",
});

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
    <html lang="en" className={clash.variable} suppressHydrationWarning>
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
