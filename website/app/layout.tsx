import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "localhost:3000";
  const protocol =
    requestHeaders.get("x-forwarded-proto") ??
    (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const title = "Latch — Security enforcement for AI agents";
  const description =
    "An open-source security boundary that enforces policy, risk, budgets, approvals, and auditability before AI agent actions execute.";

  return {
    metadataBase: new URL(origin),
    title: {
      default: title,
      template: "%s · Latch",
    },
    description,
    keywords: [
      "AI agent security",
      "MCP security",
      "policy enforcement",
      "agent firewall",
      "open source security",
    ],
    authors: [{ name: "Latch contributors" }],
    openGraph: {
      title,
      description,
      type: "website",
      images: [
        {
          url: `${origin}/og.png`,
          width: 1744,
          height: 909,
          alt: "Latch — Let agents move. Keep control.",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [`${origin}/og.png`],
    },
    icons: {},
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
