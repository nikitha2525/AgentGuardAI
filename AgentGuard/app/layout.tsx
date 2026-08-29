import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentGuard \u2014 Runtime Security Firewall for AI Agents",
  description:
    "Interactive prototype: a real-time security layer that detects threats, verifies tool permissions, and blocks dangerous AI-agent actions before execution.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-graphite-950 text-mist-100 font-body antialiased">{children}</body>
    </html>
  );
}
