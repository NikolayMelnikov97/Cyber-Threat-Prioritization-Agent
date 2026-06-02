import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Cyber Threat Prioritization Agent",
  description: "AI-powered CVE risk prioritization for cybersecurity analysts",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full`}>
      <body className="min-h-full flex flex-col bg-zinc-950 text-zinc-100 antialiased">
        <header className="border-b border-zinc-800 px-6 py-3 flex items-center justify-between">
          <a href="/" className="text-lg font-bold text-blue-400 hover:text-blue-300">
            🛡️ Cyber Threat Prioritization Agent
          </a>
          <nav className="flex items-center gap-1">
            <a href="/" className="rounded-lg px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors">
              Dashboard
            </a>
            <a href="/agent" className="rounded-lg px-3 py-1.5 text-sm bg-blue-700 text-white hover:bg-blue-600 transition-colors font-semibold">
              AI Agent
            </a>
          </nav>
        </header>
        <main className="flex-1 px-6 py-8 max-w-6xl mx-auto w-full">{children}</main>
        <footer className="border-t border-zinc-800 px-6 py-3 text-center text-xs text-zinc-600">
          AI & ML Innovation Workshop — Final Project
        </footer>
      </body>
    </html>
  );
}
