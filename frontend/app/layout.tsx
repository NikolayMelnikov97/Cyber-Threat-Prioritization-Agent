import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import NavBar from "@/components/NavBar";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Cyber Threat Prioritization Agent",
  description: "AI-powered CVE risk prioritization for cybersecurity analysts",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full`}
    >
      <body className="min-h-full flex flex-col bg-zinc-950 text-zinc-100 antialiased">
        <NavBar />
        <main className="flex-1 px-6 py-8 max-w-6xl mx-auto w-full">
          {children}
        </main>
        <footer className="border-t border-zinc-800/60 px-6 py-3 text-center text-xs text-zinc-700">
          AI & ML Innovation Workshop — Final Project
        </footer>
      </body>
    </html>
  );
}
