"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield } from "lucide-react";

const NAV_LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/environment", label: "My Environment" },
];

export default function NavBar() {
  const pathname = usePathname();

  return (
    <header className="border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur-sm sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
      <Link
        href="/"
        className="flex items-center gap-2.5 text-white hover:text-blue-300 transition-colors group"
      >
        <div className="w-7 h-7 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center group-hover:bg-blue-600/30 transition-colors">
          <Shield size={14} className="text-blue-400" />
        </div>
        <span className="text-sm font-bold tracking-tight">
          Cyber Threat Agent
        </span>
      </Link>

      <nav className="flex items-center gap-1">
        {NAV_LINKS.map(({ href, label }) => {
          const isActive = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
                isActive
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60"
              }`}
            >
              {label}
            </Link>
          );
        })}
        <Link
          href="/agent"
          className={`rounded-lg px-3 py-1.5 text-sm font-semibold transition-all ml-1 ${
            pathname === "/agent"
              ? "bg-blue-600 text-white shadow-sm shadow-blue-600/30"
              : "bg-blue-600/15 border border-blue-600/30 text-blue-400 hover:bg-blue-600 hover:text-white hover:border-blue-600"
          }`}
        >
          AI Agent
        </Link>
      </nav>
    </header>
  );
}
