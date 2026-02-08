import Link from "next/link";
import { Shield } from "lucide-react";

export function Navbar() {
  return (
    <nav className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Shield className="w-8 h-8 text-shield-600" />
          <span className="text-xl font-bold text-shield-950">ShieldIaC</span>
        </Link>
        <div className="hidden md:flex items-center gap-8">
          <Link href="/#features" className="text-sm text-gray-600 hover:text-gray-900">Features</Link>
          <Link href="/#pricing" className="text-sm text-gray-600 hover:text-gray-900">Pricing</Link>
          <Link href="/dashboard" className="text-sm text-gray-600 hover:text-gray-900">Dashboard</Link>
          <Link
            href="/dashboard"
            className="bg-shield-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-shield-700 transition"
          >
            Get Started
          </Link>
        </div>
      </div>
    </nav>
  );
}
