import { Shield } from "lucide-react";

export function Footer() {
  return (
    <footer className="bg-gray-50 border-t">
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-6 h-6 text-shield-600" />
              <span className="font-bold text-shield-950">ShieldIaC</span>
            </div>
            <p className="text-sm text-gray-500">
              Secure your infrastructure code before it ships. 200+ rules, AI fixes, compliance reports.
            </p>
          </div>
          <div>
            <h3 className="font-semibold mb-3">Product</h3>
            <ul className="space-y-2 text-sm text-gray-500">
              <li><a href="#features" className="hover:text-gray-900">Features</a></li>
              <li><a href="#pricing" className="hover:text-gray-900">Pricing</a></li>
              <li><a href="/dashboard" className="hover:text-gray-900">Dashboard</a></li>
              <li><a href="/docs" className="hover:text-gray-900">Documentation</a></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold mb-3">Resources</h3>
            <ul className="space-y-2 text-sm text-gray-500">
              <li><a href="/docs" className="hover:text-gray-900">API Reference</a></li>
              <li><a href="/docs" className="hover:text-gray-900">Rule Catalog</a></li>
              <li><a href="/blog" className="hover:text-gray-900">Blog</a></li>
              <li><a href="/changelog" className="hover:text-gray-900">Changelog</a></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold mb-3">Company</h3>
            <ul className="space-y-2 text-sm text-gray-500">
              <li><a href="/about" className="hover:text-gray-900">About</a></li>
              <li><a href="/security" className="hover:text-gray-900">Security</a></li>
              <li><a href="/privacy" className="hover:text-gray-900">Privacy</a></li>
              <li><a href="/terms" className="hover:text-gray-900">Terms</a></li>
            </ul>
          </div>
        </div>
        <div className="border-t mt-8 pt-8 text-sm text-gray-400 text-center">
          © 2025 ShieldIaC. All rights reserved.
        </div>
      </div>
    </footer>
  );
}
