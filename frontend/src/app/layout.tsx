import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ShieldIaC — IaC Security Scanner",
  description:
    "Scan Terraform, Kubernetes, Dockerfiles, and CloudFormation against 200+ security rules with AI-powered fix suggestions.",
  openGraph: {
    title: "ShieldIaC — IaC Security Scanner",
    description: "Secure your infrastructure code before deployment.",
    url: "https://shieldiac.dev",
    siteName: "ShieldIaC",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.className} bg-white text-gray-900 antialiased`}>
        <Navbar />
        <main className="min-h-screen">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
