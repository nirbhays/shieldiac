import Link from "next/link";
import { Shield, GitBranch, Bot, FileText, Check, ChevronRight } from "lucide-react";

const features = [
  {
    icon: <Shield className="w-8 h-8 text-shield-600" />,
    title: "200+ Security Rules",
    description:
      "Comprehensive coverage for Terraform, Kubernetes, Dockerfiles, and CloudFormation based on CIS benchmarks and cloud provider best practices.",
  },
  {
    icon: <GitBranch className="w-8 h-8 text-shield-600" />,
    title: "PR-Native Workflow",
    description:
      "Automatic scanning on every push and pull request. Get instant feedback with inline comments showing severity, description, and fix suggestions.",
  },
  {
    icon: <Bot className="w-8 h-8 text-shield-600" />,
    title: "AI-Powered Fix Suggestions",
    description:
      "GPT-4.1-mini generates production-ready code fixes for every finding. Copy-paste and ship — no more researching remediation steps.",
  },
  {
    icon: <FileText className="w-8 h-8 text-shield-600" />,
    title: "Compliance Reports",
    description:
      "One-click PDF reports for SOC 2, HIPAA, PCI-DSS, and CIS. Map every finding to specific compliance controls automatically.",
  },
];

const pricingPlans = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    features: [
      "3 repositories",
      "50 scans/month",
      "100+ built-in rules",
      "GitHub integration",
      "PR comments",
      "Basic dashboard",
    ],
    cta: "Get Started Free",
    highlighted: false,
  },
  {
    name: "Pro",
    price: "$29",
    period: "/month",
    features: [
      "Unlimited repositories",
      "Unlimited scans",
      "200+ built-in rules",
      "GitHub + GitLab",
      "AI-powered fix suggestions",
      "Compliance reports (SOC2, HIPAA, PCI)",
      "Custom rules",
      "Team management",
      "Priority support",
    ],
    cta: "Start Pro Trial",
    highlighted: true,
  },
  {
    name: "Enterprise",
    price: "$99",
    period: "/month",
    features: [
      "Everything in Pro",
      "SSO / SAML",
      "Dedicated support engineer",
      "Custom compliance frameworks",
      "On-premise scanner option",
      "Audit logs",
      "99.99% SLA",
      "Unlimited users",
    ],
    cta: "Contact Sales",
    highlighted: false,
  },
];

const testimonials = [
  {
    quote:
      "ShieldIaC caught a publicly accessible RDS instance in our PR that would have been a disaster. The AI fix suggestion was spot-on.",
    author: "Sarah Chen",
    role: "Platform Engineer, FinTech Co.",
  },
  {
    quote:
      "We went from zero compliance visibility to SOC 2 ready in a week. The automated reports saved us months of audit prep work.",
    author: "Marcus Johnson",
    role: "VP Engineering, HealthStart",
  },
  {
    quote:
      "200+ rules out of the box, plus custom Rego policies for our specific requirements. This is what Checkov should have been.",
    author: "Priya Patel",
    role: "DevSecOps Lead, CloudScale",
  },
];

export default function HomePage() {
  return (
    <div>
      {/* Hero */}
      <section className="relative overflow-hidden bg-gradient-to-br from-shield-950 via-shield-900 to-shield-800 text-white">
        <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
        <div className="relative max-w-7xl mx-auto px-6 py-24 lg:py-32">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 bg-shield-800/50 border border-shield-700 rounded-full px-4 py-1.5 mb-8 text-sm">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
              Now scanning 200+ security rules
            </div>
            <h1 className="text-5xl lg:text-7xl font-bold tracking-tight leading-tight mb-6">
              Secure your
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-300">
                infrastructure code
              </span>
              <br />
              before it ships
            </h1>
            <p className="text-xl text-gray-300 mb-10 max-w-2xl">
              ShieldIaC scans Terraform, Kubernetes, Dockerfiles, and CloudFormation
              on every PR. Get AI-powered fix suggestions, compliance reports, and
              a security posture dashboard — all in one platform.
            </p>
            <div className="flex flex-wrap gap-4">
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-2 bg-white text-shield-950 px-8 py-3.5 rounded-lg font-semibold text-lg hover:bg-gray-100 transition"
              >
                Start Scanning Free
                <ChevronRight className="w-5 h-5" />
              </Link>
              <Link
                href="#features"
                className="inline-flex items-center gap-2 border border-white/30 text-white px-8 py-3.5 rounded-lg font-semibold text-lg hover:bg-white/10 transition"
              >
                See How It Works
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              Everything you need to secure IaC
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              From code scanning to compliance reporting, ShieldIaC covers the
              full DevSecOps lifecycle.
            </p>
          </div>
          <div className="grid md:grid-cols-2 gap-8">
            {features.map((feature) => (
              <div
                key={feature.title}
                className="bg-white p-8 rounded-2xl border border-gray-200 hover:border-shield-300 hover:shadow-lg transition"
              >
                <div className="mb-4">{feature.icon}</div>
                <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
                <p className="text-gray-600 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-4xl font-bold text-center mb-16">
            Three steps to secure infrastructure
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: "1", title: "Connect", desc: "Link your GitHub or GitLab repos in one click with our OAuth integration." },
              { step: "2", title: "Scan", desc: "Every push and PR is automatically scanned against 200+ security rules." },
              { step: "3", title: "Fix", desc: "Get AI-powered fix suggestions in PR comments and track compliance in your dashboard." },
            ].map((item) => (
              <div key={item.step} className="text-center">
                <div className="w-16 h-16 rounded-full bg-shield-100 text-shield-700 text-2xl font-bold flex items-center justify-center mx-auto mb-6">
                  {item.step}
                </div>
                <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                <p className="text-gray-600">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-4xl font-bold text-center mb-16">
            Trusted by platform teams
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {testimonials.map((t) => (
              <div
                key={t.author}
                className="bg-white p-8 rounded-2xl border border-gray-200"
              >
                <p className="text-gray-700 mb-6 italic">&ldquo;{t.quote}&rdquo;</p>
                <div>
                  <p className="font-semibold">{t.author}</p>
                  <p className="text-sm text-gray-500">{t.role}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="py-24">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              Simple, transparent pricing
            </h2>
            <p className="text-xl text-gray-600">
              Start free. Scale as your team grows.
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            {pricingPlans.map((plan) => (
              <div
                key={plan.name}
                className={`p-8 rounded-2xl border-2 ${
                  plan.highlighted
                    ? "border-shield-600 bg-shield-50 shadow-xl relative"
                    : "border-gray-200 bg-white"
                }`}
              >
                {plan.highlighted && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-shield-600 text-white px-4 py-1 rounded-full text-sm font-medium">
                    Most Popular
                  </div>
                )}
                <h3 className="text-xl font-semibold mb-2">{plan.name}</h3>
                <div className="mb-6">
                  <span className="text-4xl font-bold">{plan.price}</span>
                  <span className="text-gray-500">{plan.period}</span>
                </div>
                <ul className="space-y-3 mb-8">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-2">
                      <Check className="w-5 h-5 text-green-500 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700">{f}</span>
                    </li>
                  ))}
                </ul>
                <button
                  className={`w-full py-3 rounded-lg font-semibold transition ${
                    plan.highlighted
                      ? "bg-shield-600 text-white hover:bg-shield-700"
                      : "bg-gray-100 text-gray-800 hover:bg-gray-200"
                  }`}
                >
                  {plan.cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 bg-shield-950 text-white">
        <div className="max-w-4xl mx-auto px-6 text-center">
          <h2 className="text-4xl font-bold mb-6">
            Start securing your IaC today
          </h2>
          <p className="text-xl text-gray-300 mb-10">
            Free for up to 3 repos. No credit card required.
          </p>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 bg-white text-shield-950 px-10 py-4 rounded-lg font-semibold text-lg hover:bg-gray-100 transition"
          >
            Get Started Free
            <ChevronRight className="w-5 h-5" />
          </Link>
        </div>
      </section>
    </div>
  );
}
