"use client";

export default function SettingsPage() {
  return (
    <div className="max-w-4xl mx-auto px-6 py-8">
      <h1 className="text-3xl font-bold mb-8">Settings</h1>

      {/* Integrations */}
      <section className="bg-white border rounded-2xl p-6 mb-8">
        <h2 className="text-lg font-semibold mb-4">Integrations</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between py-3 border-b">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 bg-gray-900 rounded-lg flex items-center justify-center text-white font-bold">GH</div>
              <div>
                <div className="font-medium">GitHub</div>
                <div className="text-sm text-green-600">Connected</div>
              </div>
            </div>
            <button className="text-sm text-red-600 hover:underline">Disconnect</button>
          </div>
          <div className="flex items-center justify-between py-3 border-b">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 bg-orange-600 rounded-lg flex items-center justify-center text-white font-bold">GL</div>
              <div>
                <div className="font-medium">GitLab</div>
                <div className="text-sm text-gray-500">Not connected</div>
              </div>
            </div>
            <button className="bg-shield-600 text-white text-sm px-4 py-2 rounded-lg hover:bg-shield-700">Connect</button>
          </div>
        </div>
      </section>

      {/* Billing */}
      <section className="bg-white border rounded-2xl p-6 mb-8">
        <h2 className="text-lg font-semibold mb-4">Billing</h2>
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="text-2xl font-bold">Free Plan</div>
            <div className="text-sm text-gray-500">12/50 scans used this month • 2/3 repos</div>
          </div>
          <button className="bg-shield-600 text-white px-4 py-2 rounded-lg hover:bg-shield-700">Upgrade to Pro</button>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div className="bg-shield-600 h-2 rounded-full" style={{ width: "24%" }} />
        </div>
      </section>

      {/* Notifications */}
      <section className="bg-white border rounded-2xl p-6 mb-8">
        <h2 className="text-lg font-semibold mb-4">Notifications</h2>
        <div className="space-y-4">
          {[
            { label: "Email on critical findings", enabled: true },
            { label: "Weekly security summary", enabled: true },
            { label: "PR comment on every scan", enabled: true },
            { label: "Slack notifications", enabled: false },
          ].map((pref) => (
            <div key={pref.label} className="flex items-center justify-between">
              <span>{pref.label}</span>
              <div className={`w-10 h-6 rounded-full ${pref.enabled ? "bg-green-500" : "bg-gray-300"} relative cursor-pointer`}>
                <div className={`w-4 h-4 bg-white rounded-full absolute top-1 ${pref.enabled ? "right-1" : "left-1"} transition`} />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Webhook Secret */}
      <section className="bg-white border rounded-2xl p-6">
        <h2 className="text-lg font-semibold mb-4">Webhook Configuration</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Webhook URL</label>
            <div className="flex">
              <input
                type="text"
                value="https://api.shieldiac.dev/api/v1/webhooks/github"
                readOnly
                className="flex-1 bg-gray-50 border rounded-l-lg px-4 py-2 text-sm font-mono"
              />
              <button className="bg-gray-100 border border-l-0 rounded-r-lg px-4 py-2 text-sm hover:bg-gray-200">
                Copy
              </button>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Webhook Secret</label>
            <input type="password" value="••••••••••••" readOnly className="w-full bg-gray-50 border rounded-lg px-4 py-2 text-sm" />
          </div>
        </div>
      </section>
    </div>
  );
}
