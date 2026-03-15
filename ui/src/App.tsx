import { useEffect, useState } from "react";
import { DiagnosticsPanel } from "./components/DiagnosticsPanel";
import { StatusHero } from "./components/StatusHero";
import { TelemetryPanel } from "./components/TelemetryPanel";
import { VaultPanel } from "./components/VaultPanel";
import { getDashboardSnapshot } from "./lib/api";
import type { DashboardSnapshot } from "./lib/types";

const tabs = [
  { id: "overview", label: "Overview" },
  { id: "vault", label: "EFL Vault" },
  { id: "diagnostics", label: "Advanced Diagnostics" }
] as const;

type TabId = (typeof tabs)[number]["id"];

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [tab, setTab] = useState<TabId>("overview");

  useEffect(() => {
    getDashboardSnapshot().then(setSnapshot);
  }, []);

  if (!snapshot) {
    return (
      <main className="min-h-screen bg-ink text-white">
        <div className="mx-auto flex min-h-screen max-w-7xl items-center justify-center px-6">
          <div className="rounded-full border border-white/10 px-6 py-3 text-sm uppercase tracking-[0.24em] text-slate-300">
            Initializing CoreVanguard shell
          </div>
        </div>
      </main>
    );
  }

  return (
    <main
      className="min-h-screen bg-ink bg-control-grid text-white"
      style={{ backgroundSize: "auto, auto, 44px 44px, 44px 44px" }}
    >
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-8 px-4 py-6 md:px-6 lg:px-8">
        <header className="glass-nav flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="eyebrow">CoreVanguard NGAV</p>
            <h1 className="font-display text-3xl font-semibold text-white">
              Commercial shell for behavioral defense
            </h1>
          </div>
          <nav className="flex flex-wrap gap-2">
            {tabs.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setTab(item.id)}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  tab === item.id
                    ? "bg-white text-ink"
                    : "bg-white/5 text-slate-300 hover:bg-white/10"
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>
        </header>

        {snapshot.data_mode !== "live" && (
          <section className="rounded-[1.5rem] border border-amber/30 bg-amber/10 px-5 py-4 text-sm text-amber">
            <span className="font-semibold uppercase tracking-[0.18em]">Development data</span>
            <span className="ml-3 text-slate-200">{snapshot.data_note}</span>
          </section>
        )}

        <StatusHero snapshot={snapshot} />

        {tab === "overview" && <TelemetryPanel telemetry={snapshot.telemetry} />}
        {tab === "vault" && <VaultPanel />}
        {tab === "diagnostics" && <DiagnosticsPanel detections={snapshot.detections} />}
      </div>
    </main>
  );
}
