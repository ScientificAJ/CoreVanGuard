import type { ComponentState, DashboardSnapshot } from "../lib/types";

const toneMap: Record<
  DashboardSnapshot["status"],
  { pill: string; ring: string; label: string }
> = {
  secure: {
    pill: "bg-signal/20 text-signal",
    ring: "border-signal/60 shadow-[0_0_40px_rgba(110,255,155,0.25)]",
    label: "Secure"
  },
  monitoring: {
    pill: "bg-amber/20 text-amber",
    ring: "border-amber/60 shadow-[0_0_40px_rgba(248,212,107,0.25)]",
    label: "Monitoring"
  },
  lockdown: {
    pill: "bg-ember/20 text-ember",
    ring: "border-ember/60 shadow-[0_0_40px_rgba(255,139,106,0.3)]",
    label: "Emergency Lockdown"
  }
};

const stateToneMap: Record<ComponentState, string> = {
  online: "bg-signal/15 text-signal",
  offline: "bg-ember/15 text-ember",
  degraded: "bg-amber/15 text-amber",
  unconfigured: "bg-slate-500/15 text-slate-300"
};

interface StatusHeroProps {
  snapshot: DashboardSnapshot;
}

export function StatusHero({ snapshot }: StatusHeroProps) {
  const tone = toneMap[snapshot.status];

  return (
    <section className="panel relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(110,255,155,0.18),transparent_34%),radial-gradient(circle_at_bottom_left,rgba(153,246,228,0.12),transparent_40%)]" />
      <div className="relative grid gap-8 lg:grid-cols-[1.4fr_0.9fr]">
        <div className="space-y-6">
          <div className={`inline-flex rounded-full px-4 py-2 text-sm font-semibold ${tone.pill}`}>
            Status at a Glance · {tone.label}
          </div>
          <div className="space-y-3">
            <h1 className="font-display text-4xl font-bold tracking-tight text-white md:text-6xl">
              {snapshot.headline}
            </h1>
            <p className="max-w-2xl text-base leading-7 text-slate-300 md:text-lg">
              {snapshot.message}
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {snapshot.services.map((service) => (
              <article
                key={service.label}
                className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur"
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">
                    {service.label}
                  </p>
                  <span
                    className={`rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${stateToneMap[service.state]}`}
                  >
                    {service.state}
                  </span>
                </div>
                <p className="mt-3 font-display text-3xl font-semibold text-white">
                  {service.state === "online" ? "Connected" : service.state}
                </p>
                <p className="mt-2 text-sm text-slate-300">{service.detail}</p>
              </article>
            ))}
          </div>
        </div>
        <div className="flex items-center justify-center">
          <div
            className={`flex h-72 w-72 flex-col items-center justify-center rounded-full border bg-slate-950/80 text-center ${tone.ring}`}
          >
            <span className="text-sm uppercase tracking-[0.38em] text-slate-400">Defense Core</span>
            <span className="mt-4 font-display text-5xl font-bold text-white">{tone.label}</span>
            <span className="mt-4 max-w-[13rem] text-sm leading-6 text-slate-300">
              Provider: {snapshot.provider.replace(/_/g, " ")}. Platform: {snapshot.platform}.
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}
