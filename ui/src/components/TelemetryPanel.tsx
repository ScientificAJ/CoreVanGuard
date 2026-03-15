import type { TelemetryFeed } from "../lib/types";

interface TelemetryPanelProps {
  telemetry: TelemetryFeed;
}

function line(points: number[], height: number) {
  if (points.length === 0) {
    return "";
  }

  const step = 100 / Math.max(points.length - 1, 1);
  return points
    .map((point, index) => `${index * step},${height - point}`)
    .join(" ");
}

export function TelemetryPanel({ telemetry }: TelemetryPanelProps) {
  const hasPoints = telemetry.points.length > 0;

  return (
    <section className="panel">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="eyebrow">Hardware-aware visualizer</p>
          <h2 className="font-display text-3xl font-semibold text-white">
            Adaptive analysis lanes across the detected host topology
          </h2>
        </div>
        <p className="max-w-xl text-sm leading-6 text-slate-300">
          Tier 3 analysis should stay off interactive workloads. These values are derived from the
          engine scheduler and host CPU profile instead of hard-coded demo metrics.
        </p>
      </div>
      <div className="mt-8 grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
        <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-5">
          {hasPoints ? (
            <svg viewBox="0 0 100 100" className="h-72 w-full overflow-visible">
              <defs>
                <linearGradient id="perf" x1="0%" x2="100%">
                  <stop offset="0%" stopColor="#6eff9b" />
                  <stop offset="100%" stopColor="#99f6e4" />
                </linearGradient>
                <linearGradient id="eff" x1="0%" x2="100%">
                  <stop offset="0%" stopColor="#f8d46b" />
                  <stop offset="100%" stopColor="#ff8b6a" />
                </linearGradient>
              </defs>
              {[20, 40, 60, 80].map((offset) => (
                <line
                  key={offset}
                  x1="0"
                  y1={offset}
                  x2="100"
                  y2={offset}
                  stroke="rgba(255,255,255,0.08)"
                  strokeDasharray="2 4"
                />
              ))}
              <polyline
                fill="none"
                stroke="url(#perf)"
                strokeWidth="3"
                points={line(telemetry.points.map((point) => point.performance_cores), 100)}
              />
              <polyline
                fill="none"
                stroke="url(#eff)"
                strokeWidth="3"
                points={line(telemetry.points.map((point) => point.efficiency_cores), 100)}
              />
            </svg>
          ) : (
            <div className="flex h-72 items-center justify-center rounded-[1.5rem] border border-dashed border-white/10 bg-white/[0.03] text-center">
              <div className="max-w-md space-y-3 px-6">
                <p className="text-xs uppercase tracking-[0.28em] text-slate-400">
                  Telemetry unavailable
                </p>
                <p className="font-display text-2xl font-semibold text-white">{telemetry.state}</p>
                <p className="text-sm leading-6 text-slate-300">{telemetry.reason}</p>
              </div>
            </div>
          )}
        </div>
        <div className="space-y-4">
          {hasPoints ? (
            telemetry.points.map((point) => (
              <article
                key={point.slot}
                className="rounded-[1.75rem] border border-white/10 bg-white/5 p-5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-display text-xl font-semibold text-white">{point.slot}</span>
                  <span className="text-xs uppercase tracking-[0.24em] text-slate-400">
                    Scheduler sample
                  </span>
                </div>
                <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
                  <div className="rounded-2xl bg-slate-950/60 p-3">
                    <p className="text-slate-400">Latency lane</p>
                    <p className="mt-1 text-xl font-semibold text-signal">
                      {point.performance_cores}%
                    </p>
                  </div>
                  <div className="rounded-2xl bg-slate-950/60 p-3">
                    <p className="text-slate-400">Background lane</p>
                    <p className="mt-1 text-xl font-semibold text-amber">
                      {point.efficiency_cores}%
                    </p>
                  </div>
                  <div className="rounded-2xl bg-slate-950/60 p-3">
                    <p className="text-slate-400">Background jobs</p>
                    <p className="mt-1 text-xl font-semibold text-mist">
                      {point.background_jobs}
                    </p>
                  </div>
                </div>
              </article>
            ))
          ) : (
            <article className="rounded-[1.75rem] border border-white/10 bg-white/5 p-5">
              <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Feed state</p>
              <p className="mt-2 font-display text-2xl font-semibold text-white">
                {telemetry.state}
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">{telemetry.reason}</p>
            </article>
          )}
        </div>
      </div>
    </section>
  );
}
