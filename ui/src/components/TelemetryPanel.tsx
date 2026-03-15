import type { TelemetryPoint } from "../lib/types";

interface TelemetryPanelProps {
  telemetry: TelemetryPoint[];
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
  return (
    <section className="panel">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="eyebrow">Hardware-aware visualizer</p>
          <h2 className="font-display text-3xl font-semibold text-white">
            Adaptive threading across performance and efficiency cores
          </h2>
        </div>
        <p className="max-w-xl text-sm leading-6 text-slate-300">
          Tier 3 analysis should stay off interactive workloads. This view makes the scheduling
          story legible instead of hidden behind an optimizer black box.
        </p>
      </div>
      <div className="mt-8 grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
        <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-5">
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
              points={line(telemetry.map((point) => point.performance_cores), 100)}
            />
            <polyline
              fill="none"
              stroke="url(#eff)"
              strokeWidth="3"
              points={line(telemetry.map((point) => point.efficiency_cores), 100)}
            />
          </svg>
        </div>
        <div className="space-y-4">
          {telemetry.map((point) => (
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
                  <p className="text-slate-400">Performance cores</p>
                  <p className="mt-1 text-xl font-semibold text-signal">
                    {point.performance_cores}%
                  </p>
                </div>
                <div className="rounded-2xl bg-slate-950/60 p-3">
                  <p className="text-slate-400">Efficiency cores</p>
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
          ))}
        </div>
      </div>
    </section>
  );
}

