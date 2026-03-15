import type { DiagnosticsFeed } from "../lib/types";

interface DiagnosticsPanelProps {
  diagnostics: DiagnosticsFeed;
}

export function DiagnosticsPanel({ diagnostics }: DiagnosticsPanelProps) {
  return (
    <section className="panel">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="eyebrow">Advanced diagnostics</p>
          <h2 className="font-display text-3xl font-semibold text-white">
            Progressive disclosure for execution DNA, origin graphs, and intercept logs
          </h2>
        </div>
        <p className="max-w-xl text-sm leading-6 text-slate-300">
          Keep the consumer path clean. Push thread-origin trees, eBPF intercepts, and anomaly
          timelines here for operators who need to reason about exact behavior.
        </p>
      </div>
      <div className="mt-8 grid gap-4">
        {diagnostics.events.length > 0 ? (
          diagnostics.events.map((detection) => (
            <article
              key={detection.title}
              className="grid gap-3 rounded-[1.75rem] border border-white/10 bg-white/5 p-5 md:grid-cols-[0.8fr_1.4fr_1.2fr]"
            >
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Signal</p>
                <p className="mt-2 font-display text-2xl font-semibold text-white">
                  {detection.title}
                </p>
                <p className="mt-2 text-sm capitalize text-pulse">{detection.severity}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Origin</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">{detection.origin}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Action</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">{detection.action}</p>
              </div>
            </article>
          ))
        ) : (
          <article className="rounded-[1.75rem] border border-white/10 bg-white/5 p-5">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Feed state</p>
            <p className="mt-2 font-display text-2xl font-semibold text-white">
              {diagnostics.state}
            </p>
            <p className="mt-2 text-sm leading-6 text-slate-300">{diagnostics.reason}</p>
          </article>
        )}
      </div>
    </section>
  );
}
