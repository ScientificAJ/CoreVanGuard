import { useState, type FormEvent } from "react";
import { enrollVaultKey } from "../lib/api";

export function VaultPanel() {
  const [label, setLabel] = useState("Primary workstation vault");
  const [result, setResult] = useState(
    "The vault flow is present, but the native secure-entry bridge is not wired yet."
  );

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const message = await enrollVaultKey(label);
      setResult(message);
    } catch (error) {
      setResult(error instanceof Error ? error.message : "Vault enrollment failed.");
    }
  }

  return (
    <section className="panel">
      <div className="grid gap-8 lg:grid-cols-[1fr_0.95fr]">
        <div className="space-y-4">
          <p className="eyebrow">Emergency file locking vault</p>
          <h2 className="font-display text-3xl font-semibold text-white">
            High-friction controls for the highest-value recovery path
          </h2>
          <p className="max-w-2xl text-sm leading-7 text-slate-300">
            This surface should never collect a plaintext key inside the webview. The interface is
            ready for that path, but the platform-specific secure desktop or secure input handoff
            still needs to be implemented per OS.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-5">
              <p className="text-sm text-slate-400">Protection mode</p>
              <p className="mt-2 font-display text-2xl font-semibold text-white">Kernel-gated</p>
            </div>
            <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-5">
              <p className="text-sm text-slate-400">Input policy</p>
              <p className="mt-2 font-display text-2xl font-semibold text-white">
                Native secure entry
              </p>
            </div>
          </div>
        </div>
        <form
          onSubmit={handleSubmit}
          className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6"
        >
          <label className="block text-sm font-medium text-slate-300" htmlFor="vault-label">
            Vault profile label
          </label>
          <input
            id="vault-label"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            className="mt-3 w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-white outline-none ring-0 transition focus:border-pulse"
            placeholder="Primary workstation vault"
          />
          <button
            type="submit"
            className="mt-5 w-full rounded-2xl bg-gradient-to-r from-pulse to-signal px-4 py-3 font-semibold text-ink transition hover:brightness-110"
          >
            Launch secure key enrollment
          </button>
          <div className="mt-5 rounded-2xl border border-white/10 bg-white/5 p-4 text-sm leading-6 text-slate-300">
            {result}
          </div>
        </form>
      </div>
    </section>
  );
}
