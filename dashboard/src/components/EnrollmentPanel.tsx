// Enrollment panel — shown on the device page for self-enrolled
// (reaper-managed) WireGuard peers. Regular onboarded devices don't get
// this; the caller only renders it when an EnrolledPeer matches the IP.

import type { ReactNode } from "react";
import type { EnrolledPeer } from "../lib/api";
import { fmtAge, fmtDateTime } from "../lib/format";
import { Tag } from "./Tag";

// The gateway samples rx on the reaper's 20s cadence, and keepalive is
// clamped to a 10s minimum — so on a healthy peer the observed miss count
// can be as high as 1 purely from sampling jitter. We therefore only flag
// "stale" from the 2nd missed beat, which never triggers on a live peer at
// any valid keepalive. A peer that misses its whole window is reaped by the
// gateway and drops out of the list, so this renders small values only.
const staleMissedThreshold = 2;

// missedHeartbeats derives how many keepalive intervals have elapsed since
// the gateway last saw the peer's rx advance.
function missedHeartbeats(p: EnrolledPeer): number {
  const ka = p.keepalive_interval_seconds ?? 0;
  const last = p.last_rx_at ? Date.parse(p.last_rx_at) : 0;
  if (ka <= 0 || !last) return 0;
  return Math.max(0, Math.floor((Date.now() - last) / 1000 / ka));
}

function ago(t: string | undefined): string {
  const a = fmtAge(t);
  return a === "—" ? a : a + " ago";
}

export function EnrollmentPanel({ peer }: { peer: EnrolledPeer }) {
  const missed = missedHeartbeats(peer);
  const stale = missed >= staleMissedThreshold;
  const ka = peer.keepalive_interval_seconds ?? 0;
  const reap = peer.reap_count ?? 0;
  // Liveness window is derived, not sent: keepalive × reap_count.
  const window = ka * reap;

  return (
    <section className="bg-canvas border-1.5 border-navy overflow-hidden">
      <div className="flex items-center px-4 py-2.5 bg-navy-100 border-b border-navy gap-2">
        <div className="font-mono text-xs uppercase tracking-wider text-navy font-bold">
          Enrollment
        </div>
        <Tag tone={stale ? "warning" : "success"}>
          <span aria-hidden="true">●</span> {stale ? "stale" : "live"}
        </Tag>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3">
        <Field label="Authorizer" className="border-b border-canvas-muted sm:border-r">
          <span className="font-mono">{peer.authorizer_name || "—"}</span>
          {peer.authorizer_type && (
            <>
              {" "}
              <span className="text-text-muted">·</span>{" "}
              <Tag tone="neutral">{peer.authorizer_type}</Tag>
            </>
          )}
        </Field>
        <Field label="Subject" className="border-b border-canvas-muted sm:border-r">
          <span className="font-mono text-xs break-all">{peer.subject_key || "—"}</span>
        </Field>
        <Field label="Enrolled" className="border-b border-canvas-muted">
          <div className="tabular-nums">{ago(peer.created_at)}</div>
          <div className="text-text-muted text-2xs tabular-nums mt-0.5">
            {fmtDateTime(peer.created_at)}
          </div>
        </Field>

        <Field label="Keepalive" className="sm:border-r border-canvas-muted">
          <span className="tabular-nums">{ka ? ka + "s" : "—"}</span>
        </Field>
        <Field label="Liveness window" className="sm:border-r border-canvas-muted">
          <span className="tabular-nums">{window ? window + "s" : "—"}</span>
          {ka > 0 && reap > 0 ? (
            <span className="text-text-muted text-xs ml-1.5">
              {ka}s × {reap}
            </span>
          ) : null}
        </Field>
        <Field label="Last heartbeat">
          <span className="tabular-nums">{peer.last_rx_at ? ago(peer.last_rx_at) : "—"}</span>
          {stale && (
            <Tag tone="warning" className="ml-1.5">
              {missed} missed
            </Tag>
          )}
        </Field>
      </div>
    </section>
  );
}

function Field({
  label,
  children,
  className = "",
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={"px-4 py-3 " + className}>
      <div className="font-mono text-2xs uppercase tracking-wider text-text-subtle mb-1">
        {label}
      </div>
      <div className="text-sm text-text">{children}</div>
    </div>
  );
}
