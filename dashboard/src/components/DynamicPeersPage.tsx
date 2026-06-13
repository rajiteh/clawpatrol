// Dynamic peers — transient, self-registered WireGuard leases (e.g.
// Kubernetes agent pods). Read-only observability: the gateway is the
// source of truth (leases expire on missed heartbeats), so there is no
// row action here. Polls /api/dynamic-peers on the same 5s cadence as
// the rest of the dashboard.

import { useEffect, useState } from "react";
import { getDynamicPeers, type DynamicPeerLease } from "../lib/api";
import { fmtAge, fmtDateTime, fmtExpiry } from "../lib/format";
import { Main } from "./Main";
import { PageTitle } from "./PageTitle";
import { Tag } from "./Tag";

export function DynamicPeersPage() {
  const [leases, setLeases] = useState<DynamicPeerLease[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const rows = await getDynamicPeers();
        if (alive) {
          setLeases(rows ?? []);
          setErr(null);
        }
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : "load failed");
      }
    }
    load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  return (
    <Main>
      <PageTitle trail={[{ label: "Dynamic peers" }]} />
      <p className="text-xs text-text-muted max-w-prose">
        Transient WireGuard peers that self-register through a configured authorizer and hold a
        lease renewed by heartbeats. Leases are revoked automatically when a peer stops sending
        heartbeats.
      </p>
      {err && <div className="text-sm text-danger-500">{err}</div>}
      <section className="bg-canvas border-1.5 border-navy overflow-hidden">
        <div className="overflow-x-auto">
          <LeasesTable leases={leases} />
        </div>
      </section>
    </Main>
  );
}

function LeasesTable({ leases }: { leases: DynamicPeerLease[] | null }) {
  return (
    <table className="w-full table-fixed border-collapse" style={{ minWidth: 860 }}>
      <colgroup>
        <col />
        <col style={{ width: 120 }} />
        <col style={{ width: 180 }} />
        <col style={{ width: 110 }} />
        <col style={{ width: 110 }} />
        <col style={{ width: 90 }} />
      </colgroup>
      <thead className="bg-navy-100 border-b border-navy">
        <tr>
          <Th>Peer</Th>
          <Th>Profile</Th>
          <Th>Authorizer</Th>
          <Th>Heartbeat</Th>
          <Th>Expires</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody>
        {leases === null && (
          <tr>
            <td colSpan={6} className="px-5 py-8 text-center text-xs text-text-subtle">
              Loading…
            </td>
          </tr>
        )}
        {leases !== null && leases.length === 0 && (
          <tr>
            <td colSpan={6} className="px-5 py-8 text-center text-xs text-text-subtle">
              No dynamic peers registered
            </td>
          </tr>
        )}
        {(leases ?? []).map((l) => (
          <tr key={l.peer_ip} className="border-b border-canvas-muted">
            <Td>
              <div className="flex flex-col min-w-0">
                <span className="text-sm font-semibold text-text truncate" title={l.subject_key}>
                  {l.display_name || l.peer_ip}
                </span>
                <span className="text-2xs text-text-muted tabular-nums truncate" title={l.owner}>
                  {l.peer_ip}
                  {l.owner ? " · " + l.owner : ""}
                </span>
              </div>
            </Td>
            <Td className="truncate">
              <Tag tone="info">{l.profile || "—"}</Tag>
            </Td>
            <Td className="text-xs text-text-muted truncate" title={l.authorizer_type}>
              {l.authorizer_name || "—"}
              <span className="text-2xs text-text-subtle"> · {l.transport}</span>
            </Td>
            <Td
              className="text-xs text-text-muted tabular-nums"
              title={l.last_heartbeat ? fmtDateTime(l.last_heartbeat) : ""}
            >
              {l.last_heartbeat ? fmtAge(l.last_heartbeat) : "—"}
            </Td>
            <Td className="text-xs text-text-muted tabular-nums">{fmtExpiry(l.expires_at)}</Td>
            <Td>
              <Tag tone={l.expired ? "danger" : "success"}>{l.expired ? "expired" : "live"}</Tag>
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={
        "px-3 sm:px-3.5 py-2.5 text-left text-xs font-mono uppercase tracking-wider text-navy font-bold " +
        className
      }
    >
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
  ...rest
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <td className={"px-3 sm:px-3.5 py-2.5 align-middle overflow-hidden " + className} {...rest}>
      {children}
    </td>
  );
}
