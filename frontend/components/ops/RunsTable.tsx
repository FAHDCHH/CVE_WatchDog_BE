"use client";

import { RefreshCw } from "lucide-react";
import { apiGet } from "@/lib/api";
import { Page, RunSummary } from "@/lib/types";
import { useApi } from "@/lib/hooks";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/Badge";
import { Loading, ErrorState, EmptyState } from "@/components/ui/States";

function duration(start: string | null, end: string | null): string {
  if (!start || !end) return "—";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (Number.isNaN(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

export function RunsTable({
  selectedRunId,
  onSelectRun,
}: {
  selectedRunId: string | null;
  onSelectRun: (id: string | null) => void;
}) {
  const { data, error, loading, reload } = useApi<Page<RunSummary>>(
    () => apiGet<Page<RunSummary>>("/admin/runs", { params: { limit: 12 } }),
    []
  );

  return (
    <Panel
      index="B1"
      title="Recent pipeline runs"
      right={
        <button className="btn-icon" onClick={reload} aria-label="Refresh runs">
          <RefreshCw size={15} />
        </button>
      }
      noBody
    >
      {loading ? (
        <Loading label="Loading runs…" />
      ) : error ? (
        <ErrorState message={error.message} onRetry={reload} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="No runs yet" message="No EltRun records found." />
      ) : (
        <div className="table-wrap">
          <table className="t">
            <thead>
              <tr>
                <th>Pipeline</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Trigger</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((r) => {
                const active = r.id === selectedRunId;
                return (
                  <tr
                    key={r.id}
                    data-clickable="true"
                    data-active={active}
                    onClick={() => onSelectRun(active ? null : r.id)}
                    title={active ? "Click to clear log filter" : "Click to view this run's logs"}
                  >
                    <td className="cve">{r.pipeline ?? "—"}</td>
                    <td>{r.mode}</td>
                    <td>
                      <StatusBadge value={r.status} />
                    </td>
                    <td className="num muted" title={fmtDateTime(r.started_at)}>
                      {fmtAgo(r.started_at)}
                    </td>
                    <td className="num">{duration(r.started_at, r.completed_at)}</td>
                    <td className="muted">{r.triggered_by}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
