"use client";

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, RefreshCw, X } from "lucide-react";
import { apiGet } from "@/lib/api";
import { Page, LogEntry } from "@/lib/types";
import { useApi } from "@/lib/hooks";
import { fmtAgo, fmtTime } from "@/lib/format";
import { Panel } from "@/components/ui/Panel";
import { LevelBadge } from "@/components/ui/Badge";
import { Loading, ErrorState, EmptyState } from "@/components/ui/States";

const LEVELS = ["", "debug", "info", "warn", "error"];
const SOURCES = [
  "",
  "nvd_cves",
  "nvd_changes",
  "epss",
  "cisa_kev",
  "cwe",
  "transform",
  "load",
  "consistency",
  "recovery",
  "pipeline",
  "system",
];
const LIMIT = 25;

export function LogsPanel({
  runId,
  onClearRun,
}: {
  runId: string | null;
  onClearRun: () => void;
}) {
  const [level, setLevel] = useState("");
  const [source, setSource] = useState("");
  const [cveId, setCveId] = useState("");
  const [offset, setOffset] = useState(0);

  // Reset paging whenever a filter (including the selected run) changes.
  useEffect(() => setOffset(0), [runId, level, source, cveId]);

  const { data, error, loading, reload } = useApi<Page<LogEntry>>(
    () =>
      apiGet<Page<LogEntry>>("/admin/logs", {
        params: {
          run_id: runId ?? undefined,
          level: level || undefined,
          source: source || undefined,
          cve_id: cveId.trim() || undefined,
          limit: LIMIT,
          offset,
        },
      }),
    [runId, level, source, cveId, offset]
  );

  const total = data?.total ?? 0;
  const showingFrom = total === 0 ? 0 : offset + 1;
  const showingTo = Math.min(offset + LIMIT, total);

  return (
    <Panel
      index="B2"
      title="Pipeline logs"
      right={
        <button className="btn-icon" onClick={reload} aria-label="Refresh logs">
          <RefreshCw size={15} />
        </button>
      }
      noBody
    >
      <div className="panel__body" style={{ paddingBottom: 0 }}>
        <div className="filters">
          <div className="field">
            <label>Level</label>
            <select className="select" value={level} onChange={(e) => setLevel(e.target.value)}>
              {LEVELS.map((l) => (
                <option key={l} value={l}>
                  {l || "all levels"}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Source</label>
            <select className="select" value={source} onChange={(e) => setSource(e.target.value)}>
              {SOURCES.map((s) => (
                <option key={s} value={s}>
                  {s || "all sources"}
                </option>
              ))}
            </select>
          </div>
          <div className="field field--grow">
            <label>CVE ID</label>
            <input
              className="input"
              value={cveId}
              placeholder="CVE-2026-…"
              spellCheck={false}
              onChange={(e) => setCveId(e.target.value)}
            />
          </div>
        </div>

        {runId && (
          <div style={{ marginTop: 14 }}>
            <span className="badge badge--run" style={{ cursor: "pointer" }} onClick={onClearRun}>
              run {runId.slice(0, 8)} <X size={11} style={{ marginLeft: 2 }} />
            </span>
          </div>
        )}
      </div>

      {loading ? (
        <Loading label="Loading logs…" />
      ) : error ? (
        <ErrorState message={error.message} onRetry={reload} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="No log entries" message="No logs match these filters." />
      ) : (
        <>
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Level</th>
                  <th>Source</th>
                  <th>Event</th>
                  <th>CVE</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((log) => (
                  <tr key={log.id}>
                    <td className="num muted" title={fmtTime(log.created_at)}>
                      {fmtAgo(log.created_at)}
                    </td>
                    <td>
                      <LevelBadge value={log.level} />
                    </td>
                    <td className="cve muted">{log.source}</td>
                    <td className="cve">{log.event_type}</td>
                    <td className="cve muted">{log.cve_id ?? "—"}</td>
                    <td className="cell-msg" title={log.message}>
                      {log.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pager">
            <span>
              {showingFrom}–{showingTo} of {total.toLocaleString()}
            </span>
            <div className="pager__btns">
              <button
                className="btn-icon"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                aria-label="Previous page"
              >
                <ChevronLeft size={16} />
              </button>
              <button
                className="btn-icon"
                disabled={offset + LIMIT >= total}
                onClick={() => setOffset(offset + LIMIT)}
                aria-label="Next page"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </>
      )}
    </Panel>
  );
}
