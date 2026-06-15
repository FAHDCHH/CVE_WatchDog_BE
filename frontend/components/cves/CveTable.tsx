"use client";

import { ShieldAlert } from "lucide-react";
import { CveSummary } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/Badge";
import { fmtDateTime } from "@/lib/format";

function pct(v: number | null): string {
  return v === null || v === undefined ? "—" : `${(v * 100).toFixed(1)}%`;
}

export function CveTable({
  items,
  selectedId,
  onSelect,
}: {
  items: CveSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table className="t">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>EPSS pct</th>
            <th>KEV</th>
            <th>Status</th>
            <th>Published</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr
              key={c.cve_id}
              data-clickable="true"
              data-active={c.cve_id === selectedId}
              onClick={() => onSelect(c.cve_id)}
            >
              <td className="cve">{c.cve_id}</td>
              <td>
                <SeverityBadge value={c.cvss_severity} />
              </td>
              <td className="num">{c.cvss_score ?? "—"}</td>
              <td className="num">{pct(c.epss_percentile)}</td>
              <td>
                {c.is_kev ? (
                  <span className="badge badge--fail">
                    <ShieldAlert size={11} /> KEV
                  </span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td className="muted">{c.vuln_status ?? "—"}</td>
              <td className="num muted">{fmtDateTime(c.published_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
