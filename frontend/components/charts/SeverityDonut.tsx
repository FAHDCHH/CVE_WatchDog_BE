"use client";

import { Bucket } from "@/lib/types";
import { fmtInt, severityColor, severityRank } from "@/lib/format";
import { useCountUp } from "@/lib/hooks";

const R = 52;
const CIRC = 2 * Math.PI * R;

export function SeverityDonut({ buckets }: { buckets: Bucket[] }) {
  const data = [...buckets].sort((a, b) => severityRank(a.key) - severityRank(b.key));
  const total = data.reduce((s, b) => s + b.count, 0);
  const totalUp = useCountUp(total);

  let cumulative = 0;
  const segments = data.map((b) => {
    const frac = total > 0 ? b.count / total : 0;
    const dash = frac * CIRC;
    const seg = {
      key: b.key,
      count: b.count,
      color: severityColor(b.key),
      dash,
      offset: -cumulative,
      pct: total > 0 ? (frac * 100).toFixed(1) : "0.0",
    };
    cumulative += dash;
    return seg;
  });

  return (
    <div className="donut-wrap">
      <div className="donut" role="img" aria-label="CVE count by CVSS severity">
        <svg viewBox="0 0 120 120">
          <circle
            cx="60"
            cy="60"
            r={R}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="14"
          />
          {total > 0 &&
            segments.map((s) => (
              <circle
                key={s.key}
                className="donut__seg"
                cx="60"
                cy="60"
                r={R}
                fill="none"
                stroke={s.color}
                strokeWidth="14"
                strokeDasharray={`${s.dash} ${CIRC - s.dash}`}
                strokeDashoffset={s.offset}
              />
            ))}
        </svg>
        <div className="donut__center">
          <span className="n display">{fmtInt(totalUp)}</span>
          <span className="l">Tracked</span>
        </div>
      </div>

      <div className="legend">
        {segments.map((s) => (
          <div className="legend__row" key={s.key}>
            <span className="swatch" style={{ background: s.color }} />
            <span className="k">{s.key}</span>
            <span className="v">{fmtInt(s.count)}</span>
            <span className="p">{s.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
