"use client";

import { LucideIcon } from "lucide-react";
import { fmtInt } from "@/lib/format";
import { useCountUp } from "@/lib/hooks";

export function KpiCard({
  label,
  value,
  icon: Icon,
  meta,
  variant,
  spark,
  delay = 0,
}: {
  label: string;
  value: number;
  icon: LucideIcon;
  meta?: string;
  variant?: "alert" | "warn";
  spark?: string;
  delay?: number;
}) {
  const animated = useCountUp(value);
  return (
    <div
      className={`panel kpi reveal ${variant ? `kpi--${variant}` : ""}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="kpi__label">
        <span className="kpi__icon">
          <Icon />
        </span>
        {label}
      </div>
      <div className="kpi__value">{fmtInt(animated)}</div>
      {meta && <div className="kpi__meta">{meta}</div>}
      {spark && <span className="kpi__spark display">{spark}</span>}
    </div>
  );
}
