"use client";

import { useEffect, useState } from "react";
import { Bucket } from "@/lib/types";
import { fmtInt } from "@/lib/format";
import { EmptyState } from "@/components/ui/States";

export function BarList({
  items,
  variant = "amber",
  max,
}: {
  items: Bucket[];
  variant?: "amber" | "cyan";
  max?: number;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const r = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(r);
  }, []);

  if (!items.length) return <EmptyState message="No data for this dimension." />;

  const peak = max ?? Math.max(...items.map((i) => i.count), 1);
  const fillClass = variant === "cyan" ? "bar__fill bar__fill--cyan" : "bar__fill";

  return (
    <div className="bars">
      {items.map((it) => {
        const pct = peak > 0 ? (it.count / peak) * 100 : 0;
        return (
          <div className="bar" key={it.key}>
            <span className="bar__key" title={it.key}>
              {it.key}
            </span>
            <span className="bar__val">{fmtInt(it.count)}</span>
            <div className="bar__track">
              <div
                className={fillClass}
                style={{ width: mounted ? `${Math.max(pct, 2)}%` : "0%" }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
