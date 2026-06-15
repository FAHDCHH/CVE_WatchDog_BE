"use client";

import { Boxes, Crosshair, RefreshCw, Skull } from "lucide-react";
import { apiGet } from "@/lib/api";
import { DashboardStats } from "@/lib/types";
import { useApi } from "@/lib/hooks";
import { cweLabel } from "@/lib/cwe";
import { Panel } from "@/components/ui/Panel";
import { KpiCard } from "@/components/ui/KpiCard";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { BarList } from "@/components/charts/BarList";
import { Loading, ErrorState } from "@/components/ui/States";

export default function OverviewPage() {
  const { data, error, loading, reload } = useApi<DashboardStats>(
    () => apiGet<DashboardStats>("/stats"),
    []
  );

  if (loading) return <Loading label="Loading enriched CVE snapshot…" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  const epss = [...data.epss_buckets].sort((a, b) => b.key.localeCompare(a.key));
  const topCwes = data.top_cwes.map((b) => ({ key: cweLabel(b.key), count: b.count }));
  const kevPct =
    data.total_cves > 0
      ? ((data.kev_count / data.total_cves) * 100).toFixed(1)
      : "0.0";

  return (
    <>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
        }}
      >
        <span className="eyebrow">Live snapshot · enriched_cve store</span>
        <button className="btn btn--ghost" onClick={reload}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* KPI row */}
      <div className="grid grid--kpi">
        <KpiCard
          label="Total CVEs tracked"
          value={data.total_cves}
          icon={Boxes}
          meta="enriched records in store"
          spark="∑"
          delay={0}
        />
        <KpiCard
          label="Known Exploited (KEV)"
          value={data.kev_count}
          icon={Crosshair}
          meta={`${kevPct}% of tracked · CISA catalog`}
          variant="alert"
          spark="!"
          delay={80}
        />
        <KpiCard
          label="Ransomware-linked"
          value={data.ransomware_count}
          icon={Skull}
          meta="flagged in KEV ransomware column"
          variant="warn"
          spark="☣"
          delay={160}
        />
      </div>

      {/* severity + status */}
      <div className="grid grid--split">
        <Panel index="A1" title="Severity distribution">
          <SeverityDonut buckets={data.by_severity} />
        </Panel>
        <Panel index="A2" title="Vulnerability status">
          <BarList items={data.by_status} variant="cyan" />
        </Panel>
      </div>

      {/* attack vector + epss */}
      <div className="grid grid--bars">
        <Panel index="A3" title="Attack vector">
          <BarList items={data.by_attack_vector} />
        </Panel>
        <Panel index="A4" title="EPSS percentile bands">
          <BarList items={epss} variant="cyan" />
        </Panel>
      </div>

      {/* top cwes */}
      <Panel index="A5" title="Top weaknesses (CWE)">
        <BarList items={topCwes} />
      </Panel>
    </>
  );
}
