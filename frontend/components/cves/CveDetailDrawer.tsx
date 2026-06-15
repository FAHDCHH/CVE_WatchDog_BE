"use client";

import { useEffect } from "react";
import { ExternalLink, ShieldAlert, X } from "lucide-react";
import { apiGet } from "@/lib/api";
import { CveDetail } from "@/lib/types";
import { useApi } from "@/lib/hooks";
import { fmtDate, fmtDateTime, daysUntil, severityClass } from "@/lib/format";
import { decodeCvssVector } from "@/lib/cvss";
import { cweName } from "@/lib/cwe";
import { SeverityBadge } from "@/components/ui/Badge";
import { Loading, ErrorState } from "@/components/ui/States";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  );
}

function refLinks(refs: unknown): string[] {
  if (!Array.isArray(refs)) return [];
  const out: string[] = [];
  for (const r of refs) {
    if (typeof r === "string") out.push(r);
    else if (r && typeof r === "object" && "url" in r && typeof r.url === "string")
      out.push(r.url);
  }
  return out.slice(0, 25);
}

function hostOf(url: string): { host: string; path: string } {
  try {
    const u = new URL(url);
    return { host: u.hostname.replace(/^www\./, ""), path: (u.pathname + u.search) || "/" };
  } catch {
    return { host: url, path: "" };
  }
}

export function CveDetailDrawer({
  cveId,
  onClose,
}: {
  cveId: string;
  onClose: () => void;
}) {
  const { data, error, loading, reload } = useApi<CveDetail>(
    () => apiGet<CveDetail>(`/cves/${encodeURIComponent(cveId)}`),
    [cveId]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const refs = data ? refLinks(data.references) : [];
  const vector = data ? decodeCvssVector(data.cvss_vector) : [];
  const subtitle =
    data?.kev_vulnerability_name ||
    (data?.cwe_ids && data.cwe_ids.length ? cweName(data.cwe_ids[0]) : null);

  // KEV due-date urgency.
  let dueClass = "u--ok";
  let dueText = "";
  if (data?.kev_due_date) {
    const d = daysUntil(data.kev_due_date);
    if (d !== null) {
      if (d < 0) { dueClass = "u--over"; dueText = `${Math.abs(d)}d overdue`; }
      else if (d <= 3) { dueClass = "u--soon"; dueText = `in ${d}d`; }
      else { dueClass = "u--ok"; dueText = `in ${d}d`; }
    }
  }

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Details for ${cveId}`}>
        <div className="drawer__head">
          <div style={{ minWidth: 0 }}>
            <div className="drawer__id display">{cveId}</div>
            {data && subtitle && <div className="drawer__sub">{subtitle}</div>}
            {data && (
              <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                <SeverityBadge value={data.cvss_severity} />
                {data.is_kev && (
                  <span className="badge badge--fail">
                    <ShieldAlert size={11} /> KEV
                  </span>
                )}
                {data.ransomware_known === "Known" && (
                  <span className="badge badge--high">Ransomware</span>
                )}
              </div>
            )}
          </div>
          <button className="btn-icon" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        <div className="drawer__body">
          {loading ? (
            <Loading label="Loading CVE…" />
          ) : error ? (
            <ErrorState message={error.message} onRetry={reload} />
          ) : !data ? null : (
            <>
              {data.description_en && (
                <div className="dsec">
                  <span className="dsec__title">Description</span>
                  <p className="desc desc-block">{data.description_en}</p>
                </div>
              )}

              {/* risk scores */}
              <div className="dsec">
                <span className="dsec__title">Risk scores</span>
                <div className="score-grid">
                  <div
                    className="scorecard"
                    style={{ ["--tone" as string]: `var(--${severityClass(data.cvss_severity)})` }}
                  >
                    <div className="l">CVSS base</div>
                    <div className="v">{data.cvss_score ?? "—"}</div>
                    <div className="sub">
                      {data.cvss_severity ?? "—"}
                      {data.cvss_version ? ` · v${data.cvss_version}` : ""}
                    </div>
                  </div>
                  <div className="scorecard" style={{ ["--tone" as string]: "var(--cyan)" }}>
                    <div className="l">EPSS</div>
                    <div className="v">
                      {data.epss_score !== null ? `${(data.epss_score * 100).toFixed(1)}%` : "—"}
                    </div>
                    <div className="sub">30-day exploit prob.</div>
                  </div>
                  <div className="scorecard" style={{ ["--tone" as string]: "var(--cyan)" }}>
                    <div className="l">EPSS percentile</div>
                    <div className="v">
                      {data.epss_percentile !== null
                        ? `${(data.epss_percentile * 100).toFixed(0)}%`
                        : "—"}
                    </div>
                    {data.epss_percentile !== null && (
                      <div className="meter">
                        <div
                          className="meter__fill"
                          style={{ width: `${(data.epss_percentile * 100).toFixed(0)}%` }}
                        />
                      </div>
                    )}
                    <div className="sub">vs. all CVEs</div>
                  </div>
                </div>
              </div>

              {/* cvss metrics */}
              {(vector.length > 0 || data.attack_vector) && (
                <div className="dsec">
                  <span className="dsec__title">CVSS metrics</span>
                  {vector.length > 0 ? (
                    <div className="vec-grid">
                      {vector.map((m) => (
                        <div className="vec-pill" key={m.code} data-danger={m.danger}>
                          <div className="pl">{m.label}</div>
                          <div className="pv">{m.value}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <dl className="kv">
                      <Row label="Attack vector" value={data.attack_vector} />
                      <Row label="Complexity" value={data.attack_complexity} />
                      <Row label="Privileges req." value={data.privileges_required} />
                      <Row label="User interaction" value={data.user_interaction} />
                    </dl>
                  )}
                  {data.cvss_vector && <div className="code-line">{data.cvss_vector}</div>}
                  {(data.exploitability_score !== null || data.impact_score !== null) && (
                    <div className="sub" style={{ color: "var(--text-faint)", fontSize: 11 }}>
                      Exploitability {data.exploitability_score ?? "—"} · Impact{" "}
                      {data.impact_score ?? "—"} · Source {data.cvss_type ?? "—"}
                    </div>
                  )}
                </div>
              )}

              {/* KEV alert */}
              {data.is_kev && (
                <div className="dsec">
                  <span className="dsec__title">Known exploited</span>
                  <div className="kev-card">
                    <div className="kev-card__top">
                      <ShieldAlert />
                      <span className="t">Actively exploited in the wild</span>
                    </div>
                    {data.kev_vulnerability_name && (
                      <div className="name">{data.kev_vulnerability_name}</div>
                    )}
                    <dl className="kv">
                      <Row
                        label="Vendor / Product"
                        value={
                          [data.kev_vendor_project, data.kev_product].filter(Boolean).join(" · ") ||
                          null
                        }
                      />
                      <Row label="Ransomware" value={data.ransomware_known} />
                    </dl>
                    <div className="kev-dates">
                      <div className="kev-date">
                        <div className="l">Added to KEV</div>
                        <div className="v">{fmtDate(data.kev_date_added)}</div>
                      </div>
                      <div className="kev-date">
                        <div className="l">Remediation due</div>
                        <div className="v">{fmtDate(data.kev_due_date)}</div>
                        {dueText && <div className={`u ${dueClass}`}>{dueText}</div>}
                      </div>
                    </div>
                    {data.kev_required_action && (
                      <div className="callout">
                        <div className="l">Required action</div>
                        <p>{data.kev_required_action}</p>
                      </div>
                    )}
                    {data.kev_short_description && (
                      <p className="desc" style={{ fontSize: 12.5 }}>
                        {data.kev_short_description}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* weaknesses */}
              {data.cwe_ids && data.cwe_ids.length > 0 && (
                <div className="dsec">
                  <span className="dsec__title">Weaknesses (CWE)</span>
                  <div className="cwe-list">
                    {data.cwe_ids.map((id) => (
                      <span key={id} className="badge badge--info" title={id}>
                        {cweName(id)} · {id}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* references */}
              {refs.length > 0 && (
                <div className="dsec">
                  <span className="dsec__title">References</span>
                  <div className="reflist">
                    {refs.map((url) => {
                      const { host, path } = hostOf(url);
                      return (
                        <a
                          key={url}
                          className="reflink"
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <ExternalLink />
                          <span className="reftext">
                            <span className="host">{host}</span>
                            {path && <span className="path">{path}</span>}
                          </span>
                        </a>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* lifecycle */}
              <div className="dsec">
                <span className="dsec__title">Lifecycle</span>
                <dl className="kv">
                  <Row label="Status" value={data.vuln_status} />
                  <Row label="Published" value={fmtDateTime(data.published_at)} />
                  <Row label="Last modified" value={fmtDateTime(data.last_modified_at)} />
                  <Row label="First seen" value={fmtDateTime(data.first_seen_at)} />
                  <Row label="Source id" value={data.source_identifier} />
                </dl>
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
}
