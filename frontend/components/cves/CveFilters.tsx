"use client";

import { useState } from "react";
import { ArrowDown, ArrowUp, RotateCcw, Search, SlidersHorizontal } from "lucide-react";
import { FilterOptions } from "@/lib/types";
import {
  CveFiltersState,
  SEVERITIES,
  SORT_FIELDS,
  activeAdvancedCount,
} from "@/lib/cveFilters";
import { severityColor } from "@/lib/format";

function FilterSelect({
  label,
  value,
  onChangeVal,
  opts,
}: {
  label: string;
  value: string;
  onChangeVal: (v: string) => void;
  opts: string[] | undefined;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      <select className="select" value={value} onChange={(e) => onChangeVal(e.target.value)}>
        <option value="">any</option>
        {(opts ?? []).map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </div>
  );
}

export function CveFilters({
  filters,
  onChange,
  onReset,
  options,
}: {
  filters: CveFiltersState;
  onChange: (next: CveFiltersState) => void;
  onReset: () => void;
  options: FilterOptions | null;
}) {
  const [open, setOpen] = useState(false);
  const advCount = activeAdvancedCount(filters);
  const set = (patch: Partial<CveFiltersState>) => onChange({ ...filters, ...patch });

  const toggleSeverity = (s: string) =>
    set({
      severity: filters.severity.includes(s)
        ? filters.severity.filter((x) => x !== s)
        : [...filters.severity, s],
    });

  return (
    <section className="panel">
      <div className="panel__body toolbar">
        {/* primary row */}
        <div className="toolbar__row">
          <div className="search">
            <Search />
            <input
              className="input"
              placeholder="Search CVE id or description…"
              value={filters.q}
              onChange={(e) => set({ q: e.target.value })}
            />
          </div>

          <div className="field">
            <label>Sort by</label>
            <select
              className="select"
              value={filters.sort}
              onChange={(e) => set({ sort: e.target.value })}
            >
              {SORT_FIELDS.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label>Order</label>
            <button
              className="btn"
              onClick={() => set({ order: filters.order === "desc" ? "asc" : "desc" })}
              title="Toggle sort order"
            >
              {filters.order === "desc" ? <ArrowDown size={15} /> : <ArrowUp size={15} />}
              {filters.order === "desc" ? "Desc" : "Asc"}
            </button>
          </div>

          <button
            className="btn btn--ghost"
            data-on={open}
            onClick={() => setOpen((o) => !o)}
          >
            <SlidersHorizontal size={15} />
            Advanced{advCount ? ` (${advCount})` : ""}
          </button>

          <button className="btn btn--ghost" onClick={onReset} title="Clear all filters">
            <RotateCcw size={14} />
            Reset
          </button>
        </div>

        {/* severity + kev row */}
        <div className="toolbar__row">
          <div className="field" style={{ flex: 1 }}>
            <label>Severity</label>
            <div className="chips">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  className="chip-toggle"
                  data-on={filters.severity.includes(s)}
                  style={{ ["--dot" as string]: severityColor(s) }}
                  onClick={() => toggleSeverity(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="field">
            <label>KEV</label>
            <div className="seg" role="group" aria-label="KEV filter">
              {(
                [
                  ["all", "All"],
                  ["kev", "KEV only"],
                  ["nonkev", "Non-KEV"],
                ] as const
              ).map(([val, lbl]) => (
                <button
                  key={val}
                  data-on={filters.kev === val}
                  onClick={() => set({ kev: val })}
                >
                  {lbl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* advanced */}
        {open && (
          <div className="adv">
            <div className="field">
              <label>CVSS score</label>
              <div className="range">
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={10}
                  step={0.1}
                  placeholder="min"
                  value={filters.cvssMin}
                  onChange={(e) => set({ cvssMin: e.target.value })}
                />
                <span>–</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={10}
                  step={0.1}
                  placeholder="max"
                  value={filters.cvssMax}
                  onChange={(e) => set({ cvssMax: e.target.value })}
                />
              </div>
            </div>

            <div className="field">
              <label>EPSS percentile</label>
              <div className="range">
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={1}
                  step={0.01}
                  placeholder="0.0"
                  value={filters.epssPctMin}
                  onChange={(e) => set({ epssPctMin: e.target.value })}
                />
                <span>–</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={1}
                  step={0.01}
                  placeholder="1.0"
                  value={filters.epssPctMax}
                  onChange={(e) => set({ epssPctMax: e.target.value })}
                />
              </div>
            </div>

            <FilterSelect
              label="Status"
              value={filters.vulnStatus}
              onChangeVal={(v) => set({ vulnStatus: v })}
              opts={options?.vuln_status}
            />
            <FilterSelect
              label="Attack vector"
              value={filters.attackVector}
              onChangeVal={(v) => set({ attackVector: v })}
              opts={options?.attack_vector}
            />
            <FilterSelect
              label="Exploit maturity"
              value={filters.exploitMaturity}
              onChangeVal={(v) => set({ exploitMaturity: v })}
              opts={options?.exploit_maturity}
            />
            <FilterSelect
              label="Ransomware"
              value={filters.ransomware}
              onChangeVal={(v) => set({ ransomware: v })}
              opts={options?.ransomware_known}
            />

            <div className="field">
              <label>CWE id</label>
              <input
                className="input"
                placeholder="CWE-79"
                value={filters.cweId}
                onChange={(e) => set({ cweId: e.target.value })}
              />
            </div>
            <div className="field">
              <label>Vendor</label>
              <input
                className="input"
                placeholder="e.g. microsoft"
                value={filters.vendor}
                onChange={(e) => set({ vendor: e.target.value })}
              />
            </div>
            <div className="field">
              <label>Product</label>
              <input
                className="input"
                placeholder="e.g. windows"
                value={filters.product}
                onChange={(e) => set({ product: e.target.value })}
              />
            </div>

            <div className="field">
              <label>Published</label>
              <div className="range">
                <input
                  className="input"
                  type="date"
                  value={filters.publishedFrom}
                  onChange={(e) => set({ publishedFrom: e.target.value })}
                />
                <span>→</span>
                <input
                  className="input"
                  type="date"
                  value={filters.publishedTo}
                  onChange={(e) => set({ publishedTo: e.target.value })}
                />
              </div>
            </div>
            <div className="field">
              <label>Modified</label>
              <div className="range">
                <input
                  className="input"
                  type="date"
                  value={filters.modifiedFrom}
                  onChange={(e) => set({ modifiedFrom: e.target.value })}
                />
                <span>→</span>
                <input
                  className="input"
                  type="date"
                  value={filters.modifiedTo}
                  onChange={(e) => set({ modifiedTo: e.target.value })}
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
