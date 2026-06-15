"use client";

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { apiGet } from "@/lib/api";
import { CveSummary, FilterOptions, Page } from "@/lib/types";
import { useApi, useDebounced } from "@/lib/hooks";
import { CveFiltersState, DEFAULT_FILTERS, buildParams } from "@/lib/cveFilters";
import { CveFilters } from "@/components/cves/CveFilters";
import { CveTable } from "@/components/cves/CveTable";
import { CveDetailDrawer } from "@/components/cves/CveDetailDrawer";
import { Panel } from "@/components/ui/Panel";
import { Loading, ErrorState, EmptyState } from "@/components/ui/States";

const LIMIT = 25;

export default function CvesPage() {
  const [filters, setFilters] = useState<CveFiltersState>(DEFAULT_FILTERS);
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const debounced = useDebounced(filters, 300);
  const filterKey = JSON.stringify(debounced);

  // New filter criteria -> back to the first page.
  useEffect(() => setOffset(0), [filterKey]);

  // Dropdown option values for the advanced filters.
  const meta = useApi<FilterOptions>(() => apiGet<FilterOptions>("/meta/filters"), []);

  const { data, error, loading, reload } = useApi<Page<CveSummary>>(
    () => apiGet<Page<CveSummary>>("/cves", { params: buildParams(debounced, LIMIT, offset) }),
    [filterKey, offset]
  );

  const total = data?.total ?? 0;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + LIMIT, total);

  return (
    <>
      <span className="eyebrow">Catalogue · {total.toLocaleString()} matching records</span>

      <CveFilters
        filters={filters}
        onChange={setFilters}
        onReset={() => setFilters(DEFAULT_FILTERS)}
        options={meta.data}
      />

      <Panel
        index="C1"
        title="Results"
        right={<span className="eyebrow">{from}–{to} of {total.toLocaleString()}</span>}
        noBody
      >
        {loading ? (
          <Loading label="Querying CVEs…" />
        ) : error ? (
          <ErrorState message={error.message} onRetry={reload} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No matches"
            message="No CVEs match the current filters. Try widening or resetting them."
          />
        ) : (
          <>
            <CveTable items={data.items} selectedId={selectedId} onSelect={setSelectedId} />
            <div className="pager">
              <span>
                {from}–{to} of {total.toLocaleString()}
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

      {selectedId && (
        <CveDetailDrawer cveId={selectedId} onClose={() => setSelectedId(null)} />
      )}
    </>
  );
}
