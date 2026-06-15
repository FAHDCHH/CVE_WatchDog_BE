"use client";

import { useState } from "react";
import { RunsTable } from "@/components/ops/RunsTable";
import { LogsPanel } from "@/components/ops/LogsPanel";

export default function OpsPage() {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  return (
    <>
      <span className="eyebrow">Pipeline observability · elt_runs + pipeline_logs</span>
      <RunsTable selectedRunId={selectedRunId} onSelectRun={setSelectedRunId} />
      <LogsPanel runId={selectedRunId} onClearRun={() => setSelectedRunId(null)} />
    </>
  );
}
