import { Inbox, TriangleAlert } from "lucide-react";

export function Loading({ label = "Fetching telemetry…" }: { label?: string }) {
  return (
    <div className="state">
      <span className="spinner" />
      <span className="state__msg">{label}</span>
    </div>
  );
}

export function ErrorState({
  title = "Request failed",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state state--error" role="alert">
      <TriangleAlert />
      <span className="state__title">{title}</span>
      <span className="state__msg">{message}</span>
      {onRetry && (
        <button className="btn btn--ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title = "Nothing here",
  message = "No records match the current view.",
}: {
  title?: string;
  message?: string;
}) {
  return (
    <div className="state">
      <Inbox />
      <span className="state__title">{title}</span>
      <span className="state__msg">{message}</span>
    </div>
  );
}
