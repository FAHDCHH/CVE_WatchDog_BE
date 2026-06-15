import { levelClass, severityClass, statusClass } from "@/lib/format";

export function Badge({
  variant,
  children,
}: {
  variant: string;
  children: React.ReactNode;
}) {
  return <span className={`badge badge--${variant}`}>{children}</span>;
}

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="badge badge--none">N/A</span>;
  return <Badge variant={severityClass(value)}>{value}</Badge>;
}

export function StatusBadge({ value }: { value: string }) {
  return <Badge variant={statusClass(value)}>{value.replace(/_/g, " ")}</Badge>;
}

export function LevelBadge({ value }: { value: string }) {
  return <Badge variant={levelClass(value)}>{value}</Badge>;
}
