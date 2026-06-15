"use client";

export function Topbar({
  eyebrow,
  title,
  right,
}: {
  eyebrow: string;
  title: string;
  right?: React.ReactNode;
}) {
  return (
    <header className="topbar">
      <div className="topbar__title">
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {right}
        <span className="chip" title="Connected to the dashboard API">
          <span className="dot dot--amber dot--live" />
          API LINKED
        </span>
      </div>
    </header>
  );
}
