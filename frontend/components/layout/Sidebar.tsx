"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, LayoutDashboard, ListFilter, LogOut, Radar } from "lucide-react";
import { useAuth } from "@/components/auth/AuthProvider";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard, adminOnly: false },
  { href: "/cves", label: "CVE Explorer", icon: ListFilter, adminOnly: false },
  { href: "/ops", label: "Pipeline Ops", icon: Activity, adminOnly: true },
];

export function Sidebar() {
  const pathname = usePathname();
  const { logout, role } = useAuth();
  const items = NAV.filter((n) => !n.adminOnly || role === "admin");

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand__mark">
          <Radar size={18} />
        </span>
        <div>
          <div className="brand__name display">WATCHDOG</div>
          <div className="brand__sub">CVE Console</div>
        </div>
      </div>

      <nav className="nav" aria-label="Primary">
        <span className="nav__label">Sections</span>
        {items.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className="nav-item"
              data-active={active}
              aria-current={active ? "page" : undefined}
            >
              <Icon />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="sidebar__foot">
        <div className="chip">
          <span className={`dot dot--live ${role === "admin" ? "dot--amber" : ""}`} />
          {role === "admin" ? "ADMIN ACCESS" : "ANALYST ACCESS"}
        </div>
        <button className="btn btn--ghost" onClick={logout}>
          <LogOut size={15} />
          Lock session
        </button>
      </div>
    </aside>
  );
}
