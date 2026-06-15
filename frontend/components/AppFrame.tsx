"use client";

import { usePathname } from "next/navigation";
import { Lock, Radar } from "lucide-react";
import { AuthProvider, useAuth } from "@/components/auth/AuthProvider";
import { LoginScreen } from "@/components/auth/LoginScreen";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";

const TITLES: Record<string, { eyebrow: string; title: string }> = {
  "/": { eyebrow: "01 / Surveillance", title: "Overview" },
  "/cves": { eyebrow: "02 / Catalogue", title: "CVE Explorer" },
  "/ops": { eyebrow: "03 / Operations", title: "Pipeline Ops" },
};

function AdminOnly() {
  return (
    <div className="state state--error" style={{ minHeight: "50vh" }}>
      <Lock />
      <span className="state__title">Admin access required</span>
      <span className="state__msg">
        Pipeline Ops is restricted to admin keys. Your current key grants access to
        the CVE dashboards only.
      </span>
    </div>
  );
}

function Gate({ children }: { children: React.ReactNode }) {
  const { ready, authed, role } = useAuth();
  const pathname = usePathname();

  // Before hydration settles, show a quiet boot splash (avoids SSR mismatch).
  if (!ready) {
    return (
      <div className="boot">
        <span className="brand__mark" style={{ width: 44, height: 44 }}>
          <Radar size={22} />
        </span>
      </div>
    );
  }

  if (!authed) return <LoginScreen />;

  const meta = TITLES[pathname] ?? { eyebrow: "", title: "Console" };
  const adminRoute = pathname.startsWith("/ops");
  const blocked = adminRoute && role !== "admin";

  return (
    <div className="shell">
      <Sidebar />
      <div className="main">
        <Topbar eyebrow={meta.eyebrow} title={meta.title} />
        <div className="content">{blocked ? <AdminOnly /> : children}</div>
      </div>
    </div>
  );
}

export function AppFrame({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <Gate>{children}</Gate>
    </AuthProvider>
  );
}
