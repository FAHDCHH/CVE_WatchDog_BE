"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { apiGet, ApiError, AUTH_EXPIRED_EVENT } from "@/lib/api";
import { Role, clearAuth, getRole, hasAuth, setAuth } from "@/lib/auth";

interface AuthCtx {
  ready: boolean; // hydration settled (sessionStorage read)
  authed: boolean;
  role: Role | null;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [role, setRole] = useState<Role | null>(null);

  // Read sessionStorage only after mount to avoid SSR/client mismatch.
  useEffect(() => {
    setAuthed(hasAuth());
    setRole(getRole());
    setReady(true);
  }, []);

  // A mid-session 401 (key revoked / server restart) bounces us to login.
  useEffect(() => {
    const onExpired = () => {
      setAuthed(false);
      setRole(null);
    };
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired);
  }, []);

  const login = useCallback(async (key: string) => {
    const k = key.trim();
    // 1. Must be a valid key for the data surface (throws 401 if not).
    await apiGet("/stats", { key: k });
    // 2. Resolve the role: an admin key also satisfies an admin endpoint.
    let resolved: Role = "user";
    try {
      await apiGet("/admin/runs", { params: { limit: 1 }, key: k });
      resolved = "admin";
    } catch (err) {
      if (!(err instanceof ApiError && (err.status === 401 || err.status === 503))) {
        throw err; // network/server error — surface it
      }
    }
    setAuth(k, resolved);
    setRole(resolved);
    setAuthed(true);
  }, []);

  const logout = useCallback(() => {
    clearAuth();
    setAuthed(false);
    setRole(null);
  }, []);

  return (
    <Ctx.Provider value={{ ready, authed, role, login, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
