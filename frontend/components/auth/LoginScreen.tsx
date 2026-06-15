"use client";

import { useState } from "react";
import { Eye, EyeOff, ShieldAlert, ShieldCheck, Radar } from "lucide-react";
import { useAuth } from "./AuthProvider";
import { ApiError } from "@/lib/api";

export function LoginScreen() {
  const { login } = useAuth();
  const [key, setKey] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = key.trim().length > 0 && !busy;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      await login(key);
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.status === 401
            ? "That access key was rejected. Check it and try again."
            : err.message
          : "Unexpected error during sign-in.";
      setError(msg);
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="login__card reveal" onSubmit={onSubmit}>
        <div className="login__top">
          <span className="brand__mark">
            <Radar size={18} />
          </span>
          <div>
            <div className="brand__name display">CVE WATCHDOG</div>
            <div className="brand__sub">Threat Intelligence Console</div>
          </div>
        </div>

        <div className="login__body">
          <p className="login__intro">
            Enter your access key to connect. An <strong>admin</strong> key unlocks
            the full console; a <strong>user</strong> key unlocks the CVE
            dashboards. The key is held only for this browser tab.
          </p>

          {error && (
            <div className="login__err" role="alert">
              <ShieldAlert />
              <span>{error}</span>
            </div>
          )}

          <div className="field">
            <label>Access key</label>
            <div className="input-key">
              <input
                className="input"
                type={show ? "text" : "password"}
                value={key}
                autoFocus
                spellCheck={false}
                autoComplete="off"
                placeholder="X-API-Key"
                onChange={(e) => setKey(e.target.value)}
              />
              <button
                type="button"
                aria-label={show ? "Hide key" : "Show key"}
                onClick={() => setShow((s) => !s)}
              >
                {show ? <EyeOff /> : <Eye />}
              </button>
            </div>
          </div>

          <button className="btn btn--primary" type="submit" disabled={!canSubmit}>
            {busy ? (
              <>
                <span className="spinner" style={{ width: 15, height: 15 }} />
                Verifying…
              </>
            ) : (
              <>
                <ShieldCheck size={16} />
                Connect
              </>
            )}
          </button>

          <p className="login__note">
            KEY · sessionStorage only · cleared on tab close · sent as X-API-Key
            over the wire · never persisted to disk
          </p>
        </div>
      </form>
    </div>
  );
}
