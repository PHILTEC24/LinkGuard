import type { Scan } from "../types";

export function getApiBaseUrl(): string {
  const custom = typeof window !== "undefined" ? localStorage.getItem("lg_backend_url") : null;
  if (custom && custom.trim()) {
    const c = custom.trim().replace(/\/+$/, "");
    return c.endsWith("/api") ? c : `${c}/api`;
  }
  const envUrl = import.meta.env.VITE_API_URL;
  if (envUrl && envUrl.trim() && !envUrl.includes("localhost")) {
    const e = envUrl.trim().replace(/\/+$/, "");
    return e.endsWith("/api") ? e : `${e}/api`;
  }
  if (typeof window !== "undefined" && window.location.protocol === "https:") {
    return `${window.location.origin}/api`;
  }
  return "http://localhost:8000/api";
}

export function setApiBaseUrl(url: string) {
  if (typeof window !== "undefined") {
    localStorage.setItem("lg_backend_url", url.trim());
  }
}

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("lg_access");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  const text = await res.text();
  let body: any = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    // Response was not JSON (e.g. HTML 404/502 error or empty response)
  }

  if (!res.ok) {
    const errorMsg =
      body.detail ||
      (text && !text.startsWith("<!")
        ? text.slice(0, 150)
        : `API request failed (${res.status} ${res.statusText || ""}). Please verify backend is live.`);
    throw new Error(errorMsg);
  }
  return body as T;
}

export const api = {
  async scan(url: string): Promise<Scan> {
    const base = getApiBaseUrl();
    return handle(
      await fetch(`${base}/scans/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ url }),
      })
    );
  },
  async history(params: Record<string, string> = {}): Promise<Scan[]> {
    const base = getApiBaseUrl();
    const qs = new URLSearchParams(params).toString();
    return handle(
      await fetch(`${base}/scans/history/?${qs}`, {
        headers: authHeader(),
      })
    );
  },
  async getScan(id: string): Promise<Scan> {
    const base = getApiBaseUrl();
    return handle(
      await fetch(`${base}/scans/${id}/`, {
        headers: authHeader(),
      })
    );
  },
  async login(username: string, password: string) {
    const base = getApiBaseUrl();
    const data = await handle<{ access: string; refresh: string }>(
      await fetch(`${base}/auth/token/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
    );
    localStorage.setItem("lg_access", data.access);
    localStorage.setItem("lg_refresh", data.refresh);
    return data;
  },
  logout() {
    localStorage.removeItem("lg_access");
    localStorage.removeItem("lg_refresh");
  },
};
