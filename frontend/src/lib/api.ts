import type { Scan } from "../types";

const rawBase = import.meta.env.VITE_API_URL || "http://localhost:8000/api";
const cleanBase = rawBase.replace(/\/+$/, "");
const BASE = cleanBase.endsWith("/api") ? cleanBase : `${cleanBase}/api`;

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("lg_access");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    // Non-JSON response
  }

  if (!res.ok) {
    const errorMsg =
      (body.detail as string) ||
      (text ? text.slice(0, 150) : `Request failed (${res.status})`);
    throw new Error(errorMsg);
  }

  return body as unknown as T;
}

export const api = {
  async scan(url: string): Promise<Scan> {
    return handle(
      await fetch(`${BASE}/scans/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ url }),
      })
    );
  },
  async history(params: Record<string, string> = {}): Promise<Scan[]> {
    const qs = new URLSearchParams(params).toString();
    return handle(
      await fetch(`${BASE}/scans/history/?${qs}`, {
        headers: authHeader(),
      })
    );
  },
  async getScan(id: string): Promise<Scan> {
    return handle(
      await fetch(`${BASE}/scans/${id}/`, {
        headers: authHeader(),
      })
    );
  },
  async login(username: string, password: string) {
    const data = await handle<{ access: string; refresh: string }>(
      await fetch(`${BASE}/auth/token/`, {
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

