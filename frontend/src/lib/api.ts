import type { Scan } from "../types";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api";

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("lg_access");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
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

