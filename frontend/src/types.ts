export type Classification = "low" | "moderate" | "high" | "critical" | "error";

export interface Indicator {
  code: string;
  label: string;
  weight: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
}

export interface ProviderResult {
  provider: string;
  status: string;
  verdict: string;
  score: number;
  details: Record<string, unknown>;
  error: string;
}

export interface Scan {
  id: string;
  original_url: string;
  normalized_url: string;
  hostname: string;
  status: "pending" | "running" | "complete" | "failed";
  classification: Classification | "";
  risk_score: number | null;
  indicators: Indicator[];
  provider_results: Record<string, ProviderResult>;
  domain_info: Record<string, unknown>;
  recommendations: string[];
  error_message: string;
  created_at: string;
  completed_at: string | null;
}

