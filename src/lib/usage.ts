import { AccountsError } from "../types.js";

/**
 * Contract for Claude's OAuth usage endpoint, measured live on 2026-07-28
 * against Claude Code 2.1.220 (`fetchUtilization: GET /api/oauth/usage`):
 *
 *   GET https://api.anthropic.com/api/oauth/usage
 *   Authorization: Bearer <claudeAiOauth.accessToken>
 *   anthropic-beta: oauth-2025-04-20
 *
 * The response carries named windows (`five_hour`, `seven_day`, nullable
 * model-scoped siblings) and a structured `limits[]` array
 * ({kind, group, percent, severity, resets_at, scope, is_active}). `limits[]`
 * is preferred: it is the shape `/status` renders and it distinguishes
 * session vs weekly vs model-scoped caps explicitly.
 */
export const DEFAULT_CLAUDE_USAGE_URL = "https://api.anthropic.com/api/oauth/usage";
export const CLAUDE_OAUTH_BETA_HEADER = "oauth-2025-04-20";

export function claudeUsageUrl(env: Record<string, string | undefined> = process.env): string {
  const override = env.ACCOUNTS_CLAUDE_USAGE_URL?.trim();
  return override || DEFAULT_CLAUDE_USAGE_URL;
}

export interface UsageWindow {
  /** Window id: `limits[].kind` (session, weekly_all, …) or the named field. */
  id: string;
  /** Percent of the window consumed, 0–100 (may overshoot server-side). */
  utilization: number;
  /** True for model/surface-scoped windows that do not gate overall usage. */
  scoped: boolean;
  resetsAt?: string;
  severity?: string;
  isActive?: boolean;
  group?: string;
}

export interface AccountUsage {
  windows: UsageWindow[];
  /** 100 − worst unscoped window; the account's real remaining margin. */
  headroom: number;
  /** Id of the unscoped window that sets the headroom. */
  bindingWindow?: string;
  fetchedAt: string;
}

export type UsageFetchErrorKind = "unauthorized" | "http" | "network" | "malformed";

export interface UsageFetchError {
  kind: UsageFetchErrorKind;
  message: string;
  status?: number;
}

export type UsageFetchResult = { ok: true; usage: AccountUsage } | { ok: false; error: UsageFetchError };

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function windowsFromLimits(limits: unknown[]): UsageWindow[] {
  const windows: UsageWindow[] = [];
  for (const entry of limits) {
    if (!isRecord(entry)) continue;
    const percent = asFiniteNumber(entry.percent);
    const kind = optionalString(entry.kind);
    if (percent === undefined || !kind) continue;
    windows.push({
      id: kind,
      utilization: percent,
      scoped: isRecord(entry.scope),
      ...(optionalString(entry.resets_at) ? { resetsAt: optionalString(entry.resets_at)! } : {}),
      ...(optionalString(entry.severity) ? { severity: optionalString(entry.severity)! } : {}),
      ...(typeof entry.is_active === "boolean" ? { isActive: entry.is_active } : {}),
      ...(optionalString(entry.group) ? { group: optionalString(entry.group)! } : {}),
    });
  }
  return windows;
}

/** Named fallback windows; ids beyond the two canonical ones are model-scoped. */
const NAMED_WINDOWS: ReadonlyArray<{ id: string; scoped: boolean }> = [
  { id: "five_hour", scoped: false },
  { id: "seven_day", scoped: false },
  { id: "seven_day_opus", scoped: true },
  { id: "seven_day_sonnet", scoped: true },
];

function windowsFromNamedFields(raw: JsonRecord): UsageWindow[] {
  const windows: UsageWindow[] = [];
  for (const { id, scoped } of NAMED_WINDOWS) {
    const field = raw[id];
    if (!isRecord(field)) continue;
    const utilization = asFiniteNumber(field.utilization);
    if (utilization === undefined) continue;
    windows.push({
      id,
      utilization,
      scoped,
      ...(optionalString(field.resets_at) ? { resetsAt: optionalString(field.resets_at)! } : {}),
    });
  }
  return windows;
}

/**
 * Normalize a `/api/oauth/usage` body. Throws AccountsError when no usable
 * window exists — a shape change must surface loudly in `accounts usage`, while
 * the hook path wraps this in a fail-open result.
 */
export function parseUsageResponse(raw: unknown, now: Date = new Date()): AccountUsage {
  if (!isRecord(raw)) throw new AccountsError("usage response is not a JSON object");
  const windows = Array.isArray(raw.limits) && raw.limits.length > 0
    ? windowsFromLimits(raw.limits)
    : windowsFromNamedFields(raw);
  if (windows.length === 0) {
    throw new AccountsError("usage response carries no readable usage window (shape change?)");
  }

  // Scoped (per-model/surface) windows never set overall headroom: a saturated
  // Opus cap does not gate work on other models. If the server ever returns
  // only scoped windows, fall back to them rather than inventing headroom.
  const binding = windows.filter((w) => !w.scoped);
  const basis = binding.length > 0 ? binding : windows;
  const worst = basis.reduce((a, b) => (b.utilization > a.utilization ? b : a));
  return {
    windows,
    headroom: Math.max(0, Math.min(100, 100 - worst.utilization)),
    bindingWindow: worst.id,
    fetchedAt: now.toISOString(),
  };
}

export interface FetchUsageOptions {
  fetchImpl?: typeof fetch;
  url?: string;
  timeoutMs?: number;
}

/**
 * Query the usage endpoint with one account's access token. Never throws and
 * never places the token in any error message — callers log results verbatim.
 */
export async function fetchAccountUsage(
  accessToken: string,
  opts: FetchUsageOptions = {},
): Promise<UsageFetchResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = opts.url ?? claudeUsageUrl();
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "anthropic-beta": CLAUDE_OAUTH_BETA_HEADER,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
    });
  } catch (error) {
    return {
      ok: false,
      error: { kind: "network", message: error instanceof Error ? error.message : String(error) },
    };
  }

  if (response.status === 401 || response.status === 403) {
    return {
      ok: false,
      error: { kind: "unauthorized", message: "usage endpoint rejected the access token", status: response.status },
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      error: { kind: "http", message: `usage endpoint returned HTTP ${response.status}`, status: response.status },
    };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { ok: false, error: { kind: "malformed", message: "usage endpoint returned non-JSON body" } };
  }
  try {
    return { ok: true, usage: parseUsageResponse(body) };
  } catch (error) {
    return {
      ok: false,
      error: { kind: "malformed", message: error instanceof Error ? error.message : String(error) },
    };
  }
}
