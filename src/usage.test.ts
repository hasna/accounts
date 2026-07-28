import { test, expect } from "bun:test";
import { claudeUsageUrl, fetchAccountUsage, parseUsageResponse } from "./lib/usage.js";

/**
 * Captured live from GET https://api.anthropic.com/api/oauth/usage on
 * 2026-07-28 (Claude Code 2.1.220 account, five_hour 10% / seven_day 80%),
 * trimmed to the fields this feature reads plus the nullable siblings.
 */
const LIVE_SHAPE = {
  five_hour: {
    utilization: 10.0,
    resets_at: "2026-07-28T14:40:00.965995+00:00",
    limit_dollars: null,
    used_dollars: null,
    remaining_dollars: null,
  },
  seven_day: {
    utilization: 80.0,
    resets_at: "2026-08-01T14:00:00.966016+00:00",
    limit_dollars: null,
    used_dollars: null,
    remaining_dollars: null,
  },
  seven_day_opus: null,
  seven_day_sonnet: null,
  limits: [
    {
      kind: "session",
      group: "session",
      percent: 10,
      severity: "normal",
      resets_at: "2026-07-28T14:40:00.965995+00:00",
      scope: null,
      is_active: false,
    },
    {
      kind: "weekly_all",
      group: "weekly",
      percent: 80,
      severity: "warning",
      resets_at: "2026-08-01T14:00:00.966016+00:00",
      scope: null,
      is_active: true,
    },
    {
      kind: "weekly_scoped",
      group: "weekly",
      percent: 6,
      severity: "normal",
      resets_at: "2026-08-01T14:00:00.966338+00:00",
      scope: { model: { id: null, display_name: "Fable" }, surface: null },
      is_active: false,
    },
  ],
};

test("parseUsageResponse prefers the structured limits[] array", () => {
  const usage = parseUsageResponse(LIVE_SHAPE);
  expect(usage.windows.map((w) => w.id)).toEqual(["session", "weekly_all", "weekly_scoped"]);
  const weekly = usage.windows.find((w) => w.id === "weekly_all")!;
  expect(weekly.utilization).toBe(80);
  expect(weekly.severity).toBe("warning");
  expect(weekly.isActive).toBe(true);
  expect(weekly.resetsAt).toBe("2026-08-01T14:00:00.966016+00:00");
  expect(weekly.scoped).toBe(false);
  const scoped = usage.windows.find((w) => w.id === "weekly_scoped")!;
  expect(scoped.scoped).toBe(true);
});

test("headroom is 100 minus the worst UNSCOPED window", () => {
  const usage = parseUsageResponse(LIVE_SHAPE);
  // session 10, weekly_all 80 bind; weekly_scoped 6 is per-model and must not.
  expect(usage.headroom).toBe(20);
  expect(usage.bindingWindow).toBe("weekly_all");
});

test("a scoped window never sets headroom even when it is the worst", () => {
  const usage = parseUsageResponse({
    limits: [
      { kind: "session", group: "session", percent: 5, severity: "normal", resets_at: null, scope: null, is_active: false },
      { kind: "weekly_scoped", group: "weekly", percent: 99, severity: "warning", resets_at: null, scope: { model: { display_name: "Opus" } }, is_active: false },
    ],
  });
  expect(usage.headroom).toBe(95);
  expect(usage.bindingWindow).toBe("session");
});

test("parseUsageResponse falls back to named windows when limits[] is absent", () => {
  const usage = parseUsageResponse({
    five_hour: { utilization: 25, resets_at: "2026-07-28T14:40:00Z" },
    seven_day: { utilization: 100, resets_at: "2026-08-01T14:00:00Z" },
    seven_day_opus: { utilization: 40, resets_at: "2026-08-01T14:00:00Z" },
    seven_day_sonnet: null,
  });
  expect(usage.windows.map((w) => w.id).sort()).toEqual(["five_hour", "seven_day", "seven_day_opus"]);
  // seven_day_opus is model-scoped; five_hour/seven_day bind.
  expect(usage.headroom).toBe(0);
  expect(usage.bindingWindow).toBe("seven_day");
});

test("headroom clamps at 0 when utilization overshoots 100", () => {
  const usage = parseUsageResponse({ five_hour: { utilization: 104.2, resets_at: null } });
  expect(usage.headroom).toBe(0);
});

test("parseUsageResponse throws on shapes with no usable window", () => {
  expect(() => parseUsageResponse({})).toThrow();
  expect(() => parseUsageResponse(null)).toThrow();
  expect(() => parseUsageResponse({ limits: [] })).toThrow();
  expect(() => parseUsageResponse({ limits: [{ kind: "x", percent: "NaN" }] })).toThrow();
});

test("fetchAccountUsage sends bearer auth + oauth beta header to the usage URL", async () => {
  let seenUrl = "";
  let seenHeaders: Record<string, string> = {};
  const fetchImpl = async (url: string | URL, init?: RequestInit) => {
    seenUrl = String(url);
    seenHeaders = Object.fromEntries(new Headers(init?.headers).entries());
    return new Response(JSON.stringify(LIVE_SHAPE), { status: 200 });
  };
  const result = await fetchAccountUsage("fake-test-token", { fetchImpl });
  expect(result.ok).toBe(true);
  if (result.ok) expect(result.usage.headroom).toBe(20);
  expect(seenUrl).toBe(claudeUsageUrl());
  expect(seenHeaders["authorization"]).toBe("Bearer fake-test-token");
  expect(seenHeaders["anthropic-beta"]).toBe("oauth-2025-04-20");
});

test("fetchAccountUsage reports 401 as unauthorized without echoing the token", async () => {
  const fetchImpl = async () => new Response("{}", { status: 401 });
  const result = await fetchAccountUsage("super-secret-token-value", { fetchImpl });
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.error.kind).toBe("unauthorized");
    expect(JSON.stringify(result.error)).not.toContain("super-secret-token-value");
  }
});

test("fetchAccountUsage reports non-2xx and network failures as errors, not throws", async () => {
  const http = await fetchAccountUsage("t", { fetchImpl: async () => new Response("oops", { status: 503 }) });
  expect(http.ok).toBe(false);
  if (!http.ok) {
    expect(http.error.kind).toBe("http");
    expect(http.error.status).toBe(503);
  }

  const network = await fetchAccountUsage("t", {
    fetchImpl: async () => {
      throw new Error("ECONNREFUSED");
    },
  });
  expect(network.ok).toBe(false);
  if (!network.ok) expect(network.error.kind).toBe("network");
});

test("fetchAccountUsage reports malformed bodies as errors", async () => {
  const bad = await fetchAccountUsage("t", { fetchImpl: async () => new Response("not json", { status: 200 }) });
  expect(bad.ok).toBe(false);
  if (!bad.ok) expect(bad.error.kind).toBe("malformed");

  const empty = await fetchAccountUsage("t", { fetchImpl: async () => new Response("{}", { status: 200 }) });
  expect(empty.ok).toBe(false);
  if (!empty.ok) expect(empty.error.kind).toBe("malformed");
});

test("claudeUsageUrl honors the override env var", () => {
  expect(claudeUsageUrl({})).toBe("https://api.anthropic.com/api/oauth/usage");
  expect(claudeUsageUrl({ ACCOUNTS_CLAUDE_USAGE_URL: "https://example.test/usage" })).toBe(
    "https://example.test/usage",
  );
});
