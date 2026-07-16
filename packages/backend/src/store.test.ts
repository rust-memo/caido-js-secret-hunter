/// <reference types="node" />
/* eslint-disable compat/compat -- Store integration tests run on Node.js 22. */

import { DatabaseSync } from "node:sqlite";

import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";
import { describe, expect, it } from "vitest";

import {
  HunterStore,
  normalizeAssetQuery,
  normalizeEndpointQuery,
  normalizeFileQuery,
  normalizeFindingQuery,
} from "./store";
import type { AssetDTO, DetectedFinding } from "./types";

describe("HunterStore", () => {
  it("normalizes bounded server queries", () => {
    expect(
      normalizeFindingQuery({
        search: "  TOKEN  ",
        severity: "CRITICAL",
        confidence: "HIGH",
        kind: "SECRET",
        status: "NEEDS_REVIEW",
        offset: -10,
        limit: 500,
      }),
    ).toEqual({
      search: "token",
      severity: "CRITICAL",
      confidence: "HIGH",
      kind: "SECRET",
      status: "NEEDS_REVIEW",
      offset: 0,
      limit: 100,
    });
    expect(
      normalizeFileQuery({ search: " APP.JS ", offset: 2.6, limit: 0 }),
    ).toEqual({ search: "app.js", offset: 2, limit: 1 });
    expect(
      normalizeAssetQuery({
        search: " map ",
        status: "SCANNED",
        offset: 2_000_000,
        limit: 50,
      }),
    ).toEqual({
      search: "map",
      status: "SCANNED",
      offset: 1_000_000,
      limit: 50,
    });
    expect(
      normalizeEndpointQuery({
        search: "  ORDER  ",
        confidence: "HIGH",
        status: "ALL",
        method: "POST",
        scope: "CROSS_ORIGIN",
        offset: -1,
        limit: 500,
      }),
    ).toEqual({
      search: "order",
      confidence: "HIGH",
      status: "ALL",
      method: "POST",
      scope: "CROSS_ORIGIN",
      offset: 0,
      limit: 100,
    });
  });

  it("migrates, filters, paginates, and retains review metadata", async () => {
    const raw = new DatabaseSync(":memory:");
    const database = asyncDatabase(raw);
    const store = new HunterStore();
    await store.initialize(sdk(database));

    expect(await store.getSettings()).toMatchObject({
      autoFetch: false,
      includeCredentials: false,
    });
    const saved = await store.saveSettings({
      scanAllHistory: true,
      autoFetch: false,
      includeCredentials: true,
      assetExclusions: [" JQuery ", "jquery", "", "Google-Analytics"],
      maxDepth: 99,
      maxAssetsPerRoot: 0,
      maxBodyBytes: 1,
      maxHistoryEntries: 1,
      maxFindings: 99_999,
    });
    expect(saved).toMatchObject({
      autoFetch: false,
      includeCredentials: false,
      assetExclusions: ["jquery", "google-analytics"],
      maxDepth: 5,
      maxAssetsPerRoot: 1,
      maxBodyBytes: 65_536,
      maxHistoryEntries: 100,
      maxFindings: 50_000,
    });

    await store.addFindings(
      "project-1",
      "request-1",
      "response-1",
      [finding("one", "CRITICAL", "https://app.test/app.js")],
      10,
    );
    await store.addFindings(
      "project-1",
      "request-2",
      "response-2",
      [finding("two", "HIGH", "https://app.test/vendor.js", "ENDPOINT")],
      10,
    );
    await store.upsertAsset(asset("https://app.test/app.js"));
    await store.upsertAsset(asset("https://app.test/vendor.js"));

    const findings = await store.listFindings("project-1", {
      search: "app.js",
      severity: "CRITICAL",
      confidence: "ALL",
      kind: "ALL",
      status: "ALL",
      offset: 0,
      limit: 1,
    });
    expect(findings.total).toBe(1);
    expect(findings.items[0]?.ruleName).toBe("Rule one");

    const fingerprint = findings.items[0]!.fingerprint;
    await store.setStatus("project-1", [fingerprint], "REVIEWED");
    await store.setNote("project-1", fingerprint, "  rotated and verified  ");
    expect(await store.getFinding("project-1", fingerprint)).toMatchObject({
      status: "REVIEWED",
      reviewNote: "rotated and verified",
    });

    const files = await store.listFiles("project-1", {
      search: "app.js",
      offset: 0,
      limit: 50,
    });
    expect(files.total).toBe(1);
    expect(files.items[0]).toMatchObject({ findings: 1, reviewed: 1 });

    const assets = await store.listAssets("project-1", {
      search: "vendor",
      status: "SCANNED",
      offset: 0,
      limit: 50,
    });
    expect(assets.total).toBe(1);

    const endpoints = await store.listEndpoints("project-1", {
      search: "orderid",
      confidence: "ALL",
      status: "ALL",
      method: "POST",
      scope: "CROSS_ORIGIN",
      offset: 0,
      limit: 50,
    });
    expect(endpoints.total).toBe(1);
    expect(endpoints.items[0]?.endpoint).toMatchObject({
      method: "POST",
      source: "FETCH",
      scope: "CROSS_ORIGIN",
      parameters: ["orderId"],
    });
    expect(await store.endpointSummary("project-1")).toMatchObject({
      observations: 1,
      uniqueRoutes: 1,
      dynamicRoutes: 1,
      crossOrigin: 1,
      parameterized: 1,
      methods: { POST: 1 },
      sources: { FETCH: 1 },
    });

    const overview = await store.overview("project-1");
    expect(overview.summary).toMatchObject({
      findingTotal: 2,
      endpointTotal: 1,
      reviewed: 1,
      needsReview: 1,
      critical: 1,
      high: 1,
      fileTotal: 2,
      assetTotal: 2,
    });

    await store.clearResults("project-1");
    expect(await store.overview("project-1")).toMatchObject({
      summary: {
        findingTotal: 0,
        endpointTotal: 0,
        fileTotal: 0,
        assetTotal: 0,
      },
      recentFindings: [],
    });
    expect(
      await store.listFindings("project-1", {
        search: "",
        severity: "ALL",
        confidence: "ALL",
        kind: "ALL",
        status: "ALL",
        offset: 0,
        limit: 50,
      }),
    ).toMatchObject({ total: 0, items: [] });
    const historyCutoff = await store.getHistoryCutoff("project-1");
    expect(historyCutoff).toBeDefined();
    expect(Number.isNaN(new Date(historyCutoff!).getTime())).toBe(false);
    const reloadedStore = new HunterStore();
    await reloadedStore.initialize(sdk(database));
    expect(await reloadedStore.getHistoryCutoff("project-1")).toBe(
      historyCutoff,
    );
    await reloadedStore.resetHistoryCutoff("project-1");
    expect(await store.getHistoryCutoff("project-1")).toBeUndefined();
    await store.addFindings(
      "project-1",
      "request-3",
      "response-3",
      [finding("one", "CRITICAL", "https://app.test/app.js")],
      10,
    );
    expect(await store.getFinding("project-1", fingerprint)).toMatchObject({
      status: "REVIEWED",
      reviewNote: "rotated and verified",
    });
    expect(
      raw
        .prepare("SELECT version FROM hunter_schema WHERE key = ?")
        .get("js-secret-hunter"),
    ).toMatchObject({ version: 5 });
    raw.close();
  });

  it("enforces the candidate cap across concurrent analysis", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new HunterStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    await Promise.all([
      store.addFindings(
        "project-1",
        "request-1",
        "response-1",
        [finding("one", "HIGH", "https://app.test/one.js")],
        1,
      ),
      store.addFindings(
        "project-1",
        "request-2",
        "response-2",
        [finding("two", "HIGH", "https://app.test/two.js")],
        1,
      ),
    ]);
    expect(await store.findingCount("project-1")).toBe(1);
    raw.close();
  });

  it("upgrades a v2 findings table without discarding existing rows", async () => {
    const raw = new DatabaseSync(":memory:");
    raw.exec(`
      CREATE TABLE findings (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        asset_url TEXT NOT NULL,
        line INTEGER NOT NULL,
        start_offset INTEGER NOT NULL,
        end_offset INTEGER NOT NULL,
        preview TEXT NOT NULL,
        masked_value TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'NEEDS_REVIEW',
        published INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        PRIMARY KEY (project_id, fingerprint)
      );
      INSERT INTO findings VALUES(
        'project-1', 'old-fingerprint', 'request-1', 'response-1', '${"a".repeat(64)}',
        'api-endpoint', 'API endpoint', 'ENDPOINT', 'INFO', 'MEDIUM',
        'https://app.test/app.js', 1, 0, 5, 'preview', '/api/v1/users',
        'NEEDS_REVIEW', 0, '2026-07-16T00:00:00.000Z'
      );
      CREATE TABLE hunter_schema (key TEXT PRIMARY KEY, version INTEGER NOT NULL);
      INSERT INTO hunter_schema VALUES('js-secret-hunter', 2);
    `);
    const store = new HunterStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    expect(
      raw
        .prepare("SELECT version FROM hunter_schema WHERE key = ?")
        .get("js-secret-hunter"),
    ).toMatchObject({ version: 5 });
    expect(
      raw
        .prepare("PRAGMA table_info(findings)")
        .all()
        .map((column) => (column as { name: string }).name),
    ).toEqual(
      expect.arrayContaining([
        "endpoint_method",
        "endpoint_source",
        "endpoint_scope",
        "endpoint_parameters",
        "endpoint_dynamic",
        "endpoint_canonical",
        "evidence_highlight",
      ]),
    );
    expect(
      await store.getFinding("project-1", "old-fingerprint"),
    ).toMatchObject({
      endpoint: {
        method: "ANY",
        source: "DETECTOR",
        scope: "UNKNOWN",
        parameters: [],
      },
    });
    raw.close();
  });

  it("clears atomically without connection-scoped transaction commands", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new HunterStore();
    await store.initialize(sdk(rejectTransactionControl(asyncDatabase(raw))));
    await store.addFindings(
      "project-1",
      "request-1",
      "response-1",
      [finding("one", "HIGH", "https://app.test/app.js")],
      10,
    );
    await store.upsertAsset(asset("https://app.test/app.js"));

    await expect(
      store.clearResults("project-1", "2026-07-16T08:30:00.000Z"),
    ).resolves.toBeUndefined();
    expect(await store.findingCount("project-1")).toBe(0);
    expect(await store.assets("project-1")).toEqual([]);
    expect(await store.getHistoryCutoff("project-1")).toBe(
      "2026-07-16T08:30:00.000Z",
    );

    await store.addFindings(
      "project-1",
      "request-2",
      "response-2",
      [finding("two", "HIGH", "https://app.test/two.js")],
      10,
    );
    await store.clearResults("project-1", "");
    expect(await store.findingCount("project-1")).toBe(0);
    expect(await store.getHistoryCutoff("project-1")).toBeUndefined();
    raw.close();
  });

  it("supports reversible rule and host exclusions", async () => {
    const raw = new DatabaseSync(":memory:");
    const store = new HunterStore();
    await store.initialize(sdk(asyncDatabase(raw)));
    await store.addFindings(
      "project-1",
      "request-1",
      "response-1",
      [
        finding("one", "HIGH", "https://app.test/app.js"),
        finding("two", "HIGH", "https://cdn.test/app.js"),
      ],
      10,
    );
    await store.ignore("project-1", "host", "APP.TEST");
    expect(await store.findingCount("project-1")).toBe(1);
    expect((await store.getIgnored("project-1")).hosts.has("app.test")).toBe(
      true,
    );
    await store.unignore("project-1", "host", "app.test");
    expect((await store.getIgnored("project-1")).hosts.size).toBe(0);
    await store.ignore("project-1", "rule", "rule.two");
    expect(await store.findingCount("project-1")).toBe(0);
    await store.restoreIgnored("project-1");
    expect((await store.getIgnored("project-1")).rules.size).toBe(0);
    raw.close();
  });
});

function finding(
  suffix: string,
  severity: DetectedFinding["severity"],
  assetUrl: string,
  kind: DetectedFinding["kind"] = "SECRET",
): DetectedFinding {
  return {
    fingerprint: `fingerprint-${suffix}`,
    valueHash: `${suffix}`.padEnd(64, "0"),
    ruleId: `rule.${suffix}`,
    ruleName: `Rule ${suffix}`,
    kind,
    severity,
    confidence: "HIGH",
    assetUrl,
    line: 3,
    start: 10,
    end: 30,
    preview: `token=${suffix}`,
    maskedValue: `${suffix.slice(0, 2)}…`,
    evidenceHighlight: suffix,
    rawValue: `secret-${suffix}`,
    endpoint:
      kind === "ENDPOINT"
        ? {
            method: "POST",
            source: "FETCH",
            scope: "CROSS_ORIGIN",
            parameters: ["orderId"],
            dynamic: true,
            canonical: "https://api.test/orders/{orderId}",
          }
        : undefined,
  };
}

function asset(url: string): AssetDTO {
  return {
    projectId: "project-1",
    url,
    requestId: `request-${url}`,
    parentUrl: "https://app.test/",
    rootUrl: "https://app.test/",
    depth: 0,
    status: "SCANNED",
    detail: "1 candidate",
    updatedAt: "2026-07-15T10:00:00.000Z",
  };
}

function sdk(database: Database): SDK {
  return { meta: { db: () => Promise.resolve(database) } } as unknown as SDK;
}

function asyncDatabase(raw: DatabaseSync): Database {
  return {
    exec: (sql: string) => Promise.resolve(raw.exec(sql)),
    prepare: (sql: string) => {
      const statement = raw.prepare(sql);
      return Promise.resolve({
        all: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.all(...parameters) as T[]),
        get: <T extends object = object>(...parameters: Parameter[]) =>
          Promise.resolve(statement.get(...parameters) as T | undefined),
        run: (...parameters: Parameter[]) => {
          const result = statement.run(...parameters);
          return Promise.resolve({
            changes: Number(result.changes),
            lastInsertRowid: Number(result.lastInsertRowid),
          });
        },
      });
    },
  };
}

function rejectTransactionControl(database: Database): Database {
  return {
    exec: (sql: string) => {
      if (/^(?:BEGIN(?: IMMEDIATE)?|COMMIT|ROLLBACK);?$/i.test(sql.trim()))
        return Promise.reject(new Error("database is locked"));
      return database.exec(sql);
    },
    prepare: (sql: string) => database.prepare(sql),
  };
}
