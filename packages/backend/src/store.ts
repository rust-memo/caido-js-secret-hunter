import type { SDK } from "caido:plugin";
import type { Database } from "sqlite";

import type {
  AssetDTO,
  AssetStatus,
  DetectedFinding,
  FindingDTO,
  HunterSettings,
  ReviewStatus,
  SensitiveFileDTO,
  Severity,
} from "./types";

const DEFAULT_SETTINGS: HunterSettings = {
  scanAllHistory: true,
  autoFetch: true,
  maxDepth: 2,
  maxAssetsPerRoot: 200,
  maxBodyBytes: 5 * 1024 * 1024,
  maxHistoryEntries: 5_000,
  maxFindings: 10_000,
};

type FindingRow = {
  project_id: string;
  fingerprint: string;
  request_id: string;
  response_id: string;
  value_hash: string;
  rule_id: string;
  rule_name: string;
  kind: FindingDTO["kind"];
  severity: Severity;
  confidence: FindingDTO["confidence"];
  asset_url: string;
  line: number;
  start_offset: number;
  end_offset: number;
  preview: string;
  masked_value: string;
  status: ReviewStatus;
  published: number;
  created_at: string;
};

type AssetRow = {
  project_id: string;
  url: string;
  request_id: string;
  parent_url: string;
  root_url: string;
  depth: number;
  status: AssetStatus;
  detail: string;
  updated_at: string;
};

export class HunterStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    await this.database.exec(`
      CREATE TABLE IF NOT EXISTS findings (
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
      CREATE INDEX IF NOT EXISTS findings_project_asset ON findings(project_id, asset_url);
      CREATE INDEX IF NOT EXISTS findings_project_status ON findings(project_id, status);
      CREATE TABLE IF NOT EXISTS review_states (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        PRIMARY KEY (project_id, fingerprint)
      );
      CREATE TABLE IF NOT EXISTS ignored_values (
        project_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (project_id, kind, value)
      );
      CREATE TABLE IF NOT EXISTS assets (
        project_id TEXT NOT NULL,
        url TEXT NOT NULL,
        request_id TEXT NOT NULL,
        parent_url TEXT NOT NULL,
        root_url TEXT NOT NULL,
        depth INTEGER NOT NULL,
        status TEXT NOT NULL,
        detail TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (project_id, url)
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  async getSettings(): Promise<HunterSettings> {
    const database = this.requireDatabase();
    const statement = await database.prepare(
      "SELECT value FROM settings WHERE key = ?",
    );
    const row = await statement.get<{ value: string }>("hunter");
    if (row === undefined) return { ...DEFAULT_SETTINGS };
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<HunterSettings>),
      });
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  async saveSettings(settings: HunterSettings): Promise<HunterSettings> {
    const normalized = normalizeSettings(settings);
    const statement = await this.requireDatabase().prepare(
      "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    );
    await statement.run("hunter", JSON.stringify(normalized));
    return normalized;
  }

  async findingCount(projectId: string): Promise<number> {
    const statement = await this.requireDatabase().prepare(
      "SELECT COUNT(*) AS count FROM findings WHERE project_id = ?",
    );
    return (await statement.get<{ count: number }>(projectId))?.count ?? 0;
  }

  async addFindings(
    projectId: string,
    requestId: string,
    responseId: string,
    findings: DetectedFinding[],
    maxFindings: number,
  ): Promise<number> {
    const database = this.requireDatabase();
    let remaining = Math.max(
      0,
      maxFindings - (await this.findingCount(projectId)),
    );
    if (remaining === 0) return 0;
    const ignored = await this.getIgnored(projectId);
    const reviewQuery = await database.prepare(
      "SELECT status FROM review_states WHERE project_id = ? AND fingerprint = ?",
    );
    const insert = await database.prepare(`
      INSERT OR IGNORE INTO findings(
        project_id, fingerprint, request_id, response_id, value_hash, rule_id, rule_name, kind,
        severity, confidence, asset_url, line, start_offset, end_offset, preview, masked_value,
        status, published, created_at
      ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    `);
    let added = 0;
    for (const finding of findings) {
      if (remaining <= 0) break;
      if (
        ignored.rules.has(finding.ruleId) ||
        ignored.hosts.has(hostOf(finding.assetUrl))
      )
        continue;
      const review = await reviewQuery.get<{ status: ReviewStatus }>(
        projectId,
        finding.fingerprint,
      );
      const result = await insert.run(
        projectId,
        finding.fingerprint,
        requestId,
        responseId,
        finding.valueHash,
        finding.ruleId,
        finding.ruleName,
        finding.kind,
        finding.severity,
        finding.confidence,
        finding.assetUrl,
        finding.line,
        finding.start,
        finding.end,
        finding.preview,
        finding.maskedValue,
        review?.status ?? "NEEDS_REVIEW",
        new Date().toISOString(),
      );
      if (result.changes > 0) {
        added += 1;
        remaining -= 1;
      }
    }
    return added;
  }

  async upsertAsset(asset: AssetDTO): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      INSERT INTO assets(project_id, url, request_id, parent_url, root_url, depth, status, detail, updated_at)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id, url) DO UPDATE SET
        request_id = excluded.request_id,
        parent_url = excluded.parent_url,
        root_url = excluded.root_url,
        depth = excluded.depth,
        status = excluded.status,
        detail = excluded.detail,
        updated_at = excluded.updated_at
    `);
    await statement.run(
      asset.projectId,
      asset.url,
      asset.requestId,
      asset.parentUrl,
      asset.rootUrl,
      asset.depth,
      asset.status,
      asset.detail,
      asset.updatedAt,
    );
  }

  async snapshot(projectId: string): Promise<{
    findings: FindingDTO[];
    files: SensitiveFileDTO[];
    assets: AssetDTO[];
  }> {
    const database = this.requireDatabase();
    const findingStatement = await database.prepare(`
      SELECT * FROM findings WHERE project_id = ?
      ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
               created_at DESC
    `);
    const assetStatement = await database.prepare(
      "SELECT * FROM assets WHERE project_id = ? ORDER BY updated_at DESC",
    );
    const findings = (await findingStatement.all<FindingRow>(projectId)).map(
      toFinding,
    );
    const assets = (await assetStatement.all<AssetRow>(projectId)).map(toAsset);
    return { findings, files: groupFiles(findings), assets };
  }

  async setStatus(
    projectId: string,
    fingerprints: string[],
    status: ReviewStatus,
  ): Promise<void> {
    const database = this.requireDatabase();
    const state = await database.prepare(`
      INSERT INTO review_states(project_id, fingerprint, status) VALUES(?, ?, ?)
      ON CONFLICT(project_id, fingerprint) DO UPDATE SET status = excluded.status
    `);
    const update = await database.prepare(
      "UPDATE findings SET status = ? WHERE project_id = ? AND fingerprint = ?",
    );
    for (const fingerprint of new Set(fingerprints)) {
      await state.run(projectId, fingerprint, status);
      await update.run(status, projectId, fingerprint);
    }
  }

  async clearResults(projectId: string): Promise<void> {
    const findings = await this.requireDatabase().prepare(
      "DELETE FROM findings WHERE project_id = ?",
    );
    const assets = await this.requireDatabase().prepare(
      "DELETE FROM assets WHERE project_id = ?",
    );
    await findings.run(projectId);
    await assets.run(projectId);
  }

  async ignore(
    projectId: string,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    const normalized = kind === "host" ? value.toLowerCase() : value;
    const insert = await this.requireDatabase().prepare(
      "INSERT OR IGNORE INTO ignored_values(project_id, kind, value) VALUES(?, ?, ?)",
    );
    await insert.run(projectId, kind, normalized);
    if (kind === "rule") {
      const remove = await this.requireDatabase().prepare(
        "DELETE FROM findings WHERE project_id = ? AND rule_id = ?",
      );
      await remove.run(projectId, normalized);
      return;
    }
    const remove = await this.requireDatabase().prepare(
      "DELETE FROM findings WHERE project_id = ? AND (lower(asset_url) LIKE ? OR lower(asset_url) LIKE ?)",
    );
    await remove.run(projectId, `%://${normalized}/%`, `%://${normalized}:%`);
  }

  async restoreIgnored(projectId: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "DELETE FROM ignored_values WHERE project_id = ?",
    );
    await statement.run(projectId);
  }

  async getIgnored(
    projectId: string,
  ): Promise<{ rules: Set<string>; hosts: Set<string> }> {
    const statement = await this.requireDatabase().prepare(
      "SELECT kind, value FROM ignored_values WHERE project_id = ?",
    );
    const rows = await statement.all<{ kind: "rule" | "host"; value: string }>(
      projectId,
    );
    return {
      rules: new Set(
        rows.filter((row) => row.kind === "rule").map((row) => row.value),
      ),
      hosts: new Set(
        rows.filter((row) => row.kind === "host").map((row) => row.value),
      ),
    };
  }

  async getFinding(
    projectId: string,
    fingerprint: string,
  ): Promise<FindingDTO | undefined> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM findings WHERE project_id = ? AND fingerprint = ?",
    );
    const row = await statement.get<FindingRow>(projectId, fingerprint);
    return row === undefined ? undefined : toFinding(row);
  }

  async markPublished(projectId: string, fingerprint: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(
      "UPDATE findings SET published = 1 WHERE project_id = ? AND fingerprint = ?",
    );
    await statement.run(projectId, fingerprint);
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("JS Secret Hunter database is not initialized");
    return this.database;
  }
}

function normalizeSettings(value: HunterSettings): HunterSettings {
  return {
    scanAllHistory: Boolean(value.scanAllHistory),
    autoFetch: Boolean(value.autoFetch),
    maxDepth: clamp(value.maxDepth, 0, 5),
    maxAssetsPerRoot: clamp(value.maxAssetsPerRoot, 1, 2_000),
    maxBodyBytes: clamp(value.maxBodyBytes, 64 * 1024, 25 * 1024 * 1024),
    maxHistoryEntries: clamp(value.maxHistoryEntries, 100, 50_000),
    maxFindings: clamp(value.maxFindings, 100, 50_000),
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  const number = Number.isFinite(value) ? Math.trunc(value) : minimum;
  return Math.max(minimum, Math.min(maximum, number));
}

function toFinding(row: FindingRow): FindingDTO {
  return {
    projectId: row.project_id,
    fingerprint: row.fingerprint,
    requestId: row.request_id,
    responseId: row.response_id,
    valueHash: row.value_hash,
    ruleId: row.rule_id,
    ruleName: row.rule_name,
    kind: row.kind,
    severity: row.severity,
    confidence: row.confidence,
    assetUrl: row.asset_url,
    line: row.line,
    start: row.start_offset,
    end: row.end_offset,
    preview: row.preview,
    maskedValue: row.masked_value,
    status: row.status,
    published: row.published === 1,
    createdAt: row.created_at,
  };
}

function toAsset(row: AssetRow): AssetDTO {
  return {
    projectId: row.project_id,
    url: row.url,
    requestId: row.request_id,
    parentUrl: row.parent_url,
    rootUrl: row.root_url,
    depth: row.depth,
    status: row.status,
    detail: row.detail,
    updatedAt: row.updated_at,
  };
}

function groupFiles(findings: FindingDTO[]): SensitiveFileDTO[] {
  const grouped = new Map<string, FindingDTO[]>();
  for (const finding of findings) {
    const current = grouped.get(finding.assetUrl) ?? [];
    current.push(finding);
    grouped.set(finding.assetUrl, current);
  }
  const files: SensitiveFileDTO[] = [];
  for (const [assetUrl, values] of grouped) {
    const source = values[0];
    if (source === undefined) continue;
    const rules = [...new Set(values.map((finding) => finding.ruleName))].join(
      ", ",
    );
    files.push({
      assetUrl,
      requestId: source.requestId,
      responseId: source.responseId,
      severity: highestSeverity(values.map((finding) => finding.severity)),
      findings: values.length,
      needsReview: values.filter((finding) => finding.status === "NEEDS_REVIEW")
        .length,
      reviewed: values.filter((finding) => finding.status === "REVIEWED")
        .length,
      falsePositive: values.filter(
        (finding) => finding.status === "FALSE_POSITIVE",
      ).length,
      rules,
      fingerprints: values.map((finding) => finding.fingerprint),
    });
  }
  return files.sort(
    (left, right) => severityRank(left.severity) - severityRank(right.severity),
  );
}

function highestSeverity(values: Severity[]): Severity {
  return values.reduce<Severity>(
    (highest, value) =>
      severityRank(value) < severityRank(highest) ? value : highest,
    "INFO",
  );
}

function severityRank(value: Severity): number {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3 }[value];
}

function hostOf(url: string): string {
  const match = url.match(/^https?:\/\/(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)/i);
  return match?.[1]?.toLowerCase() ?? "";
}
