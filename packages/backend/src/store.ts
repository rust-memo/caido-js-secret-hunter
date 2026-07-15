import type { SDK } from "caido:plugin";
import type { Database, Parameter } from "sqlite";

import type {
  AssetDTO,
  AssetQuery,
  AssetStatus,
  Confidence,
  DetectedFinding,
  FileQuery,
  FindingDTO,
  FindingKind,
  FindingQuery,
  HunterSettings,
  Page,
  ProjectSummary,
  ReviewStatus,
  SensitiveFileDTO,
  Severity,
} from "./types";

const DEFAULT_SETTINGS: HunterSettings = {
  scanAllHistory: true,
  autoFetch: false,
  includeCredentials: false,
  assetExclusions: ["jquery", "google-analytics", "googletagmanager", "gpt.js"],
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
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  asset_url: string;
  line: number;
  start_offset: number;
  end_offset: number;
  preview: string;
  masked_value: string;
  status: ReviewStatus;
  review_note: string;
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

type FileRow = {
  asset_url: string;
  request_id: string;
  response_id: string;
  severity: Severity;
  findings: number;
  needs_review: number;
  reviewed: number;
  false_positive: number;
  rules: string;
  fingerprints: string;
};

const FINDING_JOIN = `
  FROM findings
  LEFT JOIN finding_notes
    ON finding_notes.project_id = findings.project_id
   AND finding_notes.fingerprint = findings.fingerprint
`;

const FINDING_SELECT = `
  SELECT findings.*, COALESCE(finding_notes.note, '') AS review_note
  ${FINDING_JOIN}
`;

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
      CREATE INDEX IF NOT EXISTS findings_filter
        ON findings(project_id, status, severity, confidence, kind, created_at DESC);
      CREATE TABLE IF NOT EXISTS review_states (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        PRIMARY KEY (project_id, fingerprint)
      );
      CREATE TABLE IF NOT EXISTS finding_notes (
        project_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        note TEXT NOT NULL,
        updated_at TEXT NOT NULL,
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
      CREATE INDEX IF NOT EXISTS assets_filter
        ON assets(project_id, status, updated_at DESC);
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS hunter_schema (
        key TEXT PRIMARY KEY,
        version INTEGER NOT NULL
      );
      INSERT OR IGNORE INTO hunter_schema(key, version) VALUES('js-secret-hunter', 2);
      UPDATE hunter_schema SET version = 2
        WHERE key = 'js-secret-hunter' AND version < 2;
    `);
  }

  async getSettings(): Promise<HunterSettings> {
    const row = await this.requireDatabase()
      .prepare("SELECT value FROM settings WHERE key = ?")
      .then((statement) => statement.get<{ value: string }>("hunter"));
    if (row === undefined) return cloneSettings(DEFAULT_SETTINGS);
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<HunterSettings>),
      });
    } catch {
      return cloneSettings(DEFAULT_SETTINGS);
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
    const row = await this.requireDatabase()
      .prepare("SELECT COUNT(*) AS count FROM findings WHERE project_id = ?")
      .then((statement) => statement.get<{ count: number }>(projectId));
    return row?.count ?? 0;
  }

  async overview(projectId: string): Promise<{
    summary: ProjectSummary;
    recentFindings: FindingDTO[];
  }> {
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [statistics, assetCount, recentRows] = await Promise.all([
      database
        .prepare(
          `
          SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN kind = 'ENDPOINT' THEN 1 ELSE 0 END), 0) AS endpoints,
            COALESCE(SUM(CASE WHEN status = 'NEEDS_REVIEW' THEN 1 ELSE 0 END), 0) AS needs_review,
            COALESCE(SUM(CASE WHEN status = 'REVIEWED' THEN 1 ELSE 0 END), 0) AS reviewed,
            COALESCE(SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END), 0) AS false_positive,
            COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical,
            COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN published = 1 THEN 1 ELSE 0 END), 0) AS published,
            COUNT(DISTINCT asset_url) AS files
          FROM findings WHERE project_id = ?
        `,
        )
        .then((statement) =>
          statement.get<{
            total: number;
            endpoints: number;
            needs_review: number;
            reviewed: number;
            false_positive: number;
            critical: number;
            high: number;
            published: number;
            files: number;
          }>(projectId),
        ),
      database
        .prepare("SELECT COUNT(*) AS count FROM assets WHERE project_id = ?")
        .then((statement) => statement.get<{ count: number }>(projectId)),
      database
        .prepare(
          `${FINDING_SELECT}
          WHERE findings.project_id = ?
          ORDER BY ${severityOrder("findings.severity")}, findings.created_at DESC
          LIMIT 8`,
        )
        .then((statement) => statement.all<FindingRow>(projectId)),
    ]);
    return {
      summary: {
        findingTotal: statistics?.total ?? 0,
        endpointTotal: statistics?.endpoints ?? 0,
        needsReview: statistics?.needs_review ?? 0,
        reviewed: statistics?.reviewed ?? 0,
        falsePositive: statistics?.false_positive ?? 0,
        critical: statistics?.critical ?? 0,
        high: statistics?.high ?? 0,
        fileTotal: statistics?.files ?? 0,
        assetTotal: assetCount?.count ?? 0,
        published: statistics?.published ?? 0,
      },
      recentFindings: recentRows.map(toFinding),
    };
  }

  async listFindings(
    projectId: string,
    value: FindingQuery,
  ): Promise<Page<FindingDTO>> {
    const query = normalizeFindingQuery(value);
    const where = ["findings.project_id = ?"];
    const parameters: Parameter[] = [projectId];
    if (query.severity !== "ALL") {
      where.push("findings.severity = ?");
      parameters.push(query.severity);
    }
    if (query.confidence !== "ALL") {
      where.push("findings.confidence = ?");
      parameters.push(query.confidence);
    }
    if (query.kind !== "ALL") {
      where.push("findings.kind = ?");
      parameters.push(query.kind);
    }
    if (query.status !== "ALL") {
      where.push("findings.status = ?");
      parameters.push(query.status);
    }
    if (query.search !== "") {
      where.push(`instr(lower(
        findings.rule_name || ' ' || findings.rule_id || ' ' || findings.asset_url || ' ' ||
        findings.masked_value || ' ' || findings.preview || ' ' || COALESCE(finding_notes.note, '')
      ), ?) > 0`);
      parameters.push(query.search);
    }
    const clause = where.join(" AND ");
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `${FINDING_SELECT}
          WHERE ${clause}
          ORDER BY ${severityOrder("findings.severity")}, findings.created_at DESC
          LIMIT ? OFFSET ?`,
        )
        .then((statement) =>
          statement.all<FindingRow>(...parameters, query.limit, query.offset),
        ),
      database
        .prepare(`SELECT COUNT(*) AS count ${FINDING_JOIN} WHERE ${clause}`)
        .then((statement) => statement.get<{ count: number }>(...parameters)),
    ]);
    return page(rows.map(toFinding), count?.count ?? 0, query);
  }

  async listFiles(
    projectId: string,
    value: FileQuery,
  ): Promise<Page<SensitiveFileDTO>> {
    const query = normalizeFileQuery(value);
    const searchClause =
      query.search === ""
        ? ""
        : " AND instr(lower(asset_url || ' ' || rule_name), ?) > 0";
    const parameters: Parameter[] =
      query.search === "" ? [projectId] : [projectId, query.search];
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `
          SELECT asset_url, MIN(request_id) AS request_id, MIN(response_id) AS response_id,
            CASE MIN(${severityRankSql("severity")})
              WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'INFO'
            END AS severity,
            COUNT(*) AS findings,
            SUM(CASE WHEN status = 'NEEDS_REVIEW' THEN 1 ELSE 0 END) AS needs_review,
            SUM(CASE WHEN status = 'REVIEWED' THEN 1 ELSE 0 END) AS reviewed,
            SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS false_positive,
            GROUP_CONCAT(DISTINCT rule_name) AS rules,
            GROUP_CONCAT(fingerprint) AS fingerprints
          FROM findings WHERE project_id = ?${searchClause}
          GROUP BY asset_url
          ORDER BY MIN(${severityRankSql("severity")}), MAX(created_at) DESC
          LIMIT ? OFFSET ?
        `,
        )
        .then((statement) =>
          statement.all<FileRow>(...parameters, query.limit, query.offset),
        ),
      database
        .prepare(
          `
          SELECT COUNT(DISTINCT asset_url) AS count
          FROM findings WHERE project_id = ?${searchClause}
        `,
        )
        .then((statement) => statement.get<{ count: number }>(...parameters)),
    ]);
    return page(rows.map(toFile), count?.count ?? 0, query);
  }

  async listAssets(
    projectId: string,
    value: AssetQuery,
  ): Promise<Page<AssetDTO>> {
    const query = normalizeAssetQuery(value);
    const where = ["project_id = ?"];
    const parameters: Parameter[] = [projectId];
    if (query.status !== "ALL") {
      where.push("status = ?");
      parameters.push(query.status);
    }
    if (query.search !== "") {
      where.push(
        "instr(lower(url || ' ' || parent_url || ' ' || root_url || ' ' || detail), ?) > 0",
      );
      parameters.push(query.search);
    }
    const clause = where.join(" AND ");
    const database = this.requireDatabase();
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [rows, count] = await Promise.all([
      database
        .prepare(
          `SELECT * FROM assets WHERE ${clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?`,
        )
        .then((statement) =>
          statement.all<AssetRow>(...parameters, query.limit, query.offset),
        ),
      database
        .prepare(`SELECT COUNT(*) AS count FROM assets WHERE ${clause}`)
        .then((statement) => statement.get<{ count: number }>(...parameters)),
    ]);
    return page(rows.map(toAsset), count?.count ?? 0, query);
  }

  async findings(projectId: string): Promise<FindingDTO[]> {
    const rows = await this.requireDatabase()
      .prepare(
        `${FINDING_SELECT}
        WHERE findings.project_id = ?
        ORDER BY ${severityOrder("findings.severity")}, findings.created_at DESC`,
      )
      .then((statement) => statement.all<FindingRow>(projectId));
    return rows.map(toFinding);
  }

  async assets(projectId: string): Promise<AssetDTO[]> {
    const rows = await this.requireDatabase()
      .prepare(
        "SELECT * FROM assets WHERE project_id = ? ORDER BY updated_at DESC",
      )
      .then((statement) => statement.all<AssetRow>(projectId));
    return rows.map(toAsset);
  }

  async addFindings(
    projectId: string,
    requestId: string,
    responseId: string,
    findings: DetectedFinding[],
    maxFindings: number,
  ): Promise<number> {
    const database = this.requireDatabase();
    const ignored = await this.getIgnored(projectId);
    const reviewQuery = await database.prepare(
      "SELECT status FROM review_states WHERE project_id = ? AND fingerprint = ?",
    );
    const insert = await database.prepare(`
      INSERT OR IGNORE INTO findings(
        project_id, fingerprint, request_id, response_id, value_hash, rule_id, rule_name, kind,
        severity, confidence, asset_url, line, start_offset, end_offset, preview, masked_value,
        status, published, created_at
      ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?
        WHERE (SELECT COUNT(*) FROM findings WHERE project_id = ?) < ?
    `);
    let added = 0;
    for (const finding of findings) {
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
        projectId,
        maxFindings,
      );
      if (result.changes > 0) added += 1;
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

  async setStatus(
    projectId: string,
    fingerprints: string[],
    status: ReviewStatus,
  ): Promise<void> {
    if (!isReviewStatus(status)) throw new Error("Unknown review status");
    const database = this.requireDatabase();
    const state = await database.prepare(`
      INSERT INTO review_states(project_id, fingerprint, status) VALUES(?, ?, ?)
      ON CONFLICT(project_id, fingerprint) DO UPDATE SET status = excluded.status
    `);
    const update = await database.prepare(
      "UPDATE findings SET status = ? WHERE project_id = ? AND fingerprint = ?",
    );
    for (const fingerprint of [...new Set(fingerprints)].slice(0, 500)) {
      await state.run(projectId, fingerprint, status);
      await update.run(status, projectId, fingerprint);
    }
  }

  async setNote(
    projectId: string,
    fingerprint: string,
    note: string,
  ): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      INSERT INTO finding_notes(project_id, fingerprint, note, updated_at)
      VALUES(?, ?, ?, ?)
      ON CONFLICT(project_id, fingerprint) DO UPDATE SET
        note = excluded.note, updated_at = excluded.updated_at
    `);
    await statement.run(
      projectId,
      fingerprint,
      clip(note.trim(), 8_000),
      new Date().toISOString(),
    );
  }

  async clearResults(projectId: string): Promise<void> {
    const database = this.requireDatabase();
    await database
      .prepare("DELETE FROM findings WHERE project_id = ?")
      .then((statement) => statement.run(projectId));
    await database
      .prepare("DELETE FROM assets WHERE project_id = ?")
      .then((statement) => statement.run(projectId));
  }

  async ignore(
    projectId: string,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    const normalized = normalizeIgnored(kind, value);
    if (normalized === "") throw new Error("Ignored value cannot be empty");
    const database = this.requireDatabase();
    await database
      .prepare(
        "INSERT OR IGNORE INTO ignored_values(project_id, kind, value) VALUES(?, ?, ?)",
      )
      .then((statement) => statement.run(projectId, kind, normalized));
    if (kind === "rule") {
      await database
        .prepare("DELETE FROM findings WHERE project_id = ? AND rule_id = ?")
        .then((statement) => statement.run(projectId, normalized));
      return;
    }
    const rows = await database
      .prepare(
        "SELECT fingerprint, asset_url FROM findings WHERE project_id = ?",
      )
      .then((statement) =>
        statement.all<{ fingerprint: string; asset_url: string }>(projectId),
      );
    const remove = await database.prepare(
      "DELETE FROM findings WHERE project_id = ? AND fingerprint = ?",
    );
    for (const row of rows)
      if (hostOf(row.asset_url) === normalized)
        await remove.run(projectId, row.fingerprint);
  }

  async unignore(
    projectId: string,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    const normalized = normalizeIgnored(kind, value);
    await this.requireDatabase()
      .prepare(
        "DELETE FROM ignored_values WHERE project_id = ? AND kind = ? AND value = ?",
      )
      .then((statement) => statement.run(projectId, kind, normalized));
  }

  async restoreIgnored(projectId: string): Promise<void> {
    await this.requireDatabase()
      .prepare("DELETE FROM ignored_values WHERE project_id = ?")
      .then((statement) => statement.run(projectId));
  }

  async getIgnored(
    projectId: string,
  ): Promise<{ rules: Set<string>; hosts: Set<string> }> {
    const rows = await this.requireDatabase()
      .prepare("SELECT kind, value FROM ignored_values WHERE project_id = ?")
      .then((statement) =>
        statement.all<{ kind: "rule" | "host"; value: string }>(projectId),
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
    const row = await this.requireDatabase()
      .prepare(
        `${FINDING_SELECT}
        WHERE findings.project_id = ? AND findings.fingerprint = ?`,
      )
      .then((statement) => statement.get<FindingRow>(projectId, fingerprint));
    return row === undefined ? undefined : toFinding(row);
  }

  async markPublished(projectId: string, fingerprint: string): Promise<void> {
    await this.requireDatabase()
      .prepare(
        "UPDATE findings SET published = 1 WHERE project_id = ? AND fingerprint = ?",
      )
      .then((statement) => statement.run(projectId, fingerprint));
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("JS Secret Hunter database is not initialized");
    return this.database;
  }
}

export function normalizeFindingQuery(value: FindingQuery): FindingQuery {
  return {
    search: normalizeSearch(value.search),
    severity: isSeverity(value.severity) ? value.severity : "ALL",
    confidence: isConfidence(value.confidence) ? value.confidence : "ALL",
    kind: isKind(value.kind) ? value.kind : "ALL",
    status: isReviewFilter(value.status) ? value.status : "ALL",
    ...normalizePage(value),
  };
}

export function normalizeFileQuery(value: FileQuery): FileQuery {
  return { search: normalizeSearch(value.search), ...normalizePage(value) };
}

export function normalizeAssetQuery(value: AssetQuery): AssetQuery {
  return {
    search: normalizeSearch(value.search),
    status: isAssetFilter(value.status) ? value.status : "ALL",
    ...normalizePage(value),
  };
}

function normalizePage(value: { offset: number; limit: number }): {
  offset: number;
  limit: number;
} {
  return {
    offset: clamp(value.offset, 0, 1_000_000),
    limit: clamp(value.limit, 1, 100),
  };
}

function normalizeSettings(value: HunterSettings): HunterSettings {
  return {
    scanAllHistory: value.scanAllHistory === true,
    autoFetch: value.autoFetch === true,
    includeCredentials:
      value.autoFetch === true && value.includeCredentials === true,
    assetExclusions: normalizeExclusions(value.assetExclusions),
    maxDepth: clamp(value.maxDepth, 0, 5),
    maxAssetsPerRoot: clamp(value.maxAssetsPerRoot, 1, 2_000),
    maxBodyBytes: clamp(value.maxBodyBytes, 64 * 1024, 25 * 1024 * 1024),
    maxHistoryEntries: clamp(value.maxHistoryEntries, 100, 50_000),
    maxFindings: clamp(value.maxFindings, 100, 50_000),
  };
}

function cloneSettings(value: HunterSettings): HunterSettings {
  return { ...value, assetExclusions: [...value.assetExclusions] };
}

function normalizeExclusions(values: string[]): string[] {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.map((value) => value.trim().toLowerCase()))]
    .filter((value) => value.length > 0)
    .map((value) => clip(value, 120))
    .slice(0, 50);
}

function normalizeSearch(value: string): string {
  return clip(value.trim().toLowerCase(), 200);
}

function normalizeIgnored(kind: "rule" | "host", value: string): string {
  const normalized = value.trim();
  return kind === "host" ? normalized.toLowerCase() : normalized;
}

function clamp(value: number, minimum: number, maximum: number): number {
  const number = Number.isFinite(value) ? Math.trunc(value) : minimum;
  return Math.max(minimum, Math.min(maximum, number));
}

function clip(value: string, maximum: number): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
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
    reviewNote: row.review_note,
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

function toFile(row: FileRow): SensitiveFileDTO {
  return {
    assetUrl: row.asset_url,
    requestId: row.request_id,
    responseId: row.response_id,
    severity: row.severity,
    findings: row.findings,
    needsReview: row.needs_review,
    reviewed: row.reviewed,
    falsePositive: row.false_positive,
    rules: row.rules,
    fingerprints: row.fingerprints.split(",").filter(Boolean),
  };
}

function page<T>(
  items: T[],
  total: number,
  query: { offset: number; limit: number },
): Page<T> {
  return { items, total, offset: query.offset, limit: query.limit };
}

function severityRankSql(column: string): string {
  return `CASE ${column} WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END`;
}

function severityOrder(column: string): string {
  return severityRankSql(column);
}

function isSeverity(value: FindingQuery["severity"]): boolean {
  return ["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"].includes(value);
}

function isConfidence(value: FindingQuery["confidence"]): boolean {
  return ["ALL", "HIGH", "MEDIUM", "LOW"].includes(value);
}

function isKind(value: FindingQuery["kind"]): boolean {
  return [
    "ALL",
    "SECRET",
    "CREDENTIAL",
    "ENDPOINT",
    "IDENTIFIER",
    "CONFIGURATION",
  ].includes(value);
}

function isReviewFilter(value: FindingQuery["status"]): boolean {
  return ["ALL", "NEEDS_REVIEW", "REVIEWED", "FALSE_POSITIVE"].includes(value);
}

function isReviewStatus(value: string): value is ReviewStatus {
  return ["NEEDS_REVIEW", "REVIEWED", "FALSE_POSITIVE"].includes(value);
}

function isAssetFilter(value: AssetQuery["status"]): boolean {
  return [
    "ALL",
    "QUEUED",
    "FETCHING",
    "SCANNED",
    "SKIPPED",
    "FAILED",
    "CANCELLED",
  ].includes(value);
}

function hostOf(url: string): string {
  const match = url.match(/^https?:\/\/(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)/i);
  return match?.[1]?.toLowerCase() ?? "";
}
