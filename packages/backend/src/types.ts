export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type FindingKind =
  "SECRET" | "CREDENTIAL" | "ENDPOINT" | "IDENTIFIER" | "CONFIGURATION";
export type ReviewStatus = "NEEDS_REVIEW" | "REVIEWED" | "FALSE_POSITIVE";
export type AssetStatus =
  "QUEUED" | "FETCHING" | "SCANNED" | "SKIPPED" | "FAILED" | "CANCELLED";

export type RuleDefinition = {
  id: string;
  name: string;
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  keywords?: string[];
  regex: string;
  secretGroup?: number;
  minEntropy?: number;
  minLength?: number;
  allowlistRegex?: string;
  enabled?: boolean;
};

export type RulePack = {
  schemaVersion: number;
  version: string;
  releasedAt: string;
  rules: RuleDefinition[];
};

export type DetectedFinding = {
  fingerprint: string;
  valueHash: string;
  ruleId: string;
  ruleName: string;
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  assetUrl: string;
  line: number;
  start: number;
  end: number;
  preview: string;
  maskedValue: string;
  rawValue: string;
};

export type FindingDTO = Omit<DetectedFinding, "rawValue"> & {
  projectId: string;
  requestId: string;
  responseId: string;
  status: ReviewStatus;
  published: boolean;
  createdAt: string;
};

export type AssetDTO = {
  projectId: string;
  url: string;
  requestId: string;
  parentUrl: string;
  rootUrl: string;
  depth: number;
  status: AssetStatus;
  detail: string;
  updatedAt: string;
};

export type SensitiveFileDTO = {
  assetUrl: string;
  requestId: string;
  responseId: string;
  severity: Severity;
  findings: number;
  needsReview: number;
  reviewed: number;
  falsePositive: number;
  rules: string;
  fingerprints: string[];
};

export type ScanState = {
  phase: "IDLE" | "SCANNING" | "PAUSED" | "STOPPING";
  queued: number;
  active: number;
  scanned: number;
  findings: number;
  message: string;
};

export type HunterSettings = {
  scanAllHistory: boolean;
  autoFetch: boolean;
  maxDepth: number;
  maxAssetsPerRoot: number;
  maxBodyBytes: number;
  maxHistoryEntries: number;
  maxFindings: number;
};

export type Snapshot = {
  findings: FindingDTO[];
  files: SensitiveFileDTO[];
  assets: AssetDTO[];
  state: ScanState;
  settings: HunterSettings;
  rulePackVersion: string;
  ignoredRules: string[];
  ignoredHosts: string[];
};

export type MessageDetails = {
  requestId: string;
  responseId: string;
  request: string;
  response: string;
};
