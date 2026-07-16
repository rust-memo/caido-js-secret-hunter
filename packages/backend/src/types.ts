export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type FindingKind =
  "SECRET" | "CREDENTIAL" | "ENDPOINT" | "IDENTIFIER" | "CONFIGURATION";
export type ReviewStatus = "NEEDS_REVIEW" | "REVIEWED" | "FALSE_POSITIVE";
export type AssetStatus =
  "QUEUED" | "FETCHING" | "SCANNED" | "SKIPPED" | "FAILED" | "CANCELLED";
export type EndpointMethod =
  | "ANY"
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS"
  | "CONNECT";
export type EndpointSource =
  | "DETECTOR"
  | "LITERAL"
  | "FETCH"
  | "AXIOS"
  | "XHR"
  | "JQUERY"
  | "ROUTER"
  | "MARKUP"
  | "WEBSOCKET";
export type EndpointScope =
  "SAME_ORIGIN" | "CROSS_ORIGIN" | "NON_HTTP" | "UNKNOWN";

export type EndpointMetadata = {
  method: EndpointMethod;
  source: EndpointSource;
  scope: EndpointScope;
  parameters: string[];
  dynamic: boolean;
  canonical: string;
};

export type RuleDefinition = {
  id: string;
  name: string;
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  engine?: "REGEX" | "LINK_REFERENCE";
  keywords?: string[];
  regex?: string;
  secretGroup?: number;
  minEntropy?: number;
  minLength?: number;
  allowlistRegex?: string;
  enabled?: boolean;
  sensitiveValue?: boolean;
};

export type RulePack = {
  schemaVersion: number;
  version: string;
  releasedAt: string;
  rules: RuleDefinition[];
};

export type RuleSummary = Pick<
  RuleDefinition,
  "id" | "name" | "kind" | "severity" | "confidence" | "enabled"
> & {
  ignored: boolean;
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
  evidenceHighlight: string;
  rawValue: string;
  endpoint?: EndpointMetadata;
};

export type FindingDTO = Omit<DetectedFinding, "rawValue"> & {
  projectId: string;
  requestId: string;
  responseId: string;
  status: ReviewStatus;
  reviewNote: string;
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
  dropped: number;
  message: string;
};

export type HunterSettings = {
  scanAllHistory: boolean;
  autoFetch: boolean;
  includeCredentials: boolean;
  assetExclusions: string[];
  maxDepth: number;
  maxAssetsPerRoot: number;
  maxBodyBytes: number;
  maxHistoryEntries: number;
  maxFindings: number;
};

export type ProjectSummary = {
  findingTotal: number;
  endpointTotal: number;
  needsReview: number;
  reviewed: number;
  falsePositive: number;
  critical: number;
  high: number;
  fileTotal: number;
  assetTotal: number;
  published: number;
};

export type Overview = {
  summary: ProjectSummary;
  recentFindings: FindingDTO[];
  state: ScanState;
  settings: HunterSettings;
  rulePackVersion: string;
  ignoredRules: string[];
  ignoredHosts: string[];
};

export type FindingQuery = {
  search: string;
  severity: "ALL" | Severity;
  confidence: "ALL" | Confidence;
  kind: "ALL" | FindingKind;
  status: "ALL" | ReviewStatus;
  offset: number;
  limit: number;
};

export type EndpointQuery = {
  search: string;
  confidence: "ALL" | Confidence;
  status: "ALL" | ReviewStatus;
  method: "ALL" | EndpointMethod;
  scope: "ALL" | EndpointScope;
  offset: number;
  limit: number;
};

export type EndpointSummary = {
  observations: number;
  uniqueRoutes: number;
  dynamicRoutes: number;
  crossOrigin: number;
  parameterized: number;
  methods: Partial<Record<EndpointMethod, number>>;
  sources: Partial<Record<EndpointSource, number>>;
};

export type FileQuery = {
  search: string;
  offset: number;
  limit: number;
};

export type AssetQuery = {
  search: string;
  status: "ALL" | AssetStatus;
  offset: number;
  limit: number;
};

export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
};

export type DataArea = "overview" | "findings" | "files" | "assets" | "rules";

export type DataChanged = {
  revision: number;
  areas: DataArea[];
};

export type ReportFormat = "html" | "json" | "csv";

export type ReportFile = {
  filename: string;
  mediaType: string;
  content: string;
};

export type MessageDetails = {
  requestId: string;
  responseId: string;
  request: string;
  response: string;
};
