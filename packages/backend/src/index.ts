import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { HunterScanner } from "./scanner";
import type { HunterSDK } from "./scanner";
import type {
  AssetDTO,
  AssetQuery,
  DataChanged,
  EndpointQuery,
  EndpointSummary,
  FileQuery,
  FindingDTO,
  FindingQuery,
  HunterSettings,
  MessageDetails,
  Overview,
  Page,
  ReportFile,
  ReportFormat,
  ReviewStatus,
  RuleSummary,
  ScanState,
  SensitiveFileDTO,
} from "./types";

const scanner = new HunterScanner();
const hunterSDK = (sdk: SDK): HunterSDK => sdk;

const getOverview = (sdk: SDK): Promise<Overview> =>
  scanner.getOverview(hunterSDK(sdk));
const listFindings = (
  sdk: SDK,
  query: FindingQuery,
): Promise<Page<FindingDTO>> => scanner.listFindings(hunterSDK(sdk), query);
const listEndpoints = (
  sdk: SDK,
  query: EndpointQuery,
): Promise<Page<FindingDTO>> => scanner.listEndpoints(hunterSDK(sdk), query);
const getEndpointSummary = (sdk: SDK): Promise<EndpointSummary> =>
  scanner.getEndpointSummary(hunterSDK(sdk));
const listFiles = (
  sdk: SDK,
  query: FileQuery,
): Promise<Page<SensitiveFileDTO>> => scanner.listFiles(hunterSDK(sdk), query);
const listAssets = (sdk: SDK, query: AssetQuery): Promise<Page<AssetDTO>> =>
  scanner.listAssets(hunterSDK(sdk), query);
const listRules = (sdk: SDK): Promise<RuleSummary[]> =>
  scanner.listRules(hunterSDK(sdk));
const getFinding = (
  sdk: SDK,
  fingerprint: string,
): Promise<FindingDTO | undefined> =>
  scanner.getFinding(hunterSDK(sdk), fingerprint);
const exportReport = (sdk: SDK, format: ReportFormat): Promise<ReportFile> =>
  scanner.exportReport(hunterSDK(sdk), format);
const getMessage = (
  sdk: SDK,
  requestId: string,
): Promise<MessageDetails | undefined> =>
  scanner.getMessage(hunterSDK(sdk), requestId);
const setStatus = (
  sdk: SDK,
  fingerprints: string[],
  status: ReviewStatus,
): Promise<void> => scanner.setStatus(hunterSDK(sdk), fingerprints, status);
const setNote = (sdk: SDK, fingerprint: string, note: string): Promise<void> =>
  scanner.setNote(hunterSDK(sdk), fingerprint, note);
const saveSettings = (
  sdk: SDK,
  settings: HunterSettings,
): Promise<HunterSettings> => scanner.saveSettings(hunterSDK(sdk), settings);
const analyzeRequest = (sdk: SDK, requestId: string): Promise<void> =>
  scanner.analyzeRequest(hunterSDK(sdk), requestId);
const rescanHistory = (sdk: SDK): Promise<void> =>
  scanner.rescan(hunterSDK(sdk), false, true);
const rebuildResults = (sdk: SDK): Promise<void> =>
  scanner.rebuildResults(hunterSDK(sdk));
const clearResults = (sdk: SDK): Promise<void> => scanner.clear(hunterSDK(sdk));
const pause = (sdk: SDK): void => scanner.pause(hunterSDK(sdk));
const resume = (sdk: SDK): void => scanner.resume(hunterSDK(sdk));
const cancel = (sdk: SDK): void => scanner.cancel(hunterSDK(sdk));
const ignore = (
  sdk: SDK,
  kind: "rule" | "host",
  value: string,
): Promise<void> => scanner.ignore(hunterSDK(sdk), kind, value);
const unignore = (
  sdk: SDK,
  kind: "rule" | "host",
  value: string,
): Promise<void> => scanner.unignore(hunterSDK(sdk), kind, value);
const restoreIgnored = (sdk: SDK): Promise<void> =>
  scanner.restoreIgnored(hunterSDK(sdk));
const createReplay = (sdk: SDK, requestId: string): Promise<string> =>
  scanner.createReplay(hunterSDK(sdk), requestId);
const publishFinding = (sdk: SDK, fingerprint: string): Promise<void> =>
  scanner.publishFinding(hunterSDK(sdk), fingerprint);

export type API = DefineAPI<{
  getOverview: typeof getOverview;
  listFindings: typeof listFindings;
  listEndpoints: typeof listEndpoints;
  getEndpointSummary: typeof getEndpointSummary;
  listFiles: typeof listFiles;
  listAssets: typeof listAssets;
  listRules: typeof listRules;
  getFinding: typeof getFinding;
  exportReport: typeof exportReport;
  getMessage: typeof getMessage;
  setStatus: typeof setStatus;
  setNote: typeof setNote;
  saveSettings: typeof saveSettings;
  analyzeRequest: typeof analyzeRequest;
  rescanHistory: typeof rescanHistory;
  rebuildResults: typeof rebuildResults;
  clearResults: typeof clearResults;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
  ignore: typeof ignore;
  unignore: typeof unignore;
  restoreIgnored: typeof restoreIgnored;
  createReplay: typeof createReplay;
  publishFinding: typeof publishFinding;
}>;

export type BackendEvents = DefineEvents<{
  "data-changed": (change: DataChanged) => void;
  "scan-state": (state: ScanState) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getOverview", getOverview);
  sdk.api.register("listFindings", listFindings);
  sdk.api.register("listEndpoints", listEndpoints);
  sdk.api.register("getEndpointSummary", getEndpointSummary);
  sdk.api.register("listFiles", listFiles);
  sdk.api.register("listAssets", listAssets);
  sdk.api.register("listRules", listRules);
  sdk.api.register("getFinding", getFinding);
  sdk.api.register("exportReport", exportReport);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("setStatus", setStatus);
  sdk.api.register("setNote", setNote);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("analyzeRequest", analyzeRequest);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("rebuildResults", rebuildResults);
  sdk.api.register("clearResults", clearResults);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  sdk.api.register("ignore", ignore);
  sdk.api.register("unignore", unignore);
  sdk.api.register("restoreIgnored", restoreIgnored);
  sdk.api.register("createReplay", createReplay);
  sdk.api.register("publishFinding", publishFinding);
  void scanner
    .initialize(hunterSDK(sdk))
    .catch((error) =>
      sdk.console.error(
        `JS Secret Hunter failed to initialize: ${String(error)}`,
      ),
    );
}

export type {
  AssetDTO,
  AssetQuery,
  AssetStatus,
  Confidence,
  DataArea,
  DataChanged,
  EndpointMetadata,
  EndpointMethod,
  EndpointQuery,
  EndpointScope,
  EndpointSource,
  EndpointSummary,
  FileQuery,
  FindingDTO,
  FindingKind,
  FindingQuery,
  HunterSettings,
  MessageDetails,
  Overview,
  Page,
  ProjectSummary,
  ReportFile,
  ReportFormat,
  ReviewStatus,
  RuleSummary,
  ScanState,
  SensitiveFileDTO,
  Severity,
} from "./types";
