import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { HunterScanner } from "./scanner";
import type { HunterSDK } from "./scanner";
import type {
  HunterSettings,
  MessageDetails,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "./types";

const scanner = new HunterScanner();

const hunterSDK = (sdk: SDK): HunterSDK => sdk as unknown as HunterSDK;
const getSnapshot = (sdk: SDK): Promise<Snapshot> =>
  scanner.getSnapshot(hunterSDK(sdk));
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
const saveSettings = (
  sdk: SDK,
  settings: HunterSettings,
): Promise<HunterSettings> => scanner.saveSettings(hunterSDK(sdk), settings);
const rescanHistory = (sdk: SDK): Promise<void> =>
  scanner.rescan(hunterSDK(sdk), true);
const clearResults = (sdk: SDK): Promise<void> => scanner.clear(hunterSDK(sdk));
const pause = (sdk: SDK): void => scanner.pause(hunterSDK(sdk));
const resume = (sdk: SDK): void => scanner.resume(hunterSDK(sdk));
const cancel = (sdk: SDK): void => scanner.cancel(hunterSDK(sdk));
const ignore = (
  sdk: SDK,
  kind: "rule" | "host",
  value: string,
): Promise<void> => scanner.ignore(hunterSDK(sdk), kind, value);
const restoreIgnored = (sdk: SDK): Promise<void> =>
  scanner.restoreIgnored(hunterSDK(sdk));
const createReplay = (sdk: SDK, requestId: string): Promise<string> =>
  scanner.createReplay(hunterSDK(sdk), requestId);
const publishFinding = (sdk: SDK, fingerprint: string): Promise<void> =>
  scanner.publishFinding(hunterSDK(sdk), fingerprint);

export type API = DefineAPI<{
  getSnapshot: typeof getSnapshot;
  getMessage: typeof getMessage;
  setStatus: typeof setStatus;
  saveSettings: typeof saveSettings;
  rescanHistory: typeof rescanHistory;
  clearResults: typeof clearResults;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
  ignore: typeof ignore;
  restoreIgnored: typeof restoreIgnored;
  createReplay: typeof createReplay;
  publishFinding: typeof publishFinding;
}>;

export type BackendEvents = DefineEvents<{
  "snapshot-updated": () => void;
  "scan-state": (state: ScanState) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getSnapshot", getSnapshot);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("setStatus", setStatus);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("clearResults", clearResults);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  sdk.api.register("ignore", ignore);
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
  FindingDTO,
  HunterSettings,
  MessageDetails,
  ReviewStatus,
  ScanState,
  SensitiveFileDTO,
  Snapshot,
} from "./types";
