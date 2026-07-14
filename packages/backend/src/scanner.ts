import type { SDK } from "caido:plugin";
import type {
  Cursor,
  ID,
  Request,
  RequestResponse,
  Response,
} from "caido:utils";
import { RequestSpec } from "caido:utils";

import { rulePack, scanText } from "./detector";
import { HunterStore } from "./store";
import type {
  AssetDTO,
  HunterSettings,
  MessageDetails,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "./types";

import type { BackendEvents } from "./index";

export type HunterSDK = SDK<Record<string, never>, BackendEvents>;
type ContentClass =
  "JAVASCRIPT" | "HTML" | "JSON" | "XML" | "TEXT" | "SOURCE_MAP" | "BINARY";
type Work = {
  generation: number;
  projectId: string;
  request: Request;
  response: Response;
  url: string;
  parentUrl: string;
  rootUrl: string;
  depth: number;
  expand: boolean;
};
type FetchWork = {
  generation: number;
  projectId: string;
  url: string;
  parentUrl: string;
  rootUrl: string;
  depth: number;
  parentRequest: Request;
};

export class HunterScanner {
  private readonly store = new HunterStore();
  private settings: HunterSettings = {
    scanAllHistory: true,
    autoFetch: true,
    maxDepth: 2,
    maxAssetsPerRoot: 200,
    maxBodyBytes: 5 * 1024 * 1024,
    maxHistoryEntries: 5_000,
    maxFindings: 10_000,
  };
  private state: ScanState = {
    phase: "IDLE",
    queued: 0,
    active: 0,
    scanned: 0,
    findings: 0,
    message: "Idle",
  };
  private generation = 0;
  private historyReading = false;
  private paused = false;
  private readonly queue: Work[] = [];
  private readonly fetchQueue: FetchWork[] = [];
  private activeWorkers = 0;
  private activeFetches = 0;
  private backgroundMonitorStarted = false;
  private readonly processed = new Set<string>();
  private readonly scheduled = new Set<string>();
  private readonly selfFetchUrls = new Set<string>();
  private readonly rootCounts = new Map<string, number>();

  async initialize(sdk: HunterSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSdk, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSdk, project) => {
      if (project !== null) void this.rescan(sdk, true);
      else this.cancel(sdk, "No active project");
    });
    await this.rescan(sdk, false);
    this.startBackgroundMonitor(sdk);
  }

  async getSnapshot(sdk: HunterSDK): Promise<Snapshot> {
    await this.store.initialize(sdk);
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined)
      return {
        findings: [],
        files: [],
        assets: [],
        state: { ...this.state, message: "No active Caido project" },
        settings: this.settings,
        rulePackVersion: rulePack.version,
        ignoredRules: [],
        ignoredHosts: [],
      };
    const values = await this.store.snapshot(projectId);
    const ignored = await this.store.getIgnored(projectId);
    this.state.findings = values.findings.length;
    return {
      ...values,
      state: this.copyState(),
      settings: this.settings,
      rulePackVersion: rulePack.version,
      ignoredRules: [...ignored.rules],
      ignoredHosts: [...ignored.hosts],
    };
  }

  async getMessage(
    sdk: HunterSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId as ID);
    if (pair === undefined) return undefined;
    return {
      requestId,
      responseId: pair.response?.getId() ?? "",
      request: pair.request.getRaw().toText(),
      response: pair.response?.getRaw().toText() ?? "",
    };
  }

  async setStatus(
    sdk: HunterSDK,
    fingerprints: string[],
    status: ReviewStatus,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    await this.store.setStatus(projectId, fingerprints, status);
    this.emitSnapshot(sdk);
  }

  async saveSettings(
    sdk: HunterSDK,
    settings: HunterSettings,
  ): Promise<HunterSettings> {
    this.settings = await this.store.saveSettings(settings);
    await this.rescan(sdk, true);
    return this.settings;
  }

  async clear(sdk: HunterSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    this.cancel(sdk, "Results cleared");
    await this.store.clearResults(projectId);
    this.state.scanned = 0;
    this.state.findings = 0;
    this.emitSnapshot(sdk);
    this.publishState(sdk);
  }

  async rescan(sdk: HunterSDK, clear: boolean): Promise<void> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) {
      this.cancel(sdk, "No active project");
      return;
    }
    this.generation += 1;
    const generation = this.generation;
    this.queue.length = 0;
    this.fetchQueue.length = 0;
    this.processed.clear();
    this.scheduled.clear();
    this.selfFetchUrls.clear();
    this.rootCounts.clear();
    this.state.scanned = 0;
    this.state.findings = clear ? 0 : await this.store.findingCount(projectId);
    if (clear) await this.store.clearResults(projectId);
    this.historyReading = true;
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Reading Caido HTTP History";
    this.publishState(sdk);
    this.emitSnapshot(sdk);
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: HunterSDK): void {
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Paused";
    this.publishState(sdk);
  }

  resume(sdk: HunterSDK): void {
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Resumed";
    this.publishState(sdk);
    this.pump(sdk);
    this.pumpFetches(sdk);
  }

  cancel(sdk: HunterSDK, message = "Queued work cancelled"): void {
    this.generation += 1;
    this.queue.length = 0;
    this.fetchQueue.length = 0;
    this.historyReading = false;
    this.paused = false;
    this.scheduled.clear();
    this.selfFetchUrls.clear();
    this.rootCounts.clear();
    this.state.phase = "IDLE";
    this.state.queued = 0;
    this.state.message = message;
    this.publishState(sdk);
  }

  async ignore(
    sdk: HunterSDK,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    await this.store.ignore(projectId, kind, value);
    this.emitSnapshot(sdk);
  }

  async restoreIgnored(sdk: HunterSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    await this.store.restoreIgnored(projectId);
    await this.rescan(sdk, true);
  }

  async createReplay(sdk: HunterSDK, requestId: string): Promise<string> {
    const session = await sdk.replay.createSession(requestId as ID);
    return session.getId();
  }

  async publishFinding(sdk: HunterSDK, fingerprint: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const finding = await this.store.getFinding(projectId, fingerprint);
    if (finding === undefined) throw new Error("Finding no longer exists");
    if (finding.status !== "REVIEWED")
      throw new Error("Review the finding before publishing it");
    if (finding.published) return;
    const pair = await sdk.requests.get(finding.requestId as ID);
    if (pair === undefined)
      throw new Error("Source request is no longer available");
    await sdk.findings.create({
      title: `[${finding.severity}] ${finding.ruleName}`,
      description:
        `JS Secret Hunter candidate\n\nAsset: ${finding.assetUrl}\nRule: ${finding.ruleId}\n` +
        `Confidence: ${finding.confidence}\nLine: ${finding.line}\nMasked value: ${finding.maskedValue}\n` +
        `Value SHA-256: ${finding.valueHash}\n\nEvidence: ${finding.preview}`,
      reporter: "JS Secret Hunter",
      dedupeKey: finding.fingerprint,
      request: pair.request,
    });
    await this.store.markPublished(projectId, fingerprint);
    this.emitSnapshot(sdk);
  }

  private async readHistory(
    sdk: HunterSDK,
    projectId: string,
    generation: number,
  ): Promise<void> {
    let cursor: string | undefined;
    let inspected = 0;
    try {
      while (
        inspected < this.settings.maxHistoryEntries &&
        generation === this.generation
      ) {
        const amount = Math.min(
          200,
          this.settings.maxHistoryEntries - inspected,
        );
        let query = sdk.requests
          .query()
          .descending("req", "created_at")
          .first(amount);
        if (cursor !== undefined) query = query.after(cursor as Cursor);
        const page = await query.execute();
        if (page.items.length === 0) break;
        for (const item of page.items) {
          if (generation !== this.generation) return;
          inspected += 1;
          if (item.response === undefined) continue;
          if (
            !this.settings.scanAllHistory &&
            !sdk.requests.inScope(item.request)
          )
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
            url: item.request.getUrl(),
            parentUrl: item.request.getUrl(),
            rootUrl: item.request.getUrl(),
            depth: 0,
            expand: true,
          });
          while (this.queue.length > 100 && generation === this.generation)
            await sleep(20);
        }
        if (!page.pageInfo.hasNextPage) break;
        cursor = page.pageInfo.endCursor;
      }
      if (generation === this.generation)
        this.state.message = `Queued ${inspected} recent History entries`;
    } catch (error) {
      this.state.message = `History scan failed: ${safeMessage(error)}`;
      sdk.console.error(this.state.message);
    } finally {
      if (generation === this.generation) {
        this.historyReading = false;
        this.finishIfIdle(sdk);
        this.publishState(sdk);
      }
    }
  }

  private async observe(
    sdk: HunterSDK,
    request: Request,
    response: Response,
  ): Promise<void> {
    if (this.selfFetchUrls.has(request.getUrl())) return;
    if (!this.settings.scanAllHistory && !sdk.requests.inScope(request)) return;
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) return;
    this.enqueue(sdk, {
      generation: this.generation,
      projectId,
      request,
      response,
      url: request.getUrl(),
      parentUrl: request.getUrl(),
      rootUrl: request.getUrl(),
      depth: 0,
      expand: true,
    });
  }

  private startBackgroundMonitor(sdk: HunterSDK): void {
    if (this.backgroundMonitorStarted) return;
    this.backgroundMonitorStarted = true;
    void this.monitorRecentHistory(sdk);
  }

  private async monitorRecentHistory(sdk: HunterSDK): Promise<void> {
    while (this.backgroundMonitorStarted) {
      await sleep(1_500);
      if (this.paused) continue;
      try {
        const projectId = await this.currentProjectId(sdk);
        if (projectId === undefined) continue;
        const generation = this.generation;
        const page = await sdk.requests
          .query()
          .descending("req", "created_at")
          .first(Math.min(200, this.settings.maxHistoryEntries))
          .execute();
        if (generation !== this.generation) continue;
        for (const item of page.items) {
          if (item.response === undefined) continue;
          if (
            !this.settings.scanAllHistory &&
            !sdk.requests.inScope(item.request)
          )
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
            url: item.request.getUrl(),
            parentUrl: item.request.getUrl(),
            rootUrl: item.request.getUrl(),
            depth: 0,
            expand: true,
          });
        }
      } catch (error) {
        sdk.console.error(
          `JS Secret Hunter background monitor failed: ${safeMessage(error)}`,
        );
      }
    }
  }

  private enqueue(sdk: HunterSDK, work: Work): void {
    const key = `${work.projectId}:${work.request.getId()}`;
    if (work.generation !== this.generation || this.processed.has(key)) return;
    this.processed.add(key);
    if (this.processed.size > this.settings.maxHistoryEntries * 2) {
      const oldest = this.processed.values().next().value as string | undefined;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    this.queue.push(work);
    this.state.queued = this.queue.length + this.fetchQueue.length;
    this.state.phase = this.paused ? "PAUSED" : "SCANNING";
    this.publishState(sdk);
    this.pump(sdk);
  }

  private pump(sdk: HunterSDK): void {
    if (this.paused) return;
    while (this.activeWorkers < 2 && this.queue.length > 0) {
      const work = this.queue.shift();
      if (work === undefined) break;
      this.activeWorkers += 1;
      this.syncState();
      this.publishState(sdk);
      void this.process(sdk, work)
        .catch((error) =>
          sdk.console.error(
            `JS Secret Hunter scan failed: ${safeMessage(error)}`,
          ),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          this.syncState();
          this.publishState(sdk);
          this.emitSnapshot(sdk);
          this.pump(sdk);
          this.finishIfIdle(sdk);
        });
    }
  }

  private async process(sdk: HunterSDK, work: Work): Promise<void> {
    if (work.generation !== this.generation) return;
    const contentClass = classify(work.request, work.response, work.url);
    if (contentClass === "BINARY") {
      await this.saveAsset(work, "SKIPPED", "Non-text response");
      return;
    }
    const body = work.response.getBody();
    if (body === undefined) {
      await this.saveAsset(work, "SKIPPED", "Empty response body");
      return;
    }
    const raw = body.toRaw();
    if (raw.length === 0 || raw.length > this.settings.maxBodyBytes) {
      await this.saveAsset(
        work,
        "SKIPPED",
        `Body exceeds ${this.settings.maxBodyBytes} byte limit`,
      );
      return;
    }
    const text = body.toText();
    const detected = scanText(text, work.url);
    const added = await this.store.addFindings(
      work.projectId,
      work.request.getId(),
      work.response.getId(),
      detected,
      this.settings.maxFindings,
    );
    this.state.findings += added;
    this.state.scanned += 1;
    await this.saveAsset(
      work,
      "SCANNED",
      `${detected.length} candidates; ${raw.length} bytes; ${contentClass.toLowerCase()}`,
    );
    if (added > 0) this.emitSnapshot(sdk);

    if (!work.expand || work.depth >= this.settings.maxDepth) return;
    if (
      contentClass !== "HTML" &&
      contentClass !== "JAVASCRIPT" &&
      contentClass !== "SOURCE_MAP"
    )
      return;
    for (const url of discoverAssets(work.url, text, contentClass))
      this.scheduleFetch(sdk, work, url);
  }

  private scheduleFetch(sdk: HunterSDK, parent: Work, url: string): void {
    if (!this.settings.autoFetch || parent.generation !== this.generation)
      return;
    const key = `${parent.projectId}:${parent.rootUrl}:${url}`;
    if (this.scheduled.has(key)) return;
    const count = this.rootCounts.get(parent.rootUrl) ?? 0;
    if (count >= this.settings.maxAssetsPerRoot) return;
    this.rootCounts.set(parent.rootUrl, count + 1);
    this.scheduled.add(key);
    let probe: RequestSpec;
    try {
      probe = new RequestSpec(url);
    } catch {
      return;
    }
    const work: FetchWork = {
      generation: parent.generation,
      projectId: parent.projectId,
      url,
      parentUrl: parent.url,
      rootUrl: parent.rootUrl,
      depth: parent.depth + 1,
      parentRequest: parent.request,
    };
    if (!sdk.requests.inScope(probe)) {
      void this.store.upsertAsset(
        assetFromFetch(work, "", "SKIPPED", "Outside Caido Scope"),
      );
      return;
    }
    this.fetchQueue.push(work);
    this.syncState();
    this.publishState(sdk);
    this.pumpFetches(sdk);
  }

  private pumpFetches(sdk: HunterSDK): void {
    if (this.paused) return;
    while (this.activeFetches < 2 && this.fetchQueue.length > 0) {
      const work = this.fetchQueue.shift();
      if (work === undefined) break;
      this.activeFetches += 1;
      this.syncState();
      this.publishState(sdk);
      void this.fetch(sdk, work)
        .catch((error) =>
          sdk.console.error(
            `JS Secret Hunter fetch failed: ${safeMessage(error)}`,
          ),
        )
        .finally(() => {
          this.activeFetches -= 1;
          this.syncState();
          this.publishState(sdk);
          this.emitSnapshot(sdk);
          this.pumpFetches(sdk);
          this.finishIfIdle(sdk);
        });
    }
  }

  private async fetch(sdk: HunterSDK, work: FetchWork): Promise<void> {
    if (work.generation !== this.generation) return;
    await this.store.upsertAsset(
      assetFromFetch(work, "", "FETCHING", "GET in progress"),
    );
    let url = work.url;
    for (let redirects = 0; redirects <= 3; redirects += 1) {
      const spec = requestFor(url, work.parentRequest);
      if (!sdk.requests.inScope(spec)) {
        await this.store.upsertAsset(
          assetFromFetch(
            { ...work, url },
            "",
            "SKIPPED",
            "Redirect left Caido Scope",
          ),
        );
        return;
      }
      this.selfFetchUrls.add(url);
      let result: RequestResponse;
      try {
        result = await sdk.requests.send(spec);
      } finally {
        this.selfFetchUrls.delete(url);
      }
      if (work.generation !== this.generation) return;
      const location = result.response.getHeader("Location")?.[0];
      if (
        result.response.getCode() >= 300 &&
        result.response.getCode() < 400 &&
        location !== undefined &&
        redirects < 3
      ) {
        const redirected = resolveUrl(url, location);
        if (redirected === undefined) break;
        url = redirected;
        continue;
      }
      this.enqueue(sdk, {
        generation: work.generation,
        projectId: work.projectId,
        request: result.request,
        response: result.response,
        url,
        parentUrl: work.parentUrl,
        rootUrl: work.rootUrl,
        depth: work.depth,
        expand: true,
      });
      return;
    }
    await this.store.upsertAsset(
      assetFromFetch(work, "", "FAILED", "Redirect limit reached"),
    );
  }

  private async saveAsset(
    work: Work,
    status: AssetDTO["status"],
    detail: string,
  ): Promise<void> {
    await this.store.upsertAsset({
      projectId: work.projectId,
      url: work.url,
      requestId: work.request.getId(),
      parentUrl: work.parentUrl,
      rootUrl: work.rootUrl,
      depth: work.depth,
      status,
      detail,
      updatedAt: new Date().toISOString(),
    });
  }

  private finishIfIdle(sdk: HunterSDK): void {
    if (
      this.historyReading ||
      this.queue.length > 0 ||
      this.fetchQueue.length > 0 ||
      this.activeWorkers > 0 ||
      this.activeFetches > 0
    )
      return;
    this.state.phase = "IDLE";
    this.state.message = `Background scan complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  private syncState(): void {
    this.state.queued = this.queue.length + this.fetchQueue.length;
    this.state.active = this.activeWorkers + this.activeFetches;
  }

  private publishState(sdk: HunterSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private emitSnapshot(sdk: HunterSDK): void {
    sdk.api.send("snapshot-updated");
  }
  private copyState(): ScanState {
    return { ...this.state };
  }

  private async currentProjectId(sdk: HunterSDK): Promise<string | undefined> {
    return (await sdk.projects.getCurrent())?.getId();
  }

  private async requireProjectId(sdk: HunterSDK): Promise<string> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) throw new Error("No active Caido project");
    return projectId;
  }
}

function classify(
  request: Request,
  response: Response,
  url: string,
): ContentClass {
  const contentType = (response.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  const path = url.toLowerCase().split(/[?#]/, 1)[0] ?? "";
  if (path.endsWith(".map")) return "SOURCE_MAP";
  if (
    /\.(?:m?js|cjs)$/.test(path) ||
    contentType.includes("javascript") ||
    contentType.includes("ecmascript")
  )
    return "JAVASCRIPT";
  if (
    contentType.includes("html") ||
    path.endsWith(".html") ||
    path.endsWith(".htm")
  )
    return "HTML";
  if (contentType.includes("json") || path.endsWith(".json")) return "JSON";
  if (contentType.includes("xml") || path.endsWith(".xml")) return "XML";
  if (
    contentType.startsWith("text/") ||
    request.getMethod().toUpperCase() === "OPTIONS"
  )
    return "TEXT";
  return "BINARY";
}

function discoverAssets(
  baseUrl: string,
  text: string,
  contentClass: ContentClass,
): string[] {
  const values = new Set<string>();
  const patterns: RegExp[] = [];
  if (contentClass === "HTML") {
    patterns.push(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi);
    patterns.push(
      /<link\b(?=[^>]*\brel\s*=\s*["'][^"']*(?:modulepreload|preload))[^>]*\bhref\s*=\s*["']([^"']+)["']/gi,
    );
  }
  if (contentClass === "JAVASCRIPT" || contentClass === "SOURCE_MAP") {
    patterns.push(
      /(?:import\s*(?:[^'"]*?\sfrom\s*)?|import\s*\(|require\s*\()\s*['"]([^'"]+)['"]/gi,
    );
    patterns.push(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/gim);
  }
  patterns.push(
    /((?:https?:)?\/\/[^\s'"<>]+?\.(?:m?js|cjs|map)(?:\?[^\s'"<>]*)?|(?:[./][^\s'"<>]*?\.(?:m?js|cjs|map)(?:\?[^\s'"<>]*)?))/gi,
  );
  for (const pattern of patterns) {
    let count = 0;
    for (
      let match = pattern.exec(text);
      match && count < 2_000;
      match = pattern.exec(text)
    ) {
      count += 1;
      const candidate = match[1] ?? match[2];
      if (candidate === undefined || candidate.trim().length === 0) continue;
      const resolved = resolveUrl(
        baseUrl,
        candidate
          .trim()
          .replace(/\\\//g, "/")
          .replace(/[),;]+$/, ""),
      );
      if (resolved !== undefined) values.add(resolved);
    }
  }
  return [...values];
}

function resolveUrl(base: string, candidate: string): string | undefined {
  if (/^(?:data|blob|javascript|webpack):/i.test(candidate)) return undefined;
  try {
    const baseParts = parseAbsoluteUrl(base);
    if (baseParts === undefined) return undefined;
    let resolved: string;
    if (/^https?:\/\//i.test(candidate)) resolved = candidate;
    else if (candidate.startsWith("//"))
      resolved = `${baseParts.scheme}:${candidate}`;
    else if (candidate.startsWith("/"))
      resolved = `${baseParts.origin}${candidate}`;
    else if (candidate.startsWith("?"))
      resolved = `${baseParts.origin}${baseParts.path}${candidate}`;
    else {
      const directory = baseParts.path.slice(
        0,
        baseParts.path.lastIndexOf("/") + 1,
      );
      const question = candidate.indexOf("?");
      const relativePath =
        question < 0 ? candidate : candidate.slice(0, question);
      const query = question < 0 ? "" : candidate.slice(question);
      resolved = `${baseParts.origin}${normalizePath(`${directory}${relativePath}`)}${query}`;
    }
    resolved = resolved.split("#", 1)[0] ?? resolved;
    const parsed = parseAbsoluteUrl(resolved);
    if (parsed === undefined || parsed.authority.includes("@"))
      return undefined;
    new RequestSpec(resolved);
    return resolved;
  } catch {
    return undefined;
  }
}

function requestFor(url: string, parent: Request): RequestSpec {
  const request = new RequestSpec(url);
  request.setHeader(
    "Accept",
    "application/javascript, text/javascript, application/json, text/*, */*;q=0.8",
  );
  for (const header of ["User-Agent", "Accept-Language"]) {
    const value = parent.getHeader(header)?.[0];
    if (value !== undefined) request.setHeader(header, value);
  }
  if (sameOrigin(url, parent.getUrl())) {
    for (const header of ["Cookie", "Authorization"]) {
      const value = parent.getHeader(header)?.[0];
      if (value !== undefined) request.setHeader(header, value);
    }
  }
  return request;
}

function sameOrigin(left: string, right: string): boolean {
  try {
    const target = new RequestSpec(left);
    const parent = new RequestSpec(right);
    return (
      target.getTls() === parent.getTls() &&
      target.getHost().toLowerCase() === parent.getHost().toLowerCase() &&
      target.getPort() === parent.getPort()
    );
  } catch {
    return false;
  }
}

function parseAbsoluteUrl(
  value: string,
):
  | { scheme: string; authority: string; origin: string; path: string }
  | undefined {
  const match = value.match(
    /^(https?):\/\/([^/?#]+)(\/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$/i,
  );
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  const scheme = match[1].toLowerCase();
  const authority = match[2];
  return {
    scheme,
    authority,
    origin: `${scheme}://${authority}`,
    path: match[3] ?? "/",
  };
}

function normalizePath(value: string): string {
  const output: string[] = [];
  for (const segment of value.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") output.pop();
    else output.push(segment);
  }
  return `/${output.join("/")}`;
}

function assetFromFetch(
  work: FetchWork,
  requestId: string,
  status: AssetDTO["status"],
  detail: string,
): AssetDTO {
  return {
    projectId: work.projectId,
    url: work.url,
    requestId,
    parentUrl: work.parentUrl,
    rootUrl: work.rootUrl,
    depth: work.depth,
    status,
    detail,
    updatedAt: new Date().toISOString(),
  };
}

function sleep(milliseconds: number): Promise<void> {
  // eslint-disable-next-line compat/compat -- Promise is provided by Caido's QuickJS runtime.
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
