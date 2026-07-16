import type { SDK } from "caido:plugin";
import type { Request, RequestResponse, Response } from "caido:utils";
import { RequestSpec } from "caido:utils";

import { classifyContent } from "./content-classifier";
import type { ContentClass } from "./content-classifier";
import { rulePack, scanText } from "./detector";
import { buildReport } from "./report";
import { HunterStore } from "./store";
import type {
  AssetDTO,
  AssetQuery,
  DataArea,
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

import type { BackendEvents } from "./index";

export type HunterSDK = SDK<Record<string, never>, BackendEvents>;

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
    autoFetch: false,
    includeCredentials: false,
    assetExclusions: [
      "jquery",
      "google-analytics",
      "googletagmanager",
      "gpt.js",
    ],
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
    dropped: 0,
    message: "Idle",
  };
  private generation = 0;
  private historyReading = false;
  private paused = false;
  private readonly queue: Work[] = [];
  private readonly fetchQueue: FetchWork[] = [];
  private activeWorkers = 0;
  private activeFetches = 0;
  private readonly activeByGeneration = new Map<number, number>();
  private backgroundMonitorStarted = false;
  private readonly processed = new Set<string>();
  private readonly scheduled = new Set<string>();
  private readonly selfFetchCounts = new Map<string, number>();
  private readonly rootCounts = new Map<string, number>();
  private revision = 0;
  private readonly pendingAreas = new Set<DataArea>();
  private changeScheduled = false;

  async initialize(sdk: HunterSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSdk, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSdk, project) => {
      if (project !== null) void this.rescan(sdk, false);
      else this.cancel(sdk, "No active project");
    });
    await this.rescan(sdk, false);
    this.startBackgroundMonitor(sdk);
  }

  async getOverview(sdk: HunterSDK): Promise<Overview> {
    await this.store.initialize(sdk);
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined)
      return {
        summary: emptySummary(),
        recentFindings: [],
        state: { ...this.state, message: "No active Caido project" },
        settings: this.settings,
        rulePackVersion: rulePack.version,
        ignoredRules: [],
        ignoredHosts: [],
      };
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [values, ignored] = await Promise.all([
      this.store.overview(projectId),
      this.store.getIgnored(projectId),
    ]);
    this.state.findings = values.summary.findingTotal;
    return {
      ...values,
      state: this.copyState(),
      settings: this.settings,
      rulePackVersion: rulePack.version,
      ignoredRules: [...ignored.rules],
      ignoredHosts: [...ignored.hosts],
    };
  }

  async listFindings(
    sdk: HunterSDK,
    query: FindingQuery,
  ): Promise<Page<FindingDTO>> {
    return this.store.listFindings(await this.requireProjectId(sdk), query);
  }

  async listEndpoints(
    sdk: HunterSDK,
    query: EndpointQuery,
  ): Promise<Page<FindingDTO>> {
    return this.store.listEndpoints(await this.requireProjectId(sdk), query);
  }

  async getEndpointSummary(sdk: HunterSDK): Promise<EndpointSummary> {
    return this.store.endpointSummary(await this.requireProjectId(sdk));
  }

  async listFiles(
    sdk: HunterSDK,
    query: FileQuery,
  ): Promise<Page<SensitiveFileDTO>> {
    return this.store.listFiles(await this.requireProjectId(sdk), query);
  }

  async listAssets(sdk: HunterSDK, query: AssetQuery): Promise<Page<AssetDTO>> {
    return this.store.listAssets(await this.requireProjectId(sdk), query);
  }

  async listRules(sdk: HunterSDK): Promise<RuleSummary[]> {
    const ignored = await this.store.getIgnored(
      await this.requireProjectId(sdk),
    );
    return rulePack.rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      kind: rule.kind,
      severity: rule.severity,
      confidence: rule.confidence,
      enabled: rule.enabled,
      ignored: ignored.rules.has(rule.id),
    }));
  }

  async getFinding(
    sdk: HunterSDK,
    fingerprint: string,
  ): Promise<FindingDTO | undefined> {
    return this.store.getFinding(await this.requireProjectId(sdk), fingerprint);
  }

  async exportReport(
    sdk: HunterSDK,
    format: ReportFormat,
  ): Promise<ReportFile> {
    const projectId = await this.requireProjectId(sdk);
    // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.all.
    const [findings, assets, rules] = await Promise.all([
      this.store.findings(projectId),
      this.store.assets(projectId),
      this.listRules(sdk),
    ]);
    return buildReport(format, { findings, assets, rules });
  }

  async getMessage(
    sdk: HunterSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId);
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
    await this.store.setStatus(
      await this.requireProjectId(sdk),
      fingerprints,
      status,
    );
    this.scheduleDataChanged(sdk, "overview", "findings", "files");
  }

  async setNote(
    sdk: HunterSDK,
    fingerprint: string,
    note: string,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    if ((await this.store.getFinding(projectId, fingerprint)) === undefined)
      throw new Error("Finding no longer exists");
    await this.store.setNote(projectId, fingerprint, note);
    this.scheduleDataChanged(sdk, "findings");
  }

  async saveSettings(
    sdk: HunterSDK,
    settings: HunterSettings,
  ): Promise<HunterSettings> {
    this.settings = await this.store.saveSettings(settings);
    this.cancel(
      sdk,
      "Settings saved; rebuild results to apply them to existing History",
    );
    this.scheduleDataChanged(sdk, "overview");
    return this.settings;
  }

  async analyzeRequest(sdk: HunterSDK, requestId: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined || pair.response === undefined)
      throw new Error("A saved request and response are required");
    if (!this.settings.scanAllHistory && !sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are disabled by Settings");
    const generation = this.generation;
    const work: Work = {
      generation,
      projectId,
      request: pair.request,
      response: pair.response,
      url: pair.request.getUrl(),
      parentUrl: pair.request.getUrl(),
      rootUrl: pair.request.getUrl(),
      depth: 0,
      expand: true,
    };
    this.incrementActive(generation);
    this.publishState(sdk);
    try {
      await this.process(sdk, work);
    } finally {
      this.decrementActive(generation);
      this.publishState(sdk);
      if (generation === this.generation) {
        this.scheduleDataChanged(
          sdk,
          "overview",
          "findings",
          "files",
          "assets",
        );
        this.finishIfIdle(sdk);
      }
    }
  }

  async clear(sdk: HunterSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const generation = this.stopForMutation(sdk, "Clearing results");
    if (!(await this.waitForOlderWorkers(generation))) return;
    await this.store.clearResults(projectId);
    if (generation !== this.generation) return;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.scanned = 0;
    this.state.findings = 0;
    this.state.message =
      "Results cleared; saved review decisions were retained";
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview", "findings", "files", "assets");
  }

  async rebuildResults(sdk: HunterSDK): Promise<void> {
    await this.rescan(sdk, true);
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
    this.selfFetchCounts.clear();
    this.rootCounts.clear();
    this.state.scanned = 0;
    this.state.dropped = 0;
    this.state.findings = clear ? 0 : await this.store.findingCount(projectId);
    this.historyReading = true;
    this.paused = clear;
    this.state.phase = clear ? "STOPPING" : "SCANNING";
    this.state.message = clear
      ? "Waiting for active work before rebuilding results"
      : "Reading Caido HTTP History";
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview");
    if (clear) {
      if (!(await this.waitForOlderWorkers(generation))) return;
      await this.store.clearResults(projectId);
      if (generation !== this.generation) return;
      this.paused = false;
      this.state.phase = "SCANNING";
      this.state.message = "Reading Caido HTTP History";
      this.publishState(sdk);
      this.scheduleDataChanged(sdk, "findings", "files", "assets");
    }
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: HunterSDK): void {
    if (this.state.phase !== "SCANNING") return;
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Background analysis paused";
    this.publishState(sdk);
  }

  resume(sdk: HunterSDK): void {
    if (this.state.phase !== "PAUSED") return;
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Background analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
    this.pumpFetches(sdk);
    this.finishIfIdle(sdk);
  }

  cancel(sdk: HunterSDK, message = "Queued work cancelled"): void {
    const cancelledFetches = [...this.fetchQueue];
    this.generation += 1;
    this.queue.length = 0;
    this.fetchQueue.length = 0;
    this.historyReading = false;
    this.paused = false;
    this.scheduled.clear();
    this.selfFetchCounts.clear();
    this.rootCounts.clear();
    this.state.phase = "IDLE";
    this.state.message = message;
    this.syncState();
    this.publishState(sdk);
    for (const work of cancelledFetches)
      void this.store
        .upsertAsset(assetFromFetch(work, "", "CANCELLED", "Cancelled"))
        .catch((error) =>
          sdk.console.error(
            `Failed to mark asset cancelled: ${safeMessage(error)}`,
          ),
        );
    this.scheduleDataChanged(sdk, "overview", "assets");
  }

  async ignore(
    sdk: HunterSDK,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    await this.store.ignore(await this.requireProjectId(sdk), kind, value);
    this.scheduleDataChanged(sdk, "overview", "findings", "files", "rules");
  }

  async unignore(
    sdk: HunterSDK,
    kind: "rule" | "host",
    value: string,
  ): Promise<void> {
    await this.store.unignore(await this.requireProjectId(sdk), kind, value);
    this.scheduleDataChanged(sdk, "overview", "rules");
  }

  async restoreIgnored(sdk: HunterSDK): Promise<void> {
    await this.store.restoreIgnored(await this.requireProjectId(sdk));
    this.scheduleDataChanged(sdk, "overview", "rules");
  }

  async createReplay(sdk: HunterSDK, requestId: string): Promise<string> {
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined) throw new Error("Source request is unavailable");
    const session = await sdk.replay.createSession(pair.request.toSpec());
    return session.getId();
  }

  async publishFinding(sdk: HunterSDK, fingerprint: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const finding = await this.store.getFinding(projectId, fingerprint);
    if (finding === undefined) throw new Error("Finding no longer exists");
    if (finding.status !== "REVIEWED")
      throw new Error("Review the finding before publishing it");
    if (finding.published) return;
    const pair = await sdk.requests.get(finding.requestId);
    if (pair === undefined)
      throw new Error("Source request is no longer available");
    await sdk.findings.create({
      title: `[${finding.severity}] ${finding.ruleName}`,
      description:
        `JS Secret Hunter candidate\n\nAsset: ${finding.assetUrl}\nRule: ${finding.ruleId}\n` +
        `Confidence: ${finding.confidence}\nLine: ${finding.line}\nMasked value: ${finding.maskedValue}\n` +
        `Value SHA-256: ${finding.valueHash}\n\nReviewer note: ${finding.reviewNote || "None"}\n\n` +
        `Evidence: ${finding.preview}\n\nRaw values and authentication material are not included. Validate the candidate manually.`,
      reporter: "JS Secret Hunter",
      dedupeKey: `js-secret-hunter:${finding.fingerprint}`,
      request: pair.request,
    });
    await this.store.markPublished(projectId, fingerprint);
    this.scheduleDataChanged(sdk, "overview", "findings");
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
        if (cursor !== undefined) query = query.after(cursor);
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
          this.enqueue(
            sdk,
            historyWork(generation, projectId, item.request, item.response),
          );
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
    if (this.paused || this.isSelfFetch(request.getUrl())) return;
    if (!this.settings.scanAllHistory && !sdk.requests.inScope(request)) return;
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) return;
    this.enqueue(
      sdk,
      historyWork(this.generation, projectId, request, response),
    );
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
          this.enqueue(
            sdk,
            historyWork(generation, projectId, item.request, item.response),
          );
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
      const oldest = this.processed.values().next().value;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    if (this.queue.length >= 2_000) {
      this.state.dropped += 1;
      this.publishState(sdk);
      return;
    }
    this.queue.push(work);
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
      this.incrementActive(work.generation);
      this.publishState(sdk);
      void this.process(sdk, work)
        .catch(async (error) => {
          sdk.console.error(
            `JS Secret Hunter scan failed: ${safeMessage(error)}`,
          );
          if (work.generation === this.generation)
            await this.saveAsset(work, "FAILED", safeMessage(error));
        })
        .finally(() => {
          this.activeWorkers -= 1;
          this.decrementActive(work.generation);
          this.publishState(sdk);
          this.pump(sdk);
          if (work.generation === this.generation) {
            this.scheduleDataChanged(
              sdk,
              "overview",
              "findings",
              "files",
              "assets",
            );
            this.finishIfIdle(sdk);
          }
        });
    }
  }

  private async process(sdk: HunterSDK, work: Work): Promise<void> {
    if (work.generation !== this.generation) return;
    const body = work.response.getBody();
    if (body === undefined) {
      await this.saveAsset(work, "SKIPPED", "Empty response body");
      return;
    }
    const raw = body.toRaw();
    if (raw.length === 0) {
      await this.saveAsset(work, "SKIPPED", "Empty response body");
      return;
    }
    if (raw.length > this.settings.maxBodyBytes) {
      await this.saveAsset(
        work,
        "SKIPPED",
        `Body exceeds ${this.settings.maxBodyBytes} byte limit`,
      );
      return;
    }
    const contentClass = classifyContent({
      contentType: (work.response.getHeader("Content-Type") ?? []).join(" "),
      url: work.url,
      method: work.request.getMethod(),
      bytes: raw,
    });
    if (contentClass === "BINARY") {
      await this.saveAsset(work, "SKIPPED", "Non-text response");
      return;
    }
    const text = body.toText();
    const detected = scanText(text, work.url);
    if (work.generation !== this.generation) return;
    const added = await this.store.addFindings(
      work.projectId,
      work.request.getId(),
      work.response.getId(),
      detected,
      this.settings.maxFindings,
    );
    if (work.generation !== this.generation) return;
    this.state.findings += added;
    this.state.scanned += 1;
    await this.saveAsset(
      work,
      "SCANNED",
      `${detected.length} candidates; ${raw.length} bytes; ${contentClass.toLowerCase()}`,
    );

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
    const work: FetchWork = {
      generation: parent.generation,
      projectId: parent.projectId,
      url,
      parentUrl: parent.url,
      rootUrl: parent.rootUrl,
      depth: parent.depth + 1,
      parentRequest: parent.request,
    };
    this.scheduled.add(key);
    const exclusion = this.settings.assetExclusions.find((value) =>
      url.toLowerCase().includes(value),
    );
    if (exclusion !== undefined) {
      void this.store
        .upsertAsset(
          assetFromFetch(
            work,
            "",
            "SKIPPED",
            `Matched auto-fetch exclusion: ${exclusion}`,
          ),
        )
        .then(() => this.scheduleDataChanged(sdk, "overview", "assets"))
        .catch((error) =>
          sdk.console.error(
            `Failed to record excluded asset: ${safeMessage(error)}`,
          ),
        );
      return;
    }
    const count = this.rootCounts.get(parent.rootUrl) ?? 0;
    if (count >= this.settings.maxAssetsPerRoot) return;
    let probe: RequestSpec;
    try {
      probe = new RequestSpec(url);
    } catch {
      return;
    }
    if (!sdk.requests.inScope(probe)) {
      void this.store
        .upsertAsset(assetFromFetch(work, "", "SKIPPED", "Outside Caido Scope"))
        .then(() => this.scheduleDataChanged(sdk, "overview", "assets"))
        .catch((error) =>
          sdk.console.error(
            `Failed to record skipped asset: ${safeMessage(error)}`,
          ),
        );
      return;
    }
    this.rootCounts.set(parent.rootUrl, count + 1);
    this.fetchQueue.push(work);
    void this.store
      .upsertAsset(assetFromFetch(work, "", "QUEUED", "Waiting to fetch"))
      .catch((error) =>
        sdk.console.error(`Failed to queue asset: ${safeMessage(error)}`),
      );
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview", "assets");
    this.pumpFetches(sdk);
  }

  private pumpFetches(sdk: HunterSDK): void {
    if (this.paused) return;
    while (this.activeFetches < 2 && this.fetchQueue.length > 0) {
      const work = this.fetchQueue.shift();
      if (work === undefined) break;
      this.activeFetches += 1;
      this.incrementActive(work.generation);
      this.publishState(sdk);
      void this.fetch(sdk, work)
        .catch(async (error) => {
          sdk.console.error(
            `JS Secret Hunter fetch failed: ${safeMessage(error)}`,
          );
          await this.store.upsertAsset(
            assetFromFetch(work, "", "FAILED", clip(safeMessage(error), 500)),
          );
        })
        .finally(() => {
          this.activeFetches -= 1;
          this.decrementActive(work.generation);
          this.publishState(sdk);
          this.pumpFetches(sdk);
          if (work.generation === this.generation) {
            this.scheduleDataChanged(sdk, "overview", "assets");
            this.finishIfIdle(sdk);
          }
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
      const spec = requestFor(
        url,
        work.parentRequest,
        this.settings.includeCredentials,
      );
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
      this.beginSelfFetch(url);
      let result: RequestResponse;
      try {
        result = await sdk.requests.send(spec);
      } finally {
        this.endSelfFetch(url);
      }
      if (work.generation !== this.generation) {
        await this.store.upsertAsset(
          assetFromFetch(work, "", "CANCELLED", "Cancelled while fetching"),
        );
        return;
      }
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
      detail: clip(detail, 500),
      updatedAt: new Date().toISOString(),
    });
  }

  private stopForMutation(sdk: HunterSDK, message: string): number {
    this.generation += 1;
    this.queue.length = 0;
    this.fetchQueue.length = 0;
    this.historyReading = false;
    this.paused = true;
    this.scheduled.clear();
    this.selfFetchCounts.clear();
    this.rootCounts.clear();
    this.state.phase = "STOPPING";
    this.state.message = message;
    this.publishState(sdk);
    return this.generation;
  }

  private async waitForOlderWorkers(generation: number): Promise<boolean> {
    while (
      [...this.activeByGeneration].some(
        ([activeGeneration, count]) =>
          activeGeneration !== generation && count > 0,
      )
    ) {
      if (generation !== this.generation) return false;
      await sleep(20);
    }
    return generation === this.generation;
  }

  private finishIfIdle(sdk: HunterSDK): void {
    if (
      this.historyReading ||
      this.queue.length > 0 ||
      this.fetchQueue.length > 0 ||
      (this.activeByGeneration.get(this.generation) ?? 0) > 0
    )
      return;
    this.state.phase = "IDLE";
    this.state.message = `Background scan complete: ${this.state.scanned} responses analyzed`;
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview", "findings", "files", "assets");
  }

  private incrementActive(generation: number): void {
    this.activeByGeneration.set(
      generation,
      (this.activeByGeneration.get(generation) ?? 0) + 1,
    );
  }

  private decrementActive(generation: number): void {
    const remaining = (this.activeByGeneration.get(generation) ?? 1) - 1;
    if (remaining <= 0) this.activeByGeneration.delete(generation);
    else this.activeByGeneration.set(generation, remaining);
  }

  private beginSelfFetch(url: string): void {
    this.selfFetchCounts.set(url, (this.selfFetchCounts.get(url) ?? 0) + 1);
  }

  private endSelfFetch(url: string): void {
    const remaining = (this.selfFetchCounts.get(url) ?? 1) - 1;
    if (remaining <= 0) this.selfFetchCounts.delete(url);
    else this.selfFetchCounts.set(url, remaining);
  }

  private isSelfFetch(url: string): boolean {
    return (this.selfFetchCounts.get(url) ?? 0) > 0;
  }

  private syncState(): void {
    this.state.queued = this.queue.length + this.fetchQueue.length;
    this.state.active = this.activeByGeneration.get(this.generation) ?? 0;
  }

  private publishState(sdk: HunterSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private scheduleDataChanged(sdk: HunterSDK, ...areas: DataArea[]): void {
    areas.forEach((area) => this.pendingAreas.add(area));
    if (this.changeScheduled) return;
    this.changeScheduled = true;
    setTimeout(() => {
      this.changeScheduled = false;
      if (this.pendingAreas.size === 0) return;
      this.revision += 1;
      const changed = [...this.pendingAreas];
      this.pendingAreas.clear();
      sdk.api.send("data-changed", { revision: this.revision, areas: changed });
    }, 400);
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

function historyWork(
  generation: number,
  projectId: string,
  request: Request,
  response: Response,
): Work {
  const url = request.getUrl();
  return {
    generation,
    projectId,
    request,
    response,
    url,
    parentUrl: url,
    rootUrl: url,
    depth: 0,
    expand: true,
  };
}

function emptySummary() {
  return {
    findingTotal: 0,
    endpointTotal: 0,
    needsReview: 0,
    reviewed: 0,
    falsePositive: 0,
    critical: 0,
    high: 0,
    fileTotal: 0,
    assetTotal: 0,
    published: 0,
  };
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

function requestFor(
  url: string,
  parent: Request,
  includeCredentials: boolean,
): RequestSpec {
  const request = new RequestSpec(url);
  request.setHeader(
    "Accept",
    "application/javascript, text/javascript, application/json, text/*, */*;q=0.8",
  );
  for (const header of ["User-Agent", "Accept-Language"]) {
    const value = parent.getHeader(header)?.[0];
    if (value !== undefined) request.setHeader(header, value);
  }
  if (includeCredentials && sameOrigin(url, parent.getUrl())) {
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

function clip(value: string, maximum: number): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function sleep(milliseconds: number): Promise<void> {
  // eslint-disable-next-line compat/compat -- Caido's async plugin runtime supports Promise.
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
