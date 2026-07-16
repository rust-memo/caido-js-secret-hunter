# JS Secret Hunter for Caido

Professional background discovery and triage of secrets, credentials, endpoints, identifiers, and sensitive configuration in Caido HTTP traffic.

> Use this plugin only on systems you are authorized to test. A match is a review candidate, not proof that a credential is valid.

## Highlights

- Scans existing HTTP History and monitors new responses without blocking Caido, restricted to domains in Caido Scope by default.
- Analyzes JavaScript, source maps, HTML, JSON, XML, and other text responses with a versioned 43-rule detector pack, including extensionless scripts served with generic metadata.
- Extracts absolute URLs, root/dot/slash-relative routes, legacy action resources, and dynamic template paths into a dedicated Endpoint Intelligence workspace.
- Infers HTTP method and call-site source for Fetch, Axios, XHR, jQuery, routers, markup, and WebSockets, then records scope, parameters, dynamic state, and canonical route patterns.
- Scores every endpoint from 0–100 using explainable positive and negative signals, suppresses weak module/asset/locale paths, and provides precision filters for focused review.
- Decodes escaped and Base64 content once per response, maps evidence back to the source line, and redacts neighboring credentials from previews.
- Provides dedicated Dashboard, Findings, Sensitive Files, Assets, Rules, Reports, and Settings workspaces.
- Uses server-side search, filters, sorting, pagination, and bounded queues so large projects do not send the full dataset to the UI.
- Supports bulk triage, persistent review notes, reversible rule/host exclusions, Replay handoff, and deduplicated redacted Caido Findings.
- Highlights the detected masked value in redacted evidence and scrolls source-aligned matches into view in the original response.
- Exports sanitized HTML, JSON, and CSV reports. CSV cells are protected against spreadsheet-formula injection.
- Can analyze one saved Caido Request ID without clearing existing project results.

## Safety and privacy

- Raw matched values are transient and are **not persisted** by the plugin. Stored results contain a masked value, a SHA-256 value hash, and a redacted evidence preview.
- History scans, live response monitoring, and targeted Request ID analysis follow **Caido Scope only by default**. All-History coverage is an explicit, warned opt-in.
- Cross-origin HTTP and WebSocket endpoint references found inside authorized responses are retained only when their destination also matches Caido Scope; same-origin routes remain eligible automatically.
- Automatic asset fetching is **off by default**. When enabled, every request and redirect must remain inside Caido Scope.
- Forwarding `Cookie` and `Authorization` is a separate, explicit opt-in and is limited to exact same-origin requests.
- Auto-fetch exclusions are configurable as bounded case-insensitive URL substrings; fresh installs include common analytics/vendor noise such as jQuery, Modernizr, GTM, and Facebook Events, while captured responses remain eligible for local secret analysis.
- History, response size, recursion depth, discovered assets, retained findings, and the live work queue are bounded.
- Saving Settings is non-destructive. Rebuild and clear operations are explicit and confirmed; matching review states and notes survive a rebuild.
- Clear results stores a per-project checkpoint: older captured History stays cleared across reloads and project changes until you explicitly choose Scan History or Rebuild, while newly captured responses remain eligible.
- Data is isolated per Caido project. Switching projects does not delete another project's results.
- Existing project databases are migrated in place. Rebuild results when you want older endpoint observations rescored with the v1.3 Precision Engine.

Encoded examples, public identifiers, test keys, and stale credentials can still produce false positives. Validate findings manually before reporting them.

## Installation

1. Download `plugin_package.zip`, `plugin_package.zip.sig`, and `SHA256SUMS` from the latest GitHub Release.
2. Verify the checksum and signature:

   ```bash
   sha256sum --check SHA256SUMS
   openssl pkeyutl -verify -pubin -inkey PUBLIC_KEY.pem \
     -sigfile plugin_package.zip.sig -rawin -in plugin_package.zip
   ```

3. In Caido, open **Plugins**, choose **Install Package**, and select `plugin_package.zip`.
4. Open **JS Secret Hunter** from the Caido sidebar.

The repository's verification key is [PUBLIC_KEY.pem](PUBLIC_KEY.pem).

## Recommended first run

1. Configure the authorized target in **Caido Scope**.
2. Open the plugin and run **Scan History**.
3. Review **Sensitive Files**, then triage individual candidates in **Findings**.
4. Add reviewer notes, mark confirmed candidates as reviewed, and classify noise as false positive.
5. Enable automatic asset fetching only if captured traffic does not already include the required dependencies.

Defaults select up to 5,000 in-scope History responses, 5 MiB per response, two dependency levels, 200 assets per root, and 10,000 retained findings. In scope-only mode, the scanner can inspect up to 50,000 recent entries to fill that eligible-response quota without analyzing out-of-scope traffic. These limits are bounded and configurable.

## Development

Requirements:

- Node.js 22 or newer
- pnpm 11.13.0
- A Caido version compatible with plugin SDK 0.57.1

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

The installable package is generated at `dist/plugin_package.zip`. Contribution and release expectations are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## العربية

الإضافة تفحص استجابات **HTTP History** القديمة والجديدة في الخلفية، ثم تعرض النتائج في واجهة احترافية تشمل لوحة ملخص، والنتائج، والملفات الحساسة، والأصول، والقواعد، والتقارير، والإعدادات. مساحة **Endpoint Intelligence** تعرض نوع الطلب، ومصدر الاستدعاء، والنطاق، والباراميترات، والمسارات الديناميكية، كما تمنح كل Endpoint درجة دقة من 100 مع توضيح أسبابها وإمكانية فلترة النتائج الضعيفة. عند فتح نتيجة يتم تمييز الجزء المكتشف داخل الدليل المنقّح، كما تنتقل استجابة المصدر تلقائيًا إلى التطابق عندما تكون إحداثيات النص الأصلية متاحة.

القيم السرية الخام لا تُحفظ؛ يتم الاحتفاظ بقيمة مخفية وبصمة SHA-256 ومعاينة منقّحة فقط. تحليل الـHistory والاستجابات الجديدة وRequest ID يعمل افتراضيًا على الدومينات المضافة إلى **Caido Scope فقط**، وأي ترقية من إصدار أقدم تتحول إلى هذا الوضع الآمن. يمكن تفعيل تحليل كل الـHistory من الإعدادات بعد تحذير وموافقة صريحة. جلب ملفات JavaScript تلقائيًا متوقف افتراضيًا، وأي طلب يتم تفعيله يجب أن يبقى داخل **Caido Scope**. تمرير `Cookie` أو `Authorization` يحتاج موافقة منفصلة ولا يعمل إلا لنفس المصدر تمامًا.

حفظ الإعدادات لا يمسح النتائج. عند استخدام **Clear results** تبقى النتائج القديمة محذوفة حتى بعد إعادة تحميل الإضافة أو تغيير المشروع، ولا تعود إلا عند تشغيل **Scan History** أو **Rebuild results** صراحةً. تم إصلاح خطأ `database is locked` في الإصدار 1.2.2. الاستجابات الجديدة تظل قابلة للتحليل. راجع كل نتيجة يدويًا قبل اعتبارها تسريبًا مؤكدًا.

## License

[MIT](LICENSE) © 2026 rust-memo

Quoted-link discovery is conceptually inspired by the MIT-licensed [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder), PortSwigger's [js-link-finder](https://github.com/portswigger/js-link-finder), and the original [LinkFinder](https://github.com/GerbenJavado/LinkFinder). The Caido extractor is an independent TypeScript implementation with call-site inference, explainable precision scoring, stricter noise filtering, template-route normalization, redaction, and bounded processing. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
