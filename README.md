# JS Secret Hunter for Caido

Background discovery and review of secrets, credentials, endpoints, identifiers, and sensitive configuration in Caido HTTP History and live responses.

> Use this plugin only on systems you are authorized to test. A match is a candidate, not proof of a valid secret.

## What it does

- Scans existing HTTP History on project open and continues scanning new responses in the background, with a bounded recent-History monitor as a fallback when an event is missed.
- Analyzes JavaScript, source maps, HTML, JSON, XML, and other text responses with a versioned 40-rule detector pack.
- Discovers referenced JavaScript files, modules, and source maps and can fetch them recursively.
- Shows matched files inside the plugin under **Sensitive Files**, with their original Caido request and response.
- Separates findings, discovered links/configuration, and the asset-fetch graph into dedicated tabs.
- Supports per-finding and per-file review states: `NEEDS_REVIEW`, `REVIEWED`, and `FALSE_POSITIVE`.
- Can send the source request to Replay or publish a reviewed, redacted Caido Finding.
- Supports search, filters, ignored rules/hosts, persistent review decisions, and redacted JSON/CSV export.

## Safety and privacy

- Raw secret values are used transiently for detection and are **not persisted** by the plugin.
- Stored and exported results contain a masked value, a SHA-256 value fingerprint, and a short evidence preview.
- Automatic asset fetching is restricted to Caido Scope before every request and redirect.
- `Cookie` and `Authorization` headers are copied only for same-origin asset requests.
- Fetching is bounded by depth, asset, response-size, History, and finding limits. Pause and cancel controls are available in the UI.

Review the evidence and test validity manually before reporting a finding. Encoded strings, examples, test keys, and public identifiers can still produce false positives.

## Installation

1. Download `plugin_package.zip` and `plugin_package.zip.sig` from the latest GitHub Release.
2. In Caido, open **Plugins** and choose **Install Package**.
3. Select `plugin_package.zip`.
4. Open **JS Secret Hunter** from the Caido sidebar.

The signature is published alongside the package so the release artifact can be verified with [PUBLIC_KEY.pem](PUBLIC_KEY.pem):

```bash
openssl pkeyutl -verify -pubin -inkey PUBLIC_KEY.pem \
  -sigfile plugin_package.zip.sig -rawin -in plugin_package.zip
```

## Recommended first run

1. Configure the target in **Caido Scope** before enabling automatic fetch.
2. Open the plugin and let the initial History scan finish.
3. Review **Sensitive Files** first, then inspect individual candidates under **Findings**.
4. Mark confirmed candidates as reviewed and noise as false positive.

The default scan covers up to 5,000 recent History entries, 5 MiB per response, two dependency levels, 200 discovered assets per root, and 10,000 findings. All limits are configurable in **Settings**.

## Development

Requirements: Node.js 20+ and pnpm 9.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm knip
pnpm build
```

The installable package is generated at `dist/plugin_package.zip`.

## العربية

الإضافة تفحص طلبات **HTTP History** القديمة والجديدة في الخلفية، وتعرض الملفات التي تحتوي على نتائج حساسة داخل واجهة الإضافة نفسها بدل بقائها مجرد ملاحظات في History. افتح تبويب **Sensitive Files** لمراجعة الملف والـrequest والـresponse، ثم صنّف النتائج إلى مؤكدة أو `False Positive`.

قبل تفعيل جلب ملفات JavaScript تلقائيًا، أضف الهدف إلى **Caido Scope**. الإضافة لا تحفظ القيمة السرية الخام؛ بل تحفظ قيمة مخفية وبصمة SHA-256 ومعاينة قصيرة للمراجعة.

## License

[MIT](LICENSE) © 2026 rust-memo
