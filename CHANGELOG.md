# Changelog

All notable changes to this project are documented here.

## 1.1.0 - 2026-07-16

### Added

- Professional responsive UI with Dashboard, Findings, Sensitive Files, Assets, Rules, Reports, and Settings views.
- Server-side filtering and pagination for large projects, bulk review actions, persistent reviewer notes, and targeted analysis by Caido Request ID.
- Searchable rule library, reversible ignored rules and hosts, and project-level asset status tracking.
- Dedicated Endpoint Intelligence workspace with quoted-link extraction for absolute URLs, relative routes, legacy action resources, and dynamic template paths.
- Configurable auto-fetch exclusion substrings with safe defaults for common analytics and vendor noise.
- Sanitized HTML, JSON, and CSV reports with formula-injection protection.
- Explicit pause, resume, cancel, rebuild, and clear controls with accessible confirmations.
- Store, detector, report, utility, and component tests with enforced coverage thresholds.

### Changed

- Upgraded to Caido SDK 0.57.1, Vue 3.5, TypeScript 6, Vitest 4, Node.js 22, and pnpm 11.
- Automatic asset fetching is now off by default. Same-origin credential forwarding has a separate explicit consent control.
- Settings saves are non-destructive, and project changes no longer clear stored results.
- Detection reuses decoded views per response and produces source-aligned, additionally redacted previews.
- Background work is generation-aware, bounded, race-resistant, and reports dropped queue work.
- Published Caido Findings are deduplicated and contain redacted evidence only.

### Fixed

- Fixed stale or overlapping scan generations writing results after cancellation or rebuild.
- Fixed paused workers resuming while idle and asset fetches remaining stuck in `FETCHING` after errors.
- Fixed same-origin credential checks, redirect scope enforcement, duplicate self-fetch races, and host exclusion matching.
- Fixed CSV formula injection and evidence previews exposing nearby sensitive headers, URL credentials, or query values.
- Fixed unknown JavaScript escapes losing their backslash and endpoint previews retaining sensitive query values.
- Fixed unnecessary full-dataset snapshots and destructive automatic rescans during settings or project changes.

## 1.0.0 - 2026-07-14

- Initial Caido release.
- Added background scanning for existing History and live responses.
- Added a bounded recent-History monitor so background discovery remains reliable when a live response event is missed.
- Added JavaScript, source-map, and text-response analysis with 40 rules.
- Added scope-restricted recursive asset discovery and fetching.
- Added Sensitive Files, Findings, Links, Assets, and Settings views.
- Added review workflow, Replay integration, redacted Caido Findings, ignore controls, and redacted exports.
