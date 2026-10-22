# Feature report: professional reporting, dashboard drill-down, scan presets

## A. Summary

Three user-facing additions landed together because they share one theme —
making the results trustworthy and reviewable:

1. **Professional reports** — consolidated markdown/JSON/SARIF/HTML, per-finding
   reports, and an editable responsible-disclosure draft; every finding carries
   validation evidence, expected vs observed behaviour, impact, preconditions,
   safe reproduction, remediation and verification guidance.
2. **Dashboard drill-down** — a per-finding view and report export served only
   for files VEYRON itself recorded in local history.
3. **Scan presets** — `veyron scan --profile quick|standard|deep` trades
   coverage for speed.

## B. Original problem

Reports were machine-oriented and did not distinguish a corroborated finding
from a guess, and there was no way to see a single finding's evidence or hand a
tidy export to a stakeholder. Separately, every scan ran every scanner, which
was slow for a quick check. The dashboard could only summarise; it could not be
used to look at what a specific finding actually showed.

## C. Design

### Reports describe evidence, not verdicts

* The consolidated markdown ranks findings by the existing prioritisation score
  and includes a **validation evidence** section per finding, with a clear
  "unverified" marker when a finding is not `VALIDATED`.
* `render_finding_markdown` produces a standalone report for one finding.
* `render_disclosure_draft` produces an editable, **unsent** disclosure draft:
  VEYRON never contacts a security team, opens a ticket, or sends anything.
* The HTML report is self-contained with a strict CSP
  (`default-src 'none'`) and is fully escaped — finding text can never inject
  markup.

### Report set

`write_reports` writes the core formats (`markdown`, `json`, `sarif`, `html`)
directly and, when asked, a `findings/` directory of per-finding reports plus a
disclosure draft. To avoid changing the existing orchestrator contract,
`Orchestrator.outcome.reports` keeps only the four core formats; the extra paths
go into a new `outcome.extra_reports` field.

### Dashboard drill-down, confined to recorded files

New read-only routes:

* `GET /finding?assessment=<id>&id=<finding-id>` — one finding's evidence,
  escaped, rendered from the recorded JSON report.
* `GET /report/<assessment-id>/<fmt>` — serve a recorded report file.
* `GET /disclosure/<assessment-id>` — serve the recorded disclosure draft.

Every path is resolved and checked to live **under the reports directory**, and
`<assessment-id>` must match an id actually present in local history. The
dashboard still cannot be made to read an arbitrary file.

### Presets

| Preset | Scanners | AI |
| --- | --- | --- |
| `quick` | gitleaks + osv only | off |
| `standard` (default) | all configured | off (unless already on) |
| `deep` | all configured | keep configured setting |

AI is never enabled implicitly by a preset.

## D. Changed files

* `veyron/report/core.py` — `render_html`, `render_finding_markdown`,
  `render_disclosure_draft`, extended markdown, `write_reports` options.
* `veyron/orchestrator.py` — `extra_reports`; history now also records `profile`
  and the extra report paths.
* `veyron/cli.py` — `--format html`; `scan --profile`; `dast --report-dir` plus
  `_write_dast_reports()` converting DAST findings into the shared report model.
* `veyron/dashboard.py` — `load_assessment_context`, `recorded_report_path`,
  `render_finding_page`, the three routes, `Content-Disposition` support, and
  proxy/offline summary in the API payload.
* `tests/test_reports.py`, `tests/test_dashboard.py`, `tests/test_cli.py` —
  extended.

## E. Verification

* `tests/test_reports.py` asserts the HTML report escapes finding content and
  sets a strict CSP, that per-finding and disclosure files are produced, and
  that the "unverified" marker appears for non-validated findings.
* `tests/test_dashboard.py` asserts a finding page escapes a `<script>` payload,
  that a report path outside the reports directory yields 404, and that a
  recorded report exports correctly.
* `tests/test_cli.py` asserts the presets change the scanner set and the AI
  setting without performing a scan.
* A direct smoke test of `_write_dast_reports` produced the expected seven files
  (four core formats, two per-finding reports, one disclosure draft).

## F. Limitations and follow-up

* SARIF is the documented subset; per-finding SARIF is not emitted.
* The dashboard history is JSONL and re-read on each request; very large
  histories will want an index (out of scope here).
* The disclosure draft is templated; richer per-class drafting is future work.
