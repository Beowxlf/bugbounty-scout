# HAR Analyzer

## Purpose

BugBountyScout HAR Analyzer reads an existing HTTP Archive (HAR) locally. It
does not replay requests or contact any host. Phase 2A provides:

- capture summaries and normalized endpoint inventory;
- sensitive-material presence and location detection with redacted values;
- request and response cookie review;
- conservative security-header observations;
- a third-party request and potential leakage map;
- API/sensitive-looking response cache observations;
- terminal, JSON, and Markdown output.

Use it only for traffic from owned assets, labs, or explicitly authorized bug
bounty targets.

## Exporting HAR safely

1. Confirm the target and account are authorized by the program.
2. Open browser developer tools and clear unrelated traffic.
3. Capture only the minimum workflow needed for the review.
4. Avoid using production credentials or real personal data.
5. Export the HAR to encrypted/local storage.
6. Analyze it locally and share only a reviewed, redacted derivative.
7. Delete the raw capture when it is no longer required.

Browser HAR exports can contain far more than visible page content. Treat every
raw HAR as sensitive evidence.

## Data a HAR may contain

- full request URLs and query strings;
- Authorization and custom API headers;
- request and response cookies;
- session identifiers, CSRF values, OAuth codes, and refresh tokens;
- request bodies, form fields, and uploaded metadata;
- response bodies containing account data or PII;
- internal hostnames and application endpoints;
- third-party analytics, support, advertising, and telemetry requests.

## Why redaction matters

BugBountyScout detects common sensitive categories and records their category
and location rather than intentionally preserving their value in analysis
objects. Reports additionally pass output through the shared redaction engine.
The original HAR is never rewritten, so it must remain protected.

Detection is pattern-based and can have false positives or false negatives.
Always manually inspect a report before sharing it. BugBountyScout never sends
potential secrets to provider APIs for validation.

## Example workflow

```bash
bbs har summary capture.har
bbs har endpoints capture.har
bbs har secrets capture.har
bbs har cookies capture.har
bbs har headers capture.har
bbs har third-parties capture.har
bbs har report capture.har --format markdown --output reports/capture.md
bbs har report capture.har --format json --output reports/capture.json
```

All commands are passive and local. Individual review commands accept `--json`
for machine-readable output.

## Example output

```text
Sensitive material (values redacted)
Category       Location          Name           Value
bearer_token   request header    Authorization  <redacted-bearer-token>
email          query parameter   email          <redacted-email>
```

The Markdown report contains a summary, endpoint inventory, sensitive-material
findings, cookie review, header review, third-party leakage map, cache review,
manual follow-up checklist, and redaction notice.

## Interpretation and limitations

- Root-domain comparison is an intentionally lightweight hostname heuristic,
  not a Public Suffix List implementation. Confirm third-party ownership.
- A missing security header may be irrelevant to a particular response.
- A wildcard CORS header is not automatically exploitable.
- Missing cookie attributes are informational or warning-level observations
  whose relevance depends on cookie purpose and transport context.
- Public, missing, or long-lived cache directives on an API or sensitive-looking
  route require manual review; they are not automatically vulnerabilities.
- Encoded, encrypted, binary, compressed, or novel secret formats may not be
  detected.
- Duplicate endpoints are normalized by method, host, and path; query parameter
  names, statuses, MIME types, and counts are aggregated.
- The analyzer does not decrypt TLS, decode arbitrary binary content, execute
  JavaScript, authenticate, scan, replay, exploit, or bypass controls.

## Manual validation guidance

Before reporting any observation:

1. Reconfirm scope and program restrictions.
2. Establish whether the data is sensitive and belongs to the authorized test
   account.
3. Determine whether behavior is intentional and security-relevant.
4. Reproduce only with the minimum passive or explicitly permitted action.
5. Avoid accessing other users' data.
6. Preserve concise redacted evidence.
7. Describe impact conditionally when exploitability has not been established.
8. Follow the program's reporting and data-retention rules.
