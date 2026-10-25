# Remediation and exceptions

## Observed remediation

On 2026-10-25 a real scan of the first scratch image built with Go 1.26.4 found 13 HIGH, 10 MEDIUM and 1 LOW standard-library findings. The inventory and finding summary is preserved in [baseline-findings.json](evidence/baseline-findings.json), including the image config digest and SHA-256 of the original raw report. The raw baseline remains local/run evidence; committed data omits scanner prose and machine-specific details.

The response was to upgrade the actual build compiler and local test compiler to Go 1.27.3, resolve a new immutable builder digest, rebuild, and rescan against the same fresh database. The patched image produced zero findings in that scan. See [verification](verification.md) and the committed current scan summary for the exact artifact and database timestamps. No findings were suppressed, and `security/exceptions.json` remains empty. Future scans may find new issues and must rerun this process.

## Policy

Fix or remove vulnerable code first. A HIGH finding may be temporarily accepted only for the exact vulnerability ID, package, installed version and artifact digest. The record must include an accountable owner, a meaningful rationale, a repository evidence document, creation time and expiry no more than 14 days apart. Expiry is checked against the real UTC clock. Future-created, expired, duplicate, unused, wrong-version or wrong-digest entries fail. CRITICAL and unknown severities always fail, even if an exception entry exists.

The exception ledger has `schemaVersion: 1` and an `entries` array. Each entry must contain exactly these fields:

```json
{
  "id": "CVE-2099-0001",
  "package": "stdlib",
  "version": "v0.0.0-synthetic",
  "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "created": "2026-10-25T12:00:00Z",
  "expires": "2026-10-26T12:00:00Z",
  "owner": "maintainer",
  "reason": "Synthetic example only; replace with a justified, time-limited risk acceptance.",
  "evidence": "docs/exceptions/REPLACE_WITH_REVIEWED_EVIDENCE.md"
}
```

This is documentation, not an active entry. It intentionally cannot pass without a real evidence document. Tests construct temporary synthetic evidence and a fixed clock to prove valid and invalid behavior. Production has no clock override.

An evidence document should identify the exact artifact, describe reachable paths and compensating controls, link the upstream advisory or patch, specify the remediation owner/deadline, and explain the residual risk. The executable gate checks matching, lifetime and document presence; it cannot judge the truth of the rationale. Review the document and ledger together.

Both local `make scan` and the release path scope exceptions to the exported image manifest digest. The config digest separately binds the scanner inventory to the saved image. The release uses an OCI copy that preserves the original compressed layer and manifest bytes, then checks the registry digest equals the gated digest. A changed binary, dependency or layer requires reassessment and a new scoped entry.

## VEX decision

No VEX document or not-affected assertion is generated. There is no implemented reachability analysis or sufficient per-finding evidence to support one. Temporary acceptance never changes scanner severity and is not represented as proof of non-exploitability.
