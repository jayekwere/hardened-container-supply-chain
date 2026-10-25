# Release evidence

The release identity is `https://github.com/jayekwere/hardened-container-supply-chain/.github/workflows/release.yml@refs/tags/vMAJOR.MINOR.PATCH`, with issuer `https://token.actions.githubusercontent.com`. The verification helper constructs the exact identity from the supplied version tag and refuses mutable image references. The signature and both attestations must validate with normal transparency verification.

The CycloneDX predicate is generated from the same raw JSON inventory that the vulnerability gate evaluates. It includes the Go standard library version. The image's signed evidence predicate uses the custom type URI `https://github.com/jayekwere/hardened-container-supply-chain/evidence/v1`; this is a type identifier, not an externally certified schema or an SLSA provenance claim.

`release-evidence.json` has schemaVersion 1, sourceRevision, image (full digest reference), generatedAt, checksums (SHA-256 of scan, SBOM, database metadata and scanner version text), the exact exception ledger, builder workflow name and target platform. Cosign binds the predicate to the image manifest subject. The workflow checks the pushed manifest equals the locally gated manifest. The helper verifies signatures and expected predicate types; a consumer can decode the verified evidence to compare source revision, inventory and report hashes with downloaded assets.

Release assets include image-reference.txt, SBOM, scan report, database metadata, evidence predicate, verification output, checksums, and the packaged chart. `sha256sum -c checksums.txt` checks the principal report/chart assets. Checksums by themselves are not signatures; authenticate their values against the verified signed evidence when reviewing scan/SBOM data.

| Job | Token permissions | Reason |
| --- | --- | --- |
| quality / checks | contents: read | Checkout and test untrusted contributions without publishing capabilities |
| release / publish | contents: read, packages: write, id-token: write | Read source, publish image/attestations, request short-lived identity certificate |
| release / record | contents: write | Create release record/assets after verified publication |

The package token is passed through standard input for registry login and never printed. Checkout does not persist credentials. All remote workflow actions use immutable commit SHAs. Tag input is passed through environment variables, validated and quoted; no pull-request title/body is evaluated as a command.

Publication is not transactional. A push followed by a scan, signing, or verification failure may leave an unsigned image or a partial set of attestations. The final release record is withheld unless all required verifications succeed. Consumers must always verify the exact digest and both expected attestations. A mutable tag alone is insufficient evidence.

Official command references: [identity verification](https://docs.sigstore.dev/cosign/verifying/verify/), [CycloneDX inventory](https://trivy.dev/docs/latest/guide/supply-chain/sbom/), [Go release inputs](https://go.dev/dl/). These describe tool behavior; this project's executed results are recorded separately.
