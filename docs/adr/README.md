# Architecture Decision Records

This directory is the canonical log of `jesses` design decisions. Each record (ADR) captures one decision, the context that forced it, the alternatives considered, and the consequences the project now carries.

Format: [MADR 3.0](https://adr.github.io/madr/).

ADRs are immutable once accepted. A decision is reversed by superseding — writing a new ADR that supersedes the old one, with the supersession recorded in both files' frontmatter.

## Reading order

Start with 0001 if you are a new contributor: language choice sets every downstream constraint. Read in numerical order for a full history.

| # | Title | Status | Date |
|---|---|---|---|
| [0000](./0000-madr-template.md) | MADR template | — | 2026-04-16 |
| [0001](./0001-go-reference-implementation.md) | Go as reference implementation language | accepted | 2026-04-16 |
| [0002](./0002-in-toto-ite6-envelope.md) | in-toto ITE-6 envelope with new predicate URI | accepted | 2026-04-16 |
| [0003](./0003-rfc6962-merkle-tree.md) | RFC 6962 Merkle tree (byte-exact with CT) | accepted | 2026-04-16 |
| [0004](./0004-opentimestamps-rekor-only.md) | OpenTimestamps + Rekor as sole external anchors | accepted | 2026-04-16 |
| [0005](./0005-session-start-pre-commitment.md) | Mandatory session-start SCT-style pre-commitment | accepted | 2026-04-16 |
| [0006](./0006-ed25519-software-key-v0.1.md) | Software ed25519 signing for v0.1 (TEE deferred) | accepted | 2026-04-16 |
| [0007](./0007-dual-privacy-modes.md) | Dual privacy modes (raw vs input-hash only) | accepted | 2026-04-16 |
| [0008](./0008-exclusion-first-policy.md) | Exclusion-first policy evaluation | accepted | 2026-04-16 |
| [0009](./0009-platform-first-adoption.md) | Platform-first adoption via Immunefi | accepted | 2026-04-16 |
| [0010](./0010-commonhaus-over-self-foundation.md) | Commonhaus Foundation over self-founded entity | accepted | 2026-04-16 |

## Adding a new ADR

1. Copy `0000-madr-template.md` to the next free four-digit number and a hyphen-separated slug.
2. Fill in the template. If the ADR supersedes a prior decision, list it in the frontmatter and open a PR that edits both files.
3. Link the new ADR from this index.
4. Status lifecycle: `proposed` → `accepted` (merged) or `rejected` (closed without merge). Later: `deprecated` (no longer applies but not reversed) or `superseded by NNNN` (replaced).

## When to write an ADR instead of a PR description

Write an ADR when:

- The decision affects more than one package or more than one contributor's future work.
- A future maintainer reading the code alone cannot reconstruct why the code is shaped this way.
- The decision narrows or freezes a degree of freedom (e.g. "we will not support hash function X" or "the envelope format is ITE-6 and no other").

Do not write an ADR for:

- Bug fixes or incremental feature work without a design choice.
- Implementation details that are free to change later without user-visible effect.
- Style or tooling preferences (those go in `.golangci.yml`, `CONTRIBUTING.md`, or a repo setting).
