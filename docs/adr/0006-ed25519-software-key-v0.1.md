---
status: accepted
date: 2026-04-16
deciders: [maintainer]
consulted: []
informed: []
supersedes: []
superseded_by: []
---

# 0006 — Software ed25519 signing for v0.1 (TEE deferred to v0.3)

## Context and problem statement

A `.jes` is signed; the signature binds every event and the Merkle root to a key. The strength of the binding is the strength of the key's storage. An adversarial submitter who can extract the private key from their own machine can sign any `.jes` they want — including one that describes a session that did not happen the way they describe it.

The strongest defense is hardware-rooted attestation: TPM, Secure Enclave, Intel TDX, AWS Nitro Enclaves. These make the key unextractable and tie its signatures to an attested binary running in an attested environment. But they are complex to integrate, exclude users without the relevant hardware, and substantially extend the v0.1 build timeline.

v0.1 needs a signing posture that is honest about its limits, shippable in 30 days, and upgradable without breaking existing attestations.

## Decision drivers

- Time-to-release is a constraint; v0.1 ships at Day 30.
- v0.1 must be usable by a bounty hunter on a MacBook without hardware configuration.
- Signing must be byte-exact across platforms; the signature format cannot depend on OS-specific handling.
- The v0.1 threat posture must be credible even without hardware roots. An "adversarial economics" defense (fabricating a convincing fake session costs more than doing the work honestly) is acceptable at v0.1 provided it is stated plainly.
- Forward compatibility: the v0.1 signing surface must allow a drop-in TEE upgrade in v0.3 without changing the verifier contract.

## Considered options

- Software ed25519 stored at `~/.jesses/key` (v0.1 baseline)
- Software ed25519 with passphrase-encrypted at rest
- Age-encrypted software key (project-specific wrapping)
- Immediate TEE attestation (TPM / Secure Enclave / TDX / Nitro)
- Hardware security module (YubiKey, Solo)

## Decision outcome

**Chosen: software ed25519, stored unencrypted at `~/.jesses/key` for v0.1.** The honest v0.1 posture is that the submitter's machine is their own and an attacker with root there can extract any key. Wrapping the key in a passphrase or age envelope does not change the threat model meaningfully — it only adds UX friction. The v0.1 defense is the pre-commitment (ADR 0005) plus adversarial economics: fabricating a convincing fake session with correct extractor outputs, matching Rekor timestamps, and plausible event timing is costlier than doing the authorized work honestly. TEE attestation closes the residual gap in v0.3.

### Positive consequences

- Zero setup for the user. `jesses` generates the key on first run; no passphrase prompt.
- ed25519 is in the Go standard library; no third-party cryptography.
- 32-byte keys and 64-byte signatures; bit-exact across platforms.
- A v0.3 TEE upgrade replaces the private-key material with an attested enclave key; the public-key fingerprint changes per attestation anyway (pre-commitment). The envelope and predicate format do not change.

### Negative consequences

- An attacker with root on the submitter's machine can extract the key and produce signed fake attestations. This is explicitly accepted as the v0.1 residual gap and documented in `THREAT_MODEL.md` §7.
- Users are tempted to sync `~/.jesses/key` across machines (dotfile repos, cloud backup). The CLI should warn but cannot prevent this.
- Key compromise detection relies on behavioral signals (duplicate session IDs from different hosts) rather than cryptographic impossibility.

## Pros and cons of the options

### Software ed25519, unencrypted

- Good: zero friction; Go stdlib only; byte-exact
- Good: admits the limit plainly and plans the upgrade
- Bad: key extractable by local attacker (documented residual gap)

### Software ed25519, passphrase-encrypted

- Good: slows a casual attacker
- Bad: UX friction (every session prompts); easily defeated by keylogger or memory read
- Bad: presents as stronger than it is; false-assurance hazard

### Age-encrypted key

- Good: uses a well-reviewed wrapping format
- Bad: same fundamental limit; just a different wrapper; still extractable when unlocked

### Immediate TEE attestation

- Good: closes the residual gap at v0.1
- Bad: extends the v0.1 timeline by months; hardware fragmentation (Intel TDX vs SGX vs AMD SEV-SNP vs Apple Secure Enclave vs Nitro) is a substantial engineering surface
- Bad: excludes users without the relevant hardware; reduces v0.1 reach

### YubiKey / Solo

- Good: unextractable private key
- Bad: requires hardware purchase; session startup blocks on user touch
- Bad: Windows/WebAuthn integration inconsistent; increases install-time complexity

## Validation

- `internal/crypto` exposes a `Signer` interface with ed25519 as the v0.1 implementation. v0.3 adds a TEE implementation behind the same interface.
- Test `TestSignatureDeterminism` ensures signatures over canonical payloads are reproducible across runs (ed25519 is deterministic).
- The verifier path does not read the private key material; verification uses only the public key and is unaffected by the v0.1-to-v0.3 upgrade.

## Links

- `THREAT_MODEL.md` §7 (key extraction)
- ADR 0005 (pre-commitment — complements signing)
- `ROADMAP.md` §v0.3 (TEE attestation)
- `SPEC.md` §Signing
