# Managed Support Zero-Copy: sealed receiver + atomic recovery gate

**Status: staged internal contract, no runtime authorization or deployment.**

## Implemented in this draft
- A standalone X25519 private key (mode 0600) bound to ONE canonical Installation ID and ONE opaque approved SPMZ request. Stored only inside Managed Support /data, never copied to Smart Pro System or Portal.
- Pure PHP libsodium sealed-box candidate construction using receiver public key, exact IID/ref/arch/issued/expiry and the existing SPMN/SPMS formats. Only the ciphertext and non-secret binding metadata are returned; node secret is not returned to the Portal.
- Python PyNaCl receiver checks all public and decrypted fields, version contract, time limits and permission flags. It returns only an **in-memory untrusted candidate**; no save_identity, no MeshAgent or Broker call.
- Tests exercise PHP→Python interop, tampering, wrong receiver, mismatched installation/request, expired/invalid packets, key continuity, zero silent reseed and no identity files. A separate Docker image smoke build checks python3-nacl installation.

## Explicitly NOT implemented
No generated Managed node, legacy pairing reactivation, REST endpoint, transaction, immutable envelope record, reconnection, credential acknowledgement, receiver public-key publication, installable version or image publishing. QA5 remains Advanced Monthly, Managed Support 3.19.3 STOPPED/unpaired.

## Next secure integration gates

1. **Receiver public-key provenance.** Managed Support's read-only /share mapping must **not** silently become broad write access to publish a key. Define a scoped, authenticated local delivery of the public key to the already paired Smart Pro System. The Tools Ed25519 device proof must sign \`installation_id | request_ref | receiver_public_key_hex\`; Portal pins this exact binding; Broker independently verifies it before issuance. Local write access to shared files does not itself authenticate a recipient.
2. **Single atomic identity issuance.** The current legacy consume_pairing inserts a node and then consumes a pairing in separate SQL statements. Do NOT invoke it for Zero-Copy. Require verified InnoDB transactional storage, exact ledger row lock, fresh entitlement and device proof and no existing/revoked nodes, then insert one node and the **single immutable sealed blob** within one transaction, commit, and audit. All code paths capable of inserting a Managed node (including legacy pairing) must share the per-installation concurrency invariant. Refuse on unknown DB state, commit or rollback outcome. Do not implement automatic retries that create a second node.
3. **Idempotent lost-response recovery.** After a committed issuance, on renewed independently authenticated exact-device proof, return ONLY the original sealed ciphertext for the original pinned receiver key and request ref. Do not regenerate node secrets or ciphertext; do not create a second node. An expired/changed/revoked binding blocks and requires operator-led reconciliation. The initial 10-minute passive pending offer disappears when claim state transitions, so the receiver must retain a bounded local request context and verify a fresh Broker-issued post-claim delivery receipt; the old pending offer alone is NOT a sufficient recovery authority.
4. **Receipt/ack.** A verified recipient persists the Managed identity privately, performs the existing Broker heartbeat, then sends a separately authenticated request-bound ack. Broker moves the ledger to \`verified\` only after exact node+installation readback; future credential delivery then closes. Activation does not grant technician Web/Terminal/Files/Desktop or bypass server authorization.
5. **Coordinated release.** Versioned Broker, Portal, Tools and Managed Support with CI and one authorized QA5 end-to-end activation. No intermediate live updates.

## Threat boundaries
Ed25519 on Tools proves possession of a private key initially paired using the Portal installation token; it does not prove hardware identity. An attacker with administrator-level control of the Home Assistant OS can compromise local keys; Zero-Copy does not claim to resist a compromised host. Ciphertext confidentiality alone is not identity authority. No plaintext node secret in shared storage, logs, WP options, HTML or Customer Portal.

## Validation points
- PHP sealed helper mirrored into the staged WordPress Broker 0.60.38 ZIP, which is **INTERNAL ONLY / DO NOT INSTALL**.
- Main source + tests in this draft PR and distinct WordPress Broker package. Exact binary matches and end-to-end contract alignment must be validated before a combined production release.
