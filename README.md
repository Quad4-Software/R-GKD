R-NIMKE

EXPERIMENTAL - DO NOT USE

Reticulum Non-Interactive Multi-Party Key Exchange

Initial Draft v1 - 14 July 2026 - Ivan 
LXMF: f489752fbef161c64d65e385a4e9fc74 

No LLMs was used in the creation of this document or crpytographic protocol. It is considered experimental until verified and extensively tested.

---

R-NIMKE is a way to allow for low-bandwidth and Reticulum Zen compatible encrypted group messaging over Reticulum Network Stack keeping large and small groups in mind. 

===
CRPTOGRAPHIC PRIMATIVES
===

  Identity / signatures:
    - Ed25519 signatures for group state

  Pairwise sealing (membership key distribution):
    - X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305

  Symmetric AEAD (messages):
    - ChaCha20-Poly1305 with 12-byte nonces (preferred with counters)
    - OR XChaCha20-Poly1305 with 24-byte nonces if counters are impractical
    Implementations MUST pick one and set a format flag. Do not mix.

  KDF / hash:
    - HKDF-SHA256
    - SHA-256

  Randomness:
    - 32-byte secrets from a CSPRNG

===
THREAT MODEL
===

The adversary may:

  - Read all traffic on intermediate links and relays.
  - Log all historical ciphertext indefinitely.
  - Inject, modify, reorder, replay, or drop packets.
  - Operate malicious peers or Propagation Nodes.
  - Serve old or alternate signed states if clients do not enforce
    monotonic state rules.
  - Compromise a member device at a point in time.
  - Compromise the administrator key (group is then burned).

The adversary is assumed NOT to break:

  - X25519 / Ed25519
  - ChaCha20-Poly1305 / XChaCha20-Poly1305
  - HKDF-SHA256 / SHA-256
  - Secure random number generation on honest devices


---

EXPERIMENTAL - DO NOT USE

DRAFT