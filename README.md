# R-GKD

EXPERIMENTAL - DRAFT

Reticulum Group Key Distribution

Initial Draft v1 - 14 July 2026 - Ivan
LXMF: f489752fbef161c64d65e385a4e9fc74

---

Small-group crypto for apps using Reticulum or LXMF. Application layer only: not an RNS destination type, not a transport replacement, not a server that decrypts for you.

Idea is simple. An admin shares a group root secret once. After that, ordinary messages are just a short header plus ciphertext. No handshake per message. Join, leave, and rekey are where you spend airtime.

Payloads are opaque. Ship them over Single/Link, LXMF (prop nodes optional), paper/QR, resources, whatever works. If multi-hop Group Destinations get cheaper later, they can carry the same blobs.

## Why it sits beside RNS, not inside it

Discussions [705](https://github.com/markqvist/Reticulum/discussions/705), [702](https://github.com/markqvist/Reticulum/discussions/702), [772](https://github.com/markqvist/Reticulum/discussions/772) split two problems:

1. RNS Group Destinations: multicast to whoever is online when the packet goes out
2. LXMF-style group chat: still has to work offline, partitioned, roaming, delayed via prop nodes or paper

Markqvist's take in [702](https://github.com/markqvist/Reticulum/discussions/702): LXMF group messaging cannot hang on RNS multicast for that asynchrony.

## Stance

Hostile network. Bytes on the air are expensive. CPU and disk are not. One admin signs membership. If that admin key burns, abandon the group. Keep the mechanisms intentionally boring.

Rekey at N=16 is about 3.2 KiB once (state 1292 + keydist 1978). Wire `member_count` is uint16, but v1 apps must refuse anything above 16. Bigger communities: several small groups. Seals can also move paper / OOB when flooding keydist is too rich.

## Threat model

Adversary can read links, keep ciphertext forever, inject/reorder/replay/drop, run bad peers or prop nodes, feed stale signed states to clients that ignore monotonic rules, partition members onto different highest `state_seq`, crash or roll devices back to reuse counters, compromise a member later, or steal the admin key (group burned).

Assumed unbroken on honest devices: X25519, Ed25519, ChaCha20-Poly1305 / XChaCha20-Poly1305, HKDF-SHA256, SHA-256, CSPRNG.

## Claims

What we try for:

- Confidentiality for holders of the GRS used to derive keys
- Integrity via AEAD
- Membership authenticity via admin Ed25519 + local monotonic `state_seq`
- Keydist authenticity: admin signs keydist, signed state commits to GRS (`grs_commit`), so a forged seal cannot swap in a different secret
- Kick: removed members do not get GRS_{v+1} (does not heal an attacker who still owns a remaining device)

What we do **not** claim while GRS_v sits on disk: forward secrecy inside that version. Epochs provide key separation and replay namespaces, not forward secrecy. Possession of GRS_v permits derivation of every CK_v,t for any representable t. Closing someone out of future traffic means a new GRS and new `state_seq`.

Optional: derive the CK values you need soon, erase GRS, keep only those CK. Without GRS you cannot mint other epochs, and you cannot follow TIME_BUCKET / LOCAL_COUNTER into new epochs until a fresh seal. Not the default.

Also not goals: cheap join/leave, admin recovery without a new group, MLS-style continuous PCS, strong metadata privacy, malicious-admin resistance, global membership consensus under partition.

## Encoding

Unsigned big-endian integers. Fixed fields, no padding. Counts prefix their arrays. `extensions_len = 0` and no extension bytes in v1.

Ed25519 signs the exact bytes defined below (no extra hash unless stated). Reject trailing junk on state, keydist, and ordinary messages.

Member rows sorted by MemberID ascending (raw 16-byte order). Keydist recipients should match roster order. Verifiers do not require that order, but the admin signature covers whatever byte sequence was published.

## Objects and identity

Peers are ordinary RNS Identities. Public key is 64 bytes: X25519 || Ed25519. R-GKD uses those halves. No parallel long-term seal keypair.

| Name | Size | Notes |
|------|------|--------|
| GroupID | 16 | Random at create. Fixed for the group |
| AdminPub | 32 | Admin Ed25519 half |
| MemberID | 16 | Unique in group. Admin-assigned |
| MemberPub | 32 | Member X25519 half |
| GRS_v | 32 | Root secret for version v. Never cleartext on the wire |
| state_seq | uint32 | Starts at 1. Bumps on membership change or rekey |
| epoch t | uint32 | Under the active epoch policy |

### Binding MemberPub to a destination

Before sealing to someone or accepting their attributable signatures:

1. Resolve `reticulum_dst_hash` to a full RNS public key you already trust (signed announce you accept, authenticated link, or OOB export).
2. Split into X25519 || Ed25519.
3. `member_x25519_pub` must equal the X25519 half.
4. Optional message signatures verify under that same Ed25519 half.
5. `member_key_version` bumps only when that identity's key material is replaced. Stable identity: keep it at 1.

AdminPub is fixed the same way at group creation. Changing admin means a new group.

The admin MUST identity-bind a member before adding that row to state or sealing GRS to them. Other clients MAY accept an admin-signed row as **pending** until they independently resolve the identity. A rostered recipient may receive and unseal its own seal only after verifying that the row matches its local identity (MemberID and MemberPub). Pending on a third-party receiver does not mean the admin skipped binding.

If a receiver cannot resolve a row yet: store the signed state, mark the member pending, do not seal to them as a helper, do not treat MemberPub as bound, do not accept attributable signatures. When binding steps 1-3 succeed, mark **active**. On pubkey mismatch, stay pending and surface an error. Do not activate on "admin said so" alone. Bare X25519 with no `reticulum_dst_hash` is rejected.

## Key hierarchy

GRS_v is 32 CSPRNG bytes on create/rekey.

Epoch keys are **direct** HKDF from GRS. No hash chain from t=0. TIME_BUCKET epochs around 2^24 to 2^25 must stay O(1).

```
CK_v,t = HKDF(GRS_v, salt=GroupID,
              info="RGKD1-EPOCH" || be32(v) || be32(t), 32)

SK_s,v,t = HKDF(CK_v,t, salt=GroupID,
                info="RGKD1-SENDER" || MemberID_s || be32(v) || be32(t), 32)

MK = HKDF(SK_s,v,t, salt=GroupID,
          info="RGKD1-MSG" || be32(c_s), 32)

nonce_12 = SHA-256("RGKD1-NONCE" || GroupID || MemberID_s ||
                   be32(v) || be32(t) || be32(c_s))[0:12]
```

Format 1 encrypts with ChaCha20-Poly1305(MK, nonce_12).

### Epoch policy

In signed state.

**TIME_BUCKET (1)** is the default for interoperable groups.

- `bucket_seconds` >= 60
- `t = floor(unix_time / bucket_seconds)` UTC
- Senders use the current bucket. Receivers accept +/- 1 around their current bucket (wider only if you know clocks are skewed). Outside: buffer or drop.

**LOCAL_COUNTER (2)** is fine for single-stack deployments. Each sender owns its own `t` and `c_s`. `t` is non-decreasing. Reset `c_s` to 0 on each `t` advance and each new `state_seq`. Advance `t` before `c_s` would wrap past 2^32-1. Receivers take `t` from the message header while they hold GRS or that CK. Multi-vendor groups should stick to TIME_BUCKET.

### Counters and crashes

Never encrypt two different plaintexts under the same (key, nonce).

Format 1 derives both MK and nonce_12 from `(GroupID, MemberID, state_seq, epoch, counter)`. Atomically reserve counter `c` in stable storage before constructing or transmitting a message that uses `c`. Once reserved, treat `c` as consumed even if transmission fails or the process crashes. After crash or backup restore, if you cannot prove the next unused counter, advance epoch (LOCAL_COUNTER), wait for the next time bucket (TIME_BUCKET) and reset the counter high-water, or use format 2 carefully.

Format 2 is XChaCha20-Poly1305 with a random 24-byte nonce. Fresh unique nonces with one MK are fine for XChaCha. Device rollback can also roll RNG state. If you cannot guarantee a nonce was never used with that MK, change MK first (new epoch / fresh reserved counter after persistence is healthy). Prefer format 1 on tight links when persistence works.

### Replay

Per `(MemberID, state_seq, epoch)` keep `max_c` and a bitset of recently seen counters. Minimum window **1024**. Before any counter is committed, `max_c` is unset (no high-water yet). The first successfully authenticated counter initializes `max_c` to that value.

Receive order (important):

1. Tentative check only (do not mutate window state):
   - if `max_c` is set and `c <= max_c` and `max_c - c >= window_size`: too old, drop
   - if `c` is already marked seen: drop
2. Attempt AEAD authentication and any required member signature
3. Only after both succeed: mark `c` seen, and if `c > max_c` set `max_c = c` (trim the bitset)
4. Deliver

An unauthenticated attacker must not be able to advance `max_c` with a forged large counter. Use overflow-safe comparisons as above (`c + window_size` is not used).

Persist replay state when you can. If you lose it, do not widen acceptance. Out-of-order LXMF inside the window is OK. High-water mark alone is not.

## Group state

Signed state is membership authority for anyone who has verified it.

| Field | Size | Notes |
|-------|------|--------|
| magic | 4 | "RG1S" |
| version | 1 | 1 |
| group_id | 16 | |
| state_seq | 4 | uint32 |
| prev_state_hash | 32 | SHA-256 of previous state_body, or zeros if state_seq = 1 |
| created_unix | 8 | uint64 UTC |
| epoch_policy | 1 | 1 = TIME_BUCKET, 2 = LOCAL_COUNTER |
| bucket_seconds | 4 | 0 if LOCAL_COUNTER |
| flags | 2 | bit0 = rekey |
| admin_pub | 32 | Admin Ed25519 half |
| grs_commit | 32 | SHA-256("RGKD1-GRS" \|\| group_id \|\| be32(state_seq) \|\| GRS_v) |
| member_count | 2 | uint16 |
| members | 68 × N | sorted by MemberID |
| extensions_len | 2 | 0 in v1 |
| extensions | variable | empty in v1 |

Member entry: member_id (16), reticulum_dst_hash (16), member_x25519_pub (32), member_key_version (4).

`state_body` = fields above, canonical. `state_object` = state_body || Ed25519.Sign(AdminPriv, state_body).

Accept only if magic/version match, `flags & ~KNOWN_STATE_FLAGS == 0` (v1 known bit: rekey), `extensions_len == 0`, `member_count` in 0..16, members sorted unique, signature verifies under the known AdminPub, `state_seq` advances (or same seq with identical body hash), never activate a lower seq after a higher one on that device, and if seq is last+1 with previous body held then `prev_state_hash` matches. Receivers may keep unbound rows pending. Two different bodies under the same admin and same `state_seq` burn the group.

After unseal, check `grs_commit`. Size: 204 + 68N (1292 at N=16).

### Historical states

Messages carry `state_seq`. Resolve the sender against **that** roster, not always the latest.

Until grace expires, keep at least current and previous verified state_objects, GRS/CK for those versions, and their replay windows. After grace for v-1, erase GRS_{v-1} and its CK. Departed members remain decryptable for messages under a historical state_seq that still has keys. "Not on current roster" alone is not a drop reason for that case.

### Partitions

Monotonic `state_seq` is per device. Under partition, honest members can disagree on the highest seq. No global consensus in v1. Gossip what you accept. When connectivity returns, highest valid seq wins. Admins: do not mint divergent same-seq states.

## Membership

**Create:** GroupID, admin identity, GRS_1, sign state_seq=1 with grs_commit, seal to each member, publish state + signed keydist.

**Join:** bump to v+1. Default: fresh GRS, seal to everyone including joiner, set rekey flag.

Weaker option: seal existing GRS_v to the joiner only. **No backward secrecy.** Joiner learns GRS_v and can derive every CK for that version (past epochs included). Prefer rekey.

**Leave/kick:** fresh GRS_{v+1}, seal only to remaining members. After grace, erase old GRS.

Seal:

```
eph_pub, eph_priv = X25519_Generate()
ss = X25519(eph_priv, MemberPub_i)
# Reject all-zero MemberPub and all-zero ss
seal_key = HKDF(ss, salt=GroupID, info="RGKD1-SEAL" || MemberID_i, 32)
plaintext = GRS (32) || group_id (16) || be32(state_seq)
nonce_12 = SHA-256("RGKD1-SEAL" || eph_pub || MemberID_i || be32(state_seq))[0:12]
AAD = group_id || be32(state_seq) || MemberID_i
ct||tag = ChaCha20-Poly1305(seal_key, nonce_12, AAD, plaintext)
SealBlob = eph_pub (32) || ct||tag (68)
```

Keydist (then admin signature over prior fields):

| Field | Size |
|-------|------|
| magic | 4 ("RG1K") |
| group_id | 16 |
| state_seq | 4 |
| state_hash | 32 (SHA-256 of accepted state_body) |
| recipient_count | 2 |
| recipients | N × (MemberID 16 + SealBlob 100) |
| signature | 64 |

Verify signature, match state_hash, unseal, check grs_commit. Reject bad magic, recipient_count > 16, duplicate MemberIDs, missing local seal when you are on the roster, invalid X25519 / all-zero shared secret. If next `state_seq` would overflow uint32, start a new group.

Size: 122 + 116N (1978 at N=16).

## Ordinary messages

| Field | Size |
|-------|------|
| magic | 2 (0x4731) |
| format | 1 (1 = counter ChaCha, 2 = XChaCha) |
| flags | 1 (bit0 = member signature) |
| group_trunc | 8 |
| state_seq | 4 |
| epoch | 4 |
| sender_trunc | 8 |
| counter | 4 |
| nonce24 | 0 or 24 (format 2) |
| ciphertext | variable (includes 16-byte tag) |
| signature | 0 or 64 |

Format 1 header 32 bytes, format 2 is 56. Epoch advance itself costs no airtime.

Minimum lengths (reject shorter before splitting ciphertext vs signature):

- format 1 unsigned: 32 + 16
- format 2 unsigned: 56 + 16
- with member signature: add a full 64-byte signature
- ciphertext portion must be at least the 16-byte AEAD tag

**AAD:** magic through counter (format 1), or through nonce24 (format 2). Ciphertext is AEAD output including tag.

**Truncations:** leading 8 bytes of GroupID / MemberID. Zero matches -> buffer or drop. More than one -> must drop. Admins must not assign colliding MemberID prefixes. Create must reject GroupID that collides on 8 bytes with another active group on the device.

**Member signatures:** if bit0 set, Ed25519 over `header_without_signature || ciphertext` (ciphertext includes tag). Verify under the bound Ed25519 half. Fail -> drop. Bit clear means AEAD only: any current member can impersonate content. Attributable chat sets the bit. v1: `flags & ~KNOWN_MSG_FLAGS == 0` or reject (known bit: has signature).

**Send:** activated state, epoch under policy, reserve next counter under crash rules. Exhausted uint32 with nowhere to go -> rekey or new group.

**Receive:** resolve truncations -> fetch unknown/newer state+keydist if needed -> roster for that state_seq (pending senders cannot be attributable) -> tentative replay check -> decrypt -> optional sig -> commit replay -> deliver.

### Interop rejects

| Condition | Action |
|-----------|--------|
| Unknown state/keydist magic | reject |
| State version != 1 | reject |
| Unknown ordinary format | reject |
| Unknown message flag bits | reject |
| Unknown state flag bits | reject |
| Ordinary message below minimum length | reject |
| Ciphertext shorter than AEAD tag | reject |
| extensions_len != 0 (v1) | reject |
| member_count or recipient_count > 16 | reject |
| Duplicate member or keydist rows | reject |
| Missing local keydist row | reject activation |
| state_seq / epoch / counter stuck at uint32 max | stop, rekey or new group |
| All-zero X25519 ss or MemberPub | reject seal |
| Sig present but identity unbound | drop |

## Short glossary

Only the awkward names:

| Term | Meaning |
|------|---------|
| GRS_v | Group root secret for state version v |
| CK_v,t | Epoch key. Direct HKDF from GRS (not a chain) |
| keydist | Signed object with SealBlobs (magic RG1K) |
| SealBlob | Ephemeral X25519 wrap of GRS to one MemberPub |
| pending | Roster row accepted but not identity-bound yet |
| grace | Window after rekey when v-1 keys may still open late mail |
| burned | Abandon the group (admin compromise or conflicting same-seq states) |

---

EXPERIMENTAL - DRAFT
