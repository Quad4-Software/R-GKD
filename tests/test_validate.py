from __future__ import annotations

import os
import unittest

from rgkd import constants
from rgkd.crypto import (
    commit_grs,
    decrypt_chacha,
    derive_epoch_key,
    encrypt_chacha,
    message_keys_for,
    seal_grs,
    unseal_grs,
)
from rgkd.identity import (
    MemberBindStatus,
    bind_member_pub,
    destination_hash_from_public,
    generate_peer_keys,
    split_rns_public_key,
)
from rgkd.replay import ReplayWindow
from rgkd.sizes import (
    draft_claims,
    keydist_size,
    message_overhead,
    ordinary_header_size,
    state_object_size,
)
from rgkd.wire import (
    MemberEntry,
    keydist_has_recipient,
    pack_keydist,
    pack_ordinary_header,
    pack_state_body,
    sign_state,
    state_body_hash,
    validate_ordinary_message_length,
    verify_keydist,
    verify_state_object,
    verify_unsealed_grs,
)


class SizeClaimTests(unittest.TestCase):
    def test_fixed_layout_constants(self) -> None:
        claims = draft_claims()
        self.assertEqual(claims["state_fixed_with_sig"], 204)
        self.assertEqual(claims["member_entry"], 68)
        self.assertEqual(claims["seal_blob"], 100)
        self.assertEqual(claims["keydist_fixed"], 122)
        self.assertEqual(claims["keydist_per_recipient"], 116)
        self.assertEqual(claims["msg_header_counter"], 32)
        self.assertEqual(claims["msg_header_xchacha"], 56)
        self.assertEqual(claims["aead_tag"], 16)

    def test_max_members_enforced(self) -> None:
        with self.assertRaises(ValueError):
            state_object_size(constants.MAX_MEMBERS + 1)
        with self.assertRaises(ValueError):
            keydist_size(constants.MAX_MEMBERS + 1)
        admin = generate_peer_keys()
        too_many = [
            MemberEntry(
                member_id=os.urandom(16),
                reticulum_dst_hash=os.urandom(16),
                member_x25519_pub=generate_peer_keys().member_pub,
            )
            for _ in range(constants.MAX_MEMBERS + 1)
        ]
        with self.assertRaises(ValueError):
            sign_state(
                group_id=os.urandom(16),
                state_seq=1,
                prev_state_hash=bytes(32),
                admin=admin,
                grs=os.urandom(32),
                members=too_many,
            )

    def test_draft_approximate_sizes(self) -> None:
        self.assertEqual(state_object_size(16), 204 + 68 * 16)
        self.assertEqual(keydist_size(16), 122 + 16 * 116)
        rekey = state_object_size(16) + keydist_size(16)
        self.assertAlmostEqual(rekey / 1024, 3.19, places=2)

    def test_packed_state_matches_formula(self) -> None:
        admin = generate_peer_keys()
        group_id = os.urandom(16)
        grs = os.urandom(32)
        members = []
        for _ in range(5):
            peer = generate_peer_keys()
            members.append(
                MemberEntry(
                    member_id=os.urandom(16),
                    reticulum_dst_hash=destination_hash_from_public(
                        peer.rns_public_key,
                    ),
                    member_x25519_pub=peer.member_pub,
                ),
            )
        state = sign_state(
            group_id=group_id,
            state_seq=1,
            prev_state_hash=bytes(32),
            admin=admin,
            grs=grs,
            members=members,
        )
        self.assertEqual(len(state), state_object_size(5))
        body = verify_state_object(state, admin.admin_pub)
        verify_unsealed_grs(grs, group_id=group_id, state_seq=1, state_body=body)

    def test_ordinary_header_and_message_overhead(self) -> None:
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        header = pack_ordinary_header(
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=0,
            counter=0,
        )
        self.assertEqual(len(header), ordinary_header_size())
        self.assertEqual(message_overhead(20), 32 + 16 + 20)


class IdentityTests(unittest.TestCase):
    def test_rns_public_key_halves(self) -> None:
        peer = generate_peer_keys()
        enc, sig = split_rns_public_key(peer.rns_public_key)
        self.assertEqual(enc, peer.member_pub)
        self.assertEqual(sig, peer.admin_pub)
        self.assertEqual(len(peer.rns_public_key), 64)

    def test_optional_rns_layout_if_installed(self) -> None:
        try:
            import RNS
        except ImportError:
            self.skipTest("RNS not installed")
        identity = RNS.Identity()
        public = identity.get_public_key()
        self.assertEqual(len(public), 64)
        enc, sig = split_rns_public_key(public)
        self.assertEqual(enc, identity.pub_bytes)
        self.assertEqual(sig, identity.sig_pub_bytes)
        self.assertEqual(len(identity.hash), 16)


class CryptoTests(unittest.TestCase):
    def test_aead_roundtrip_and_tamper(self) -> None:
        key = os.urandom(32)
        nonce = os.urandom(12)
        pt = b"hello reticulum"
        aad = b"aad"
        ct = encrypt_chacha(key, nonce, pt, aad)
        self.assertEqual(len(ct), len(pt) + 16)
        self.assertEqual(decrypt_chacha(key, nonce, ct, aad), pt)
        bad = bytearray(ct)
        bad[-1] ^= 0x01
        with self.assertRaises(Exception):
            decrypt_chacha(key, nonce, bytes(bad), aad)

    def test_seal_roundtrip(self) -> None:
        member = generate_peer_keys()
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        grs = os.urandom(32)
        blob = seal_grs(
            grs=grs,
            group_id=group_id,
            state_seq=3,
            member_id=member_id,
            member_pub=member.member_pub,
        )
        self.assertEqual(len(blob), 100)
        out = unseal_grs(
            seal_blob=blob,
            group_id=group_id,
            state_seq=3,
            member_id=member_id,
            member_private=member.x25519_private,
        )
        self.assertEqual(out, grs)

    def test_foreign_member_cannot_unseal(self) -> None:
        member = generate_peer_keys()
        outsider = generate_peer_keys()
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        blob = seal_grs(
            grs=os.urandom(32),
            group_id=group_id,
            state_seq=1,
            member_id=member_id,
            member_pub=member.member_pub,
        )
        with self.assertRaises(Exception):
            unseal_grs(
                seal_blob=blob,
                group_id=group_id,
                state_seq=1,
                member_id=member_id,
                member_private=outsider.x25519_private,
            )

    def test_zero_member_pub_rejected(self) -> None:
        with self.assertRaises(ValueError):
            seal_grs(
                grs=os.urandom(32),
                group_id=os.urandom(16),
                state_seq=1,
                member_id=os.urandom(16),
                member_pub=bytes(32),
            )


class HierarchyTests(unittest.TestCase):
    def test_epoch_keys_are_direct(self) -> None:
        grs = os.urandom(32)
        group_id = os.urandom(16)
        ck0 = derive_epoch_key(grs, group_id, 1, 0)
        ck_big = derive_epoch_key(grs, group_id, 1, 29_000_000)
        self.assertEqual(len(ck_big), 32)
        self.assertNotEqual(ck0, ck_big)
        again = derive_epoch_key(grs, group_id, 1, 29_000_000)
        self.assertEqual(ck_big, again)

    def test_retained_ck_cannot_derive_other_epochs(self) -> None:
        """Direct KDF: holding CK_v,t alone must not yield CK_v,t+1."""
        grs = os.urandom(32)
        group_id = os.urandom(16)
        ck5 = derive_epoch_key(grs, group_id, 1, 5)
        ck6 = derive_epoch_key(grs, group_id, 1, 6)
        # Old hash-chain design would have been SHA-256(label||ck5||...).
        # Direct design: unrelated without GRS.
        self.assertNotEqual(ck5, ck6)
        forged = derive_epoch_key(ck5, group_id, 1, 6)
        self.assertNotEqual(forged, ck6)

    def test_same_grs_different_state_seq_changes_keys(self) -> None:
        """Weaker join reuse of GRS still domains by public state_seq."""
        grs = os.urandom(32)
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        mk_a, _ = message_keys_for(
            grs=grs,
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=0,
            counter=0,
        )
        mk_b, _ = message_keys_for(
            grs=grs,
            group_id=group_id,
            member_id=member_id,
            state_seq=2,
            epoch=0,
            counter=0,
        )
        self.assertNotEqual(mk_a, mk_b)

    def test_weaker_join_reads_past_under_same_grs(self) -> None:
        """Sealing existing GRS to a joiner has no backward secrecy."""
        grs = os.urandom(32)
        group_id = os.urandom(16)
        sender_id = os.urandom(16)
        mk, nonce = message_keys_for(
            grs=grs,
            group_id=group_id,
            member_id=sender_id,
            state_seq=1,
            epoch=3,
            counter=9,
        )
        ct = encrypt_chacha(mk, nonce, b"past traffic")
        joiner_mk, joiner_nonce = message_keys_for(
            grs=grs,
            group_id=group_id,
            member_id=sender_id,
            state_seq=1,
            epoch=3,
            counter=9,
        )
        self.assertEqual(decrypt_chacha(joiner_mk, joiner_nonce, ct), b"past traffic")

    def test_message_encrypt_decrypt_via_hierarchy(self) -> None:
        grs = os.urandom(32)
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        mk, nonce = message_keys_for(
            grs=grs,
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=2,
            counter=7,
        )
        aad = b"header"
        ct = encrypt_chacha(mk, nonce, b"payload", aad)
        self.assertEqual(decrypt_chacha(mk, nonce, ct, aad), b"payload")


class ReplayTests(unittest.TestCase):
    def test_out_of_order_inside_window(self) -> None:
        w = ReplayWindow(window_size=constants.REPLAY_WINDOW_MIN)
        self.assertTrue(w.check(10))
        w.commit(10)
        self.assertTrue(w.check(8))
        w.commit(8)
        self.assertTrue(w.check(12))
        w.commit(12)
        self.assertFalse(w.check(10))

    def test_too_old_rejected(self) -> None:
        w = ReplayWindow(window_size=constants.REPLAY_WINDOW_MIN)
        w.commit(2000)
        self.assertFalse(w.check(2000 - constants.REPLAY_WINDOW_MIN))

    def test_overflow_safe_too_old(self) -> None:
        w = ReplayWindow(window_size=constants.REPLAY_WINDOW_MIN)
        w.commit(0xFFFFFFFF)
        self.assertFalse(w.check(0xFFFFFFFF - constants.REPLAY_WINDOW_MIN))

    def test_unauthenticated_large_counter_does_not_poison(self) -> None:
        w = ReplayWindow(window_size=constants.REPLAY_WINDOW_MIN)
        w.commit(10)
        self.assertTrue(w.check(10000))
        # Attacker fails AEAD: never commit
        self.assertEqual(w.max_c, 10)
        self.assertTrue(w.check(11))
        w.commit(11)
        self.assertEqual(w.max_c, 11)

    def test_first_commit_initializes_max(self) -> None:
        w = ReplayWindow(window_size=constants.REPLAY_WINDOW_MIN)
        self.assertEqual(w.max_c, -1)
        self.assertTrue(w.check(42))
        w.commit(42)
        self.assertEqual(w.max_c, 42)

    def test_minimum_window_enforced(self) -> None:
        with self.assertRaises(ValueError):
            ReplayWindow(window_size=64)


class BindingTests(unittest.TestCase):
    def test_pending_without_identity(self) -> None:
        peer = generate_peer_keys()
        status = bind_member_pub(
            member_x25519_pub=peer.member_pub,
            reticulum_dst_hash=destination_hash_from_public(peer.rns_public_key),
            resolved_rns_public_key=None,
        )
        self.assertEqual(status, MemberBindStatus.PENDING)

    def test_active_when_bound(self) -> None:
        peer = generate_peer_keys()
        status = bind_member_pub(
            member_x25519_pub=peer.member_pub,
            reticulum_dst_hash=destination_hash_from_public(peer.rns_public_key),
            resolved_rns_public_key=peer.rns_public_key,
        )
        self.assertEqual(status, MemberBindStatus.ACTIVE)

    def test_mismatch_wrong_x25519(self) -> None:
        peer = generate_peer_keys()
        other = generate_peer_keys()
        status = bind_member_pub(
            member_x25519_pub=other.member_pub,
            reticulum_dst_hash=destination_hash_from_public(peer.rns_public_key),
            resolved_rns_public_key=peer.rns_public_key,
        )
        self.assertEqual(status, MemberBindStatus.MISMATCH)


class KeydistValidationTests(unittest.TestCase):
    def test_duplicate_recipient_rejected(self) -> None:
        admin = generate_peer_keys()
        peer = generate_peer_keys()
        group_id = os.urandom(16)
        mid = os.urandom(16)
        blob = seal_grs(
            grs=os.urandom(32),
            group_id=group_id,
            state_seq=1,
            member_id=mid,
            member_pub=peer.member_pub,
        )
        with self.assertRaises(ValueError):
            pack_keydist(
                group_id=group_id,
                state_seq=1,
                state_hash=os.urandom(32),
                recipients=[(mid, blob), (mid, blob)],
                admin=admin,
            )

    def test_missing_local_recipient_detected(self) -> None:
        admin = generate_peer_keys()
        peer = generate_peer_keys()
        group_id = os.urandom(16)
        mid = os.urandom(16)
        other = os.urandom(16)
        blob = seal_grs(
            grs=os.urandom(32),
            group_id=group_id,
            state_seq=1,
            member_id=mid,
            member_pub=peer.member_pub,
        )
        packed = pack_keydist(
            group_id=group_id,
            state_seq=1,
            state_hash=os.urandom(32),
            recipients=[(mid, blob)],
            admin=admin,
        )
        body = verify_keydist(packed, admin.admin_pub)
        self.assertTrue(keydist_has_recipient(body, mid))
        self.assertFalse(keydist_has_recipient(body, other))


class FlagAndLengthTests(unittest.TestCase):
    def test_unknown_state_flags_rejected(self) -> None:
        admin = generate_peer_keys()
        with self.assertRaises(ValueError):
            sign_state(
                group_id=os.urandom(16),
                state_seq=1,
                prev_state_hash=bytes(32),
                admin=admin,
                grs=os.urandom(32),
                members=[],
                flags=0x0002,
            )

    def test_unknown_message_flags_rejected(self) -> None:
        header = bytearray(
            pack_ordinary_header(
                group_id=os.urandom(16),
                member_id=os.urandom(16),
                state_seq=1,
                epoch=0,
                counter=0,
            )
        )
        header[3] = 0x02
        with self.assertRaises(ValueError):
            validate_ordinary_message_length(bytes(header) + bytes(16))

    def test_min_ordinary_message_lengths(self) -> None:
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        h1 = pack_ordinary_header(
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=0,
            counter=0,
        )
        with self.assertRaises(ValueError):
            validate_ordinary_message_length(h1 + bytes(15))
        validate_ordinary_message_length(h1 + bytes(16))
        h2 = pack_ordinary_header(
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=0,
            counter=0,
            fmt=constants.MSG_FORMAT_XCHACHA,
            nonce24=os.urandom(24),
        )
        with self.assertRaises(ValueError):
            validate_ordinary_message_length(h2 + bytes(15))
        validate_ordinary_message_length(h2 + bytes(16))
        hs = pack_ordinary_header(
            group_id=group_id,
            member_id=member_id,
            state_seq=1,
            epoch=0,
            counter=0,
            has_signature=True,
        )
        with self.assertRaises(ValueError):
            validate_ordinary_message_length(hs + bytes(16) + bytes(63))
        validate_ordinary_message_length(hs + bytes(16) + bytes(64))


class AuthTests(unittest.TestCase):
    def test_forged_grs_fails_commit(self) -> None:
        admin = generate_peer_keys()
        member = generate_peer_keys()
        group_id = os.urandom(16)
        member_id = os.urandom(16)
        real_grs = os.urandom(32)
        state = sign_state(
            group_id=group_id,
            state_seq=1,
            prev_state_hash=bytes(32),
            admin=admin,
            grs=real_grs,
            members=[
                MemberEntry(
                    member_id=member_id,
                    reticulum_dst_hash=destination_hash_from_public(
                        member.rns_public_key,
                    ),
                    member_x25519_pub=member.member_pub,
                ),
            ],
        )
        body = verify_state_object(state, admin.admin_pub)
        fake = seal_grs(
            grs=os.urandom(32),
            group_id=group_id,
            state_seq=1,
            member_id=member_id,
            member_pub=member.member_pub,
        )
        opened = unseal_grs(
            seal_blob=fake,
            group_id=group_id,
            state_seq=1,
            member_id=member_id,
            member_private=member.x25519_private,
        )
        with self.assertRaises(ValueError):
            verify_unsealed_grs(
                opened,
                group_id=group_id,
                state_seq=1,
                state_body=body,
            )

    def test_unsigned_keydist_rejected(self) -> None:
        admin = generate_peer_keys()
        other = generate_peer_keys()
        group_id = os.urandom(16)
        mid = os.urandom(16)
        peer = generate_peer_keys()
        blob = seal_grs(
            grs=os.urandom(32),
            group_id=group_id,
            state_seq=1,
            member_id=mid,
            member_pub=peer.member_pub,
        )
        good = pack_keydist(
            group_id=group_id,
            state_seq=1,
            state_hash=os.urandom(32),
            recipients=[(mid, blob)],
            admin=admin,
        )
        verify_keydist(good, admin.admin_pub)
        with self.assertRaises(Exception):
            verify_keydist(good, other.admin_pub)
        with self.assertRaises(Exception):
            verify_keydist(good[:-64] + os.urandom(64), admin.admin_pub)


class MembershipFlowTests(unittest.TestCase):
    def test_kick_excludes_removed_member(self) -> None:
        admin = generate_peer_keys()
        keep = generate_peer_keys()
        kick = generate_peer_keys()
        group_id = os.urandom(16)
        keep_id = os.urandom(16)
        kick_id = os.urandom(16)
        grs1 = os.urandom(32)

        members_v1 = [
            MemberEntry(
                member_id=keep_id,
                reticulum_dst_hash=destination_hash_from_public(keep.rns_public_key),
                member_x25519_pub=keep.member_pub,
            ),
            MemberEntry(
                member_id=kick_id,
                reticulum_dst_hash=destination_hash_from_public(kick.rns_public_key),
                member_x25519_pub=kick.member_pub,
            ),
        ]
        state1 = sign_state(
            group_id=group_id,
            state_seq=1,
            prev_state_hash=bytes(32),
            admin=admin,
            grs=grs1,
            members=members_v1,
        )
        body1 = verify_state_object(state1, admin.admin_pub)
        seal_kick_v1 = seal_grs(
            grs=grs1,
            group_id=group_id,
            state_seq=1,
            member_id=kick_id,
            member_pub=kick.member_pub,
        )
        opened = unseal_grs(
            seal_blob=seal_kick_v1,
            group_id=group_id,
            state_seq=1,
            member_id=kick_id,
            member_private=kick.x25519_private,
        )
        verify_unsealed_grs(
            opened,
            group_id=group_id,
            state_seq=1,
            state_body=body1,
        )

        members_v2 = [
            MemberEntry(
                member_id=keep_id,
                reticulum_dst_hash=destination_hash_from_public(keep.rns_public_key),
                member_x25519_pub=keep.member_pub,
            ),
        ]
        grs2 = os.urandom(32)
        state2 = sign_state(
            group_id=group_id,
            state_seq=2,
            prev_state_hash=state_body_hash(body1),
            admin=admin,
            grs=grs2,
            members=members_v2,
            flags=constants.FLAG_REKEY,
        )
        body2 = verify_state_object(state2, admin.admin_pub)
        seal_keep_v2 = seal_grs(
            grs=grs2,
            group_id=group_id,
            state_seq=2,
            member_id=keep_id,
            member_pub=keep.member_pub,
        )
        keydist = pack_keydist(
            group_id=group_id,
            state_seq=2,
            state_hash=state_body_hash(body2),
            recipients=[(keep_id, seal_keep_v2)],
            admin=admin,
        )
        verify_keydist(keydist, admin.admin_pub)
        self.assertEqual(len(keydist), keydist_size(1))
        self.assertEqual(len(state2), state_object_size(1))

        opened2 = unseal_grs(
            seal_blob=seal_keep_v2,
            group_id=group_id,
            state_seq=2,
            member_id=keep_id,
            member_private=keep.x25519_private,
        )
        verify_unsealed_grs(
            opened2,
            group_id=group_id,
            state_seq=2,
            state_body=body2,
        )
        with self.assertRaises(Exception):
            unseal_grs(
                seal_blob=seal_kick_v1,
                group_id=group_id,
                state_seq=2,
                member_id=kick_id,
                member_private=kick.x25519_private,
            )

    def test_keydist_packed_size(self) -> None:
        admin = generate_peer_keys()
        group_id = os.urandom(16)
        recipients = []
        for _ in range(4):
            peer = generate_peer_keys()
            mid = os.urandom(16)
            blob = seal_grs(
                grs=os.urandom(32),
                group_id=group_id,
                state_seq=1,
                member_id=mid,
                member_pub=peer.member_pub,
            )
            recipients.append((mid, blob))
        packed = pack_keydist(
            group_id=group_id,
            state_seq=1,
            state_hash=os.urandom(32),
            recipients=recipients,
            admin=admin,
        )
        self.assertEqual(len(packed), keydist_size(4))


class BodyLayoutTests(unittest.TestCase):
    def test_state_fixed_body_length(self) -> None:
        admin = generate_peer_keys()
        group_id = os.urandom(16)
        grs = os.urandom(32)
        body = pack_state_body(
            group_id=group_id,
            state_seq=1,
            prev_state_hash=bytes(32),
            admin_pub=admin.admin_pub,
            grs_commit=commit_grs(grs, group_id, 1),
            members=[],
        )
        self.assertEqual(len(body), constants.STATE_FIXED_BODY)


if __name__ == "__main__":
    unittest.main()
