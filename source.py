from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------
# Crypto primitives
# -------------------------

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def kdf_rk(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    Derive new root key and a chain key from (RK, DH).
    """
    out = hkdf(ikm=dh_out, salt=root_key, info=b"RK|CK", length=64)
    new_rk = out[:32]
    ck = out[32:]
    return new_rk, ck

def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    From chain key derive message key and next chain key.
    """
    mk = hmac_sha256(chain_key, b"mk")[:32]
    next_ck = hmac_sha256(chain_key, b"ck")[:32]
    return next_ck, mk

def aead_encrypt(key32: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key32)
    return aesgcm.encrypt(nonce, plaintext, aad)

def aead_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key32)
    return aesgcm.decrypt(nonce, ciphertext, aad)

def pub_bytes(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes_raw()

def load_pub(b: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(b)


# -------------------------
# X3DH (simplified)
# -------------------------

@dataclass
class PreKeyBundle:
    ik_pub: bytes
    spk_pub: bytes
    opk_pub: Optional[bytes] = None

@dataclass
class UserKeys:
    ik_priv: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    spk_priv: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    opk_priv: Optional[X25519PrivateKey] = None

    def make_bundle(self, include_opk: bool = True) -> PreKeyBundle:
        if include_opk and self.opk_priv is None:
            self.opk_priv = X25519PrivateKey.generate()
        return PreKeyBundle(
            ik_pub=pub_bytes(self.ik_priv.public_key()),
            spk_pub=pub_bytes(self.spk_priv.public_key()),
            opk_pub=pub_bytes(self.opk_priv.public_key()) if self.opk_priv else None
        )

def x3dh_initiator(alice: UserKeys, bob_bundle: PreKeyBundle) -> Tuple[bytes, bytes, bytes]:
    """
    Returns: (root_key, alice_ephemeral_pub, used_opk_pub_or_empty)
    """
    bob_ik = load_pub(bob_bundle.ik_pub)
    bob_spk = load_pub(bob_bundle.spk_pub)

    alice_eph = X25519PrivateKey.generate()
    alice_eph_pub = pub_bytes(alice_eph.public_key())

    dh1 = alice.ik_priv.exchange(bob_spk)
    dh2 = alice_eph.exchange(bob_ik)
    dh3 = alice_eph.exchange(bob_spk)

    ikm = dh1 + dh2 + dh3

    used_opk = b""
    if bob_bundle.opk_pub:
        bob_opk = load_pub(bob_bundle.opk_pub)
        dh4 = alice_eph.exchange(bob_opk)
        ikm += dh4
        used_opk = bob_bundle.opk_pub

    rk = hkdf(ikm=ikm, salt=b"\x00" * 32, info=b"X3DH-simplified", length=32)
    return rk, alice_eph_pub, used_opk

def x3dh_responder(bob: UserKeys, alice_ik_pub: bytes, alice_eph_pub: bytes, used_opk_pub: bytes) -> bytes:
    """
    Bob derives same root key.
    """
    alice_ik = load_pub(alice_ik_pub)
    alice_eph = load_pub(alice_eph_pub)

    dh1 = bob.spk_priv.exchange(alice_ik)
    dh2 = bob.ik_priv.exchange(alice_eph)
    dh3 = bob.spk_priv.exchange(alice_eph)

    ikm = dh1 + dh2 + dh3

    if used_opk_pub:
        if bob.opk_priv is None:
            raise ValueError("OPK expected but missing")
        ikm += bob.opk_priv.exchange(alice_eph)

    rk = hkdf(ikm=ikm, salt=b"\x00" * 32, info=b"X3DH-simplified", length=32)
    return rk


# -------------------------
# Double Ratchet (simplified)
# -------------------------

@dataclass
class Header:
    dh_pub: bytes   # sender DH public
    pn: int         # previous sending chain length
    n: int          # message number in current sending chain
    nonce: bytes    # AEAD nonce (12 bytes for AES-GCM)

    def aad(self) -> bytes:
        return (
            self.dh_pub
            + self.pn.to_bytes(4, "big")
            + self.n.to_bytes(4, "big")
        )

@dataclass
class RatchetState:
    rk: bytes
    dhs_priv: X25519PrivateKey       # my current DH private
    dhr_pub: X25519PublicKey         # peer current DH public

    cks: Optional[bytes]             # sending chain key (None if not initialized yet)
    ckr: Optional[bytes]             # receiving chain key (None if not initialized yet)

    ns: int = 0
    nr: int = 0
    pn: int = 0

    skipped: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)  # (dh_pub_bytes, msg_num) -> mk

    @staticmethod
    def init_alice(rk: bytes, bob_initial_dh_pub: bytes) -> "RatchetState":
        """
        Alice creates DHs and immediately derives CKs from DH(DHs, BobDH).
        CKr is not set until she receives Bob's first ratcheted DH message.
        """
        dhs = X25519PrivateKey.generate()
        dhr = load_pub(bob_initial_dh_pub)

        rk2, cks = kdf_rk(rk, dhs.exchange(dhr))
        return RatchetState(
            rk=rk2,
            dhs_priv=dhs,
            dhr_pub=dhr,
            cks=cks,
            ckr=None,
        )

    @staticmethod
    def init_bob(rk: bytes, bob_initial_dh_priv: X25519PrivateKey) -> "RatchetState":
        """
        Bob starts with his initial DH private. He doesn't know Alice's DH yet.
        CKr/CKs not set until first message arrives (for CKr) / until he sends a reply (for CKs).
        """
        # placeholder peer dh; will be replaced on first receive
        dummy_peer = X25519PrivateKey.generate().public_key()
        return RatchetState(
            rk=rk,
            dhs_priv=bob_initial_dh_priv,
            dhr_pub=dummy_peer,
            cks=None,
            ckr=None,
        )

    def init_receiving_chain_first_time(self, received_dh_pub: bytes):
        """
        First time Bob sees Alice DH (first message in session):
        set DHR and derive CKr from DH(DHs, DHR).
        """
        self.dhr_pub = load_pub(received_dh_pub)
        self.rk, self.ckr = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))
        self.nr = 0

    def init_sending_chain_if_needed(self):
        """
        When a side wants to send but CKs isn't initialized yet (common for Bob's first reply),
        create a new DHs and derive CKs from DH(DHs_new, DHR), updating RK.
        """
        if self.cks is not None:
            return
        self.dhs_priv = X25519PrivateKey.generate()
        self.rk, self.cks = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))
        self.ns = 0

    def ratchet_step_on_receive_new_dh(self, received_dh_pub: bytes):
        """
        Standard DH ratchet step triggered when peer DH changes.
        - Update receiving chain from DH(old_DHs, new_DHr)
        - Generate new DHs and update sending chain from DH(new_DHs, new_DHr)
        """
        new_dhr = load_pub(received_dh_pub)

        # move counters
        self.pn = self.ns
        self.ns = 0
        self.nr = 0

        # receiving chain
        self.rk, self.ckr = kdf_rk(self.rk, self.dhs_priv.exchange(new_dhr))
        self.dhr_pub = new_dhr

        # sending chain
        self.dhs_priv = X25519PrivateKey.generate()
        self.rk, self.cks = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))

    def encrypt(self, plaintext: bytes) -> Tuple[Header, bytes]:
        self.init_sending_chain_if_needed()
        assert self.cks is not None

        self.cks, mk = kdf_ck(self.cks)
        header = Header(
            dh_pub=pub_bytes(self.dhs_priv.public_key()),
            pn=self.pn,
            n=self.ns,
            nonce=os.urandom(12),
        )
        ct = aead_encrypt(mk, header.nonce, plaintext, header.aad())
        self.ns += 1
        return header, ct

    def decrypt(self, header: Header, ciphertext: bytes) -> bytes:
        # If we have a skipped key, use it
        key_id = (header.dh_pub, header.n)
        if key_id in self.skipped:
            mk = self.skipped.pop(key_id)
            return aead_decrypt(mk, header.nonce, ciphertext, header.aad())

        # If receiving chain not initialized yet (Bob first receive)
        if self.ckr is None:
            self.init_receiving_chain_first_time(header.dh_pub)

        # If peer DH changed, ratchet
        if header.dh_pub != pub_bytes(self.dhr_pub):
            self.ratchet_step_on_receive_new_dh(header.dh_pub)

        assert self.ckr is not None

        # derive skipped keys up to header.n (basic out-of-order support)
        while self.nr < header.n:
            self.ckr, mk_skip = kdf_ck(self.ckr)
            self.skipped[(pub_bytes(self.dhr_pub), self.nr)] = mk_skip
            self.nr += 1

        # derive MK for this message
        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1
        return aead_decrypt(mk, header.nonce, ciphertext, header.aad())


# -------------------------
# Demo
# -------------------------

def demo():
    alice = UserKeys()
    bob = UserKeys()

    # Bob publishes bundle (IK, SPK, OPK?)
    bob_bundle = bob.make_bundle(include_opk=True)

    # X3DH simplified: derive same RK
    rk_alice, alice_eph_pub, used_opk = x3dh_initiator(alice, bob_bundle)
    rk_bob = x3dh_responder(
        bob,
        pub_bytes(alice.ik_priv.public_key()),
        alice_eph_pub,
        used_opk
    )
    assert rk_alice == rk_bob

    # Initial DH ratchet keys (published by Bob for start of double ratchet)
    bob_initial_dh_priv = X25519PrivateKey.generate()
    bob_initial_dh_pub = pub_bytes(bob_initial_dh_priv.public_key())

    # Initialize ratchet states
    alice_state = RatchetState.init_alice(rk_alice, bob_initial_dh_pub)
    bob_state = RatchetState.init_bob(rk_bob, bob_initial_dh_priv)

    # Alice -> Bob (first message)
    h1, c1 = alice_state.encrypt(b"Salut Bob! (1)")
    p1 = bob_state.decrypt(h1, c1)
    print("Bob got:", p1.decode())

    # Bob -> Alice (first reply)
    h2, c2 = bob_state.encrypt(b"Salut Alice! (1)")
    p2 = alice_state.decrypt(h2, c2)
    print("Alice got:", p2.decode())

    # Alice -> Bob (another message)
    h3, c3 = alice_state.encrypt(b"Cum e proiectul? (2)")
    p3 = bob_state.decrypt(h3, c3)
    print("Bob got:", p3.decode())

    # Bob -> Alice (another reply)
    h4, c4 = bob_state.encrypt(b"Bine, merge ratchet-ul :) (2)")
    p4 = alice_state.decrypt(h4, c4)
    print("Alice got:", p4.decode())


if __name__ == "__main__":
    demo()
