from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
import os
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Helpers base64
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    KDF pentru root key (DH-ratchet).
    Primeste:
      - rk: root key curent
      - dh_out: rezultatul Diffie-Hellman (bytes)
    Returneaza:
      - rk_nou (32 bytes)
      - ck (chain key) (32 bytes)
    """
    out = hkdf(dh_out, rk, b"RK|CK", 64)
    return out[:32], out[32:]

def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """
    KDF pentru chain key (ratchet pe mesaj).
    Din ck scoatem:
      - mk (message key) pentru AES-GCM
      - nck (next chain key) pentru urmatorul mesaj
    """
    mk = hmac_sha256(ck, b"mk")[:32]
    nck = hmac_sha256(ck, b"ck")[:32]
    return nck, mk

def aead_encrypt(key32: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key32).encrypt(nonce, plaintext, aad)

def aead_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key32).decrypt(nonce, ciphertext, aad)

def pub_bytes(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes_raw()

def load_pub(b: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(b)


# Chei utilizator (Identity + PreKeys)
#  - Identity: chei pe termen lung
#  - PreKeys: chei pentru initiere offline
@dataclass
class Identity:
    # IK_DH pentru DH, IK_SIGN pentru semnarea SPK
    ik_dh_priv: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    ik_sign_priv: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def ik_dh_pub_b64(self) -> str:
        return b64e(pub_bytes(self.ik_dh_priv.public_key()))

    def ik_sign_pub_b64(self) -> str:
        return b64e(self.ik_sign_priv.public_key().public_bytes_raw())

@dataclass
class PreKeys:
    # SPK_DH = prekey semnat, 
    # OPK = lista de one-time prekeys
    spk_dh_priv: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)
    opk_dh_privs: list[X25519PrivateKey] = field(default_factory=list)

    def generate_opks(self, n: int = 10):
        self.opk_dh_privs = [X25519PrivateKey.generate() for _ in range(n)]

    def spk_dh_pub_b64(self) -> str:
        return b64e(pub_bytes(self.spk_dh_priv.public_key()))

    def sign_spk(self, ik_sign_priv: Ed25519PrivateKey) -> str:
        sig = ik_sign_priv.sign(pub_bytes(self.spk_dh_priv.public_key()))
        return b64e(sig)

    def opk_dh_pubs_b64(self) -> list[str]:
        return [b64e(pub_bytes(k.public_key())) for k in self.opk_dh_privs]


# X3DH simplificat
#  - Alice ia bundle-ul lui Bob si calculeaza RK initial
#  - Bob (responder) calculează acelasi RK din mesajul init
def verify_spk_sig(ik_sign_pub_b64: str, spk_dh_pub_b64: str, spk_sig_b64: str) -> None:
    ik_sign_pub = Ed25519PublicKey.from_public_bytes(b64d(ik_sign_pub_b64))
    ik_sign_pub.verify(b64d(spk_sig_b64), b64d(spk_dh_pub_b64)) 

def x3dh_initiator(
    alice_ik_dh_priv: X25519PrivateKey,
    bob_ik_dh_pub_b64: str,
    bob_spk_dh_pub_b64: str,
    bob_opk_dh_pub_b64: Optional[str],
) -> Tuple[bytes, str, Optional[str]]:
    bob_ik = load_pub(b64d(bob_ik_dh_pub_b64))
    bob_spk = load_pub(b64d(bob_spk_dh_pub_b64))

    alice_eph = X25519PrivateKey.generate()
    alice_eph_pub_b64 = b64e(pub_bytes(alice_eph.public_key()))

    dh1 = alice_ik_dh_priv.exchange(bob_spk)
    dh2 = alice_eph.exchange(bob_ik)
    dh3 = alice_eph.exchange(bob_spk)

    ikm = dh1 + dh2 + dh3

    used_opk = None
    if bob_opk_dh_pub_b64:
        bob_opk = load_pub(b64d(bob_opk_dh_pub_b64))
        dh4 = alice_eph.exchange(bob_opk)
        ikm += dh4
        used_opk = bob_opk_dh_pub_b64

    rk = hkdf(ikm, b"\x00" * 32, b"X3DH-simplified", 32)
    return rk, alice_eph_pub_b64, used_opk

def x3dh_responder(
    bob_ik_dh_priv: X25519PrivateKey,
    bob_spk_dh_priv: X25519PrivateKey,
    bob_opk_dh_priv: Optional[X25519PrivateKey],
    alice_ik_dh_pub_b64: str,
    alice_eph_pub_b64: str,
    used_opk_pub_b64: Optional[str],
) -> bytes:
    alice_ik = load_pub(b64d(alice_ik_dh_pub_b64))
    alice_eph = load_pub(b64d(alice_eph_pub_b64))

    dh1 = bob_spk_dh_priv.exchange(alice_ik)
    dh2 = bob_ik_dh_priv.exchange(alice_eph)
    dh3 = bob_spk_dh_priv.exchange(alice_eph)
    ikm = dh1 + dh2 + dh3

    if used_opk_pub_b64:
        if bob_opk_dh_priv is None:
            raise ValueError("Expected OPK but none available locally")
        ikm += bob_opk_dh_priv.exchange(alice_eph)

    rk = hkdf(ikm, b"\x00" * 32, b"X3DH-simplified", 32)
    return rk


# Double Ratchet simplificat
#  - RK se actualizeaza cand DH public se schimba (DH-ratchet)
#  - CK se actualizeaza la fiecare mesaj (chain-ratchet)
@dataclass
class Header:
    dh_pub_b64: str
    pn: int
    n: int
    nonce_b64: str

    def aad(self) -> bytes:
        return b64d(self.dh_pub_b64) + self.pn.to_bytes(4, "big") + self.n.to_bytes(4, "big")

@dataclass
class RatchetState:
    rk: bytes
    dhs_priv: X25519PrivateKey
    dhr_pub: X25519PublicKey
    cks: Optional[bytes]
    ckr: Optional[bytes]
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: Dict[Tuple[str, int], bytes] = field(default_factory=dict)  # (dh_pub_b64, n) -> mk

    @staticmethod
    def init_alice(rk: bytes, bob_initial_dh_pub_b64: str) -> "RatchetState":
        dhs = X25519PrivateKey.generate()
        dhr = load_pub(b64d(bob_initial_dh_pub_b64))
        rk2, cks = kdf_rk(rk, dhs.exchange(dhr))
        return RatchetState(rk=rk2, dhs_priv=dhs, dhr_pub=dhr, cks=cks, ckr=None)

    @staticmethod
    def init_bob(rk: bytes, bob_initial_dh_priv: X25519PrivateKey) -> "RatchetState":
        dummy_peer = X25519PrivateKey.generate().public_key()
        return RatchetState(rk=rk, dhs_priv=bob_initial_dh_priv, dhr_pub=dummy_peer, cks=None, ckr=None)

    def init_receiving_first_time(self, received_dh_pub_b64: str):
        self.dhr_pub = load_pub(b64d(received_dh_pub_b64))
        self.rk, self.ckr = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))
        self.nr = 0

    def init_sending_if_needed(self):
        if self.cks is not None:
            return
        self.dhs_priv = X25519PrivateKey.generate()
        self.rk, self.cks = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))
        self.ns = 0

    def ratchet_step_on_new_dh(self, received_dh_pub_b64: str):
        new_dhr = load_pub(b64d(received_dh_pub_b64))
        self.pn = self.ns
        self.ns = 0
        self.nr = 0

        self.rk, self.ckr = kdf_rk(self.rk, self.dhs_priv.exchange(new_dhr))
        self.dhr_pub = new_dhr

        self.dhs_priv = X25519PrivateKey.generate()
        self.rk, self.cks = kdf_rk(self.rk, self.dhs_priv.exchange(self.dhr_pub))

    def encrypt(self, plaintext: bytes) -> Tuple[Header, str]:
        self.init_sending_if_needed()
        assert self.cks is not None

        self.cks, mk = kdf_ck(self.cks)
        nonce = os.urandom(12)

        hdr = Header(
            dh_pub_b64=b64e(pub_bytes(self.dhs_priv.public_key())),
            pn=self.pn,
            n=self.ns,
            nonce_b64=b64e(nonce),
        )
        ct = aead_encrypt(mk, nonce, plaintext, hdr.aad())
        self.ns += 1
        return hdr, b64e(ct)

    def decrypt(self, hdr: Header, ciphertext_b64: str) -> bytes:
        key_id = (hdr.dh_pub_b64, hdr.n)
        if key_id in self.skipped:
            mk = self.skipped.pop(key_id)
            return aead_decrypt(mk, b64d(hdr.nonce_b64), b64d(ciphertext_b64), hdr.aad())

        if self.ckr is None:
            self.init_receiving_first_time(hdr.dh_pub_b64)

        if hdr.dh_pub_b64 != b64e(pub_bytes(self.dhr_pub)):
            self.ratchet_step_on_new_dh(hdr.dh_pub_b64)

        assert self.ckr is not None

        while self.nr < hdr.n:
            self.ckr, mk_skip = kdf_ck(self.ckr)
            self.skipped[(b64e(pub_bytes(self.dhr_pub)), self.nr)] = mk_skip
            self.nr += 1

        self.ckr, mk = kdf_ck(self.ckr)
        self.nr += 1
        return aead_decrypt(mk, b64d(hdr.nonce_b64), b64d(ciphertext_b64), hdr.aad())


def ratchet_to_json(st: RatchetState) -> dict:
    return {
        "rk": b64e(st.rk),
        "dhs_priv": b64e(st.dhs_priv.private_bytes_raw()),
        "dhr_pub": b64e(pub_bytes(st.dhr_pub)),
        "cks": b64e(st.cks) if st.cks else None,
        "ckr": b64e(st.ckr) if st.ckr else None,
        "ns": st.ns,
        "nr": st.nr,
        "pn": st.pn,
        "skipped": {f"{k[0]}:{k[1]}": b64e(v) for k, v in st.skipped.items()},
    }

def ratchet_from_json(d: dict) -> RatchetState:
    dhs_priv = X25519PrivateKey.from_private_bytes(b64d(d["dhs_priv"]))
    dhr_pub = load_pub(b64d(d["dhr_pub"]))
    st = RatchetState(
        rk=b64d(d["rk"]),
        dhs_priv=dhs_priv,
        dhr_pub=dhr_pub,
        cks=b64d(d["cks"]) if d["cks"] else None,
        ckr=b64d(d["ckr"]) if d["ckr"] else None,
        ns=int(d["ns"]),
        nr=int(d["nr"]),
        pn=int(d["pn"]),
    )
    skipped = {}
    for kk, vv in d.get("skipped", {}).items():
        dh_pub_b64, n_str = kk.rsplit(":", 1)
        skipped[(dh_pub_b64, int(n_str))] = b64d(vv)
    st.skipped = skipped
    return st
