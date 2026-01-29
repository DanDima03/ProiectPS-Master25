import os, json, argparse
import requests

from crypto import (
    Identity, PreKeys, verify_spk_sig,
    x3dh_initiator, x3dh_responder,
    RatchetState, Header,
    ratchet_to_json, ratchet_from_json,
    b64e, b64d, load_pub
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

API = os.environ.get("SIGNALMINI_API", "http://localhost:8000")
STATE_DIR = os.environ.get("SIGNALMINI_STATE", ".client_state")

def ensure_dir():
    os.makedirs(STATE_DIR, exist_ok=True)

def path(name: str) -> str:
    ensure_dir()
    return os.path.join(STATE_DIR, name)

def save_json(fname: str, data: dict):
    with open(path(fname), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_json(fname: str) -> dict:
    with open(path(fname), "r", encoding="utf-8") as f:
        return json.load(f)

def has_file(fname: str) -> bool:
    return os.path.exists(path(fname))

def auth_headers() -> dict:
    tok = load_json("token.json")["access_token"]
    return {"Authorization": f"Bearer {tok}"}

def http_post(url: str, json_body: dict, auth: bool = False):
    h = auth_headers() if auth else {}
    r = requests.post(url, json=json_body, headers=h, timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_put(url: str, json_body: dict, auth: bool = False):
    h = auth_headers() if auth else {}
    r = requests.put(url, json=json_body, headers=h, timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_get(url: str, auth: bool = False):
    h = auth_headers() if auth else {}
    r = requests.get(url, headers=h, timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"HTTP {r.status_code}: {r.text}")
    return r.json()

# ---------- Local keys ----------
def load_or_create_identity() -> dict:
    if not has_file("identity.json"):
        ident = Identity()
        data = {
            "ik_dh_priv": b64e(ident.ik_dh_priv.private_bytes_raw()),
            "ik_sign_priv": b64e(ident.ik_sign_priv.private_bytes_raw()),
            "ik_dh_pub": ident.ik_dh_pub_b64(),
            "ik_sign_pub": ident.ik_sign_pub_b64(),
        }
        save_json("identity.json", data)
    return load_json("identity.json")

def load_or_create_prekeys(n_opk: int = 10) -> dict:
    if not has_file("prekeys.json"):
        idd = load_or_create_identity()
        ik_sign_priv = __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]).Ed25519PrivateKey
        # quick import above is annoying; keep simple:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        spk = PreKeys()
        spk.generate_opks(n_opk)

        ik_sign = Ed25519PrivateKey.from_private_bytes(b64d(idd["ik_sign_priv"]))
        spk_sig = spk.sign_spk(ik_sign)

        data = {
            "spk_dh_priv": b64e(spk.spk_dh_priv.private_bytes_raw()),
            "spk_dh_pub": spk.spk_dh_pub_b64(),
            "spk_sig": spk_sig,
            "opk_dh_privs": [b64e(k.private_bytes_raw()) for k in spk.opk_dh_privs],
            "opk_dh_pubs": spk.opk_dh_pubs_b64(),
        }
        save_json("prekeys.json", data)
    return load_json("prekeys.json")

def opk_take_by_pub(opk_pub_b64: str) -> X25519PrivateKey | None:
    pk = load_or_create_prekeys()
    for priv_b64, pub_b64 in zip(pk["opk_dh_privs"], pk["opk_dh_pubs"]):
        if pub_b64 == opk_pub_b64:
            return X25519PrivateKey.from_private_bytes(b64d(priv_b64))
    return None

# ---------- Session store ----------
def sess_file(peer: str) -> str:
    return f"session_{peer}.json"

def load_session(peer: str):
    if not has_file(sess_file(peer)):
        return None
    return ratchet_from_json(load_json(sess_file(peer)))

def save_session(peer: str, st: RatchetState):
    save_json(sess_file(peer), ratchet_to_json(st))

# ---------- Commands ----------
def cmd_register(args):
    http_post(f"{API}/users/register", {"username": args.username, "password": args.password})
    print("OK register")

def cmd_login(args):
    tok = http_post(f"{API}/users/login", {"username": args.username, "password": args.password})
    save_json("token.json", tok)
    save_json("me.json", {"username": args.username})
    print("OK login")

def cmd_publish_keys(args):
    idd = load_or_create_identity()
    pk = load_or_create_prekeys(args.opk)

    body = {
        "ik_dh_pub": idd["ik_dh_pub"],
        "ik_sign_pub": idd["ik_sign_pub"],
        "spk_dh_pub": pk["spk_dh_pub"],
        "spk_sig": pk["spk_sig"],
        "opk_dh_pubs": pk["opk_dh_pubs"],
    }
    http_put(f"{API}/keys/bundle", body, auth=True)
    print("OK published keys")

def cmd_send(args):
    me = load_json("me.json")["username"]
    idd = load_or_create_identity()
    pk = load_or_create_prekeys()

    # existing session?
    st = load_session(args.to)
    if st is None:
        # fetch bundle, verify SPK signature
        bundle = http_get(f"{API}/keys/bundle/{args.to}")
        verify_spk_sig(bundle["ik_sign_pub"], bundle["spk_dh_pub"], bundle["spk_sig"])

        # X3DH initiator -> RK
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        alice_ik_dh_priv = X25519PrivateKey.from_private_bytes(b64d(idd["ik_dh_priv"]))
        rk, alice_eph_pub_b64, used_opk = x3dh_initiator(
            alice_ik_dh_priv,
            bundle["ik_dh_pub"],
            bundle["spk_dh_pub"],
            bundle.get("opk_dh_pub"),
        )

        # Double ratchet init uses Bob SPK as initial DH public
        st = RatchetState.init_alice(rk, bundle["spk_dh_pub"])

        # Encrypt first message
        hdr, ct_b64 = st.encrypt(args.text.encode("utf-8"))

        payload = {
            "x3dh": {
                "alice_ik_dh_pub": idd["ik_dh_pub"],
                "alice_eph_pub": alice_eph_pub_b64,
                "used_opk_pub": used_opk,
            },
            "ratchet": {
                "header": {
                    "dh_pub": hdr.dh_pub_b64,
                    "pn": hdr.pn,
                    "n": hdr.n,
                    "nonce": hdr.nonce_b64,
                },
                "ciphertext": ct_b64,
            },
        }

        http_post(f"{API}/messages", {"to_username": args.to, "msg_type": "init", "payload": payload}, auth=True)
        save_session(args.to, st)
        print("OK sent init+msg")
        return

    # normal message
    hdr, ct_b64 = st.encrypt(args.text.encode("utf-8"))
    payload = {
        "header": {"dh_pub": hdr.dh_pub_b64, "pn": hdr.pn, "n": hdr.n, "nonce": hdr.nonce_b64},
        "ciphertext": ct_b64,
    }
    http_post(f"{API}/messages", {"to_username": args.to, "msg_type": "msg", "payload": payload}, auth=True)
    save_session(args.to, st)
    print("OK sent msg")

def cmd_inbox(args):
    idd = load_or_create_identity()
    pk = load_or_create_prekeys()

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    alice_ik_dh_priv = X25519PrivateKey.from_private_bytes(b64d(idd["ik_dh_priv"]))

    spk_dh_priv = X25519PrivateKey.from_private_bytes(b64d(pk["spk_dh_priv"]))

    msgs = http_get(f"{API}/messages/inbox", auth=True)
    if not msgs:
        print("(empty)")
        return

    for m in msgs:
        frm = m["from_username"]
        if m["msg_type"] == "init":
            x3 = m["payload"]["x3dh"]
            rat = m["payload"]["ratchet"]

            used_opk = x3.get("used_opk_pub")
            bob_opk_priv = opk_take_by_pub(used_opk) if used_opk else None

            # We are responder (Bob) in this session
            rk = x3dh_responder(
                bob_ik_dh_priv=alice_ik_dh_priv,   # local user's IK DH priv
                bob_spk_dh_priv=spk_dh_priv,
                bob_opk_dh_priv=bob_opk_priv,
                alice_ik_dh_pub_b64=x3["alice_ik_dh_pub"],
                alice_eph_pub_b64=x3["alice_eph_pub"],
                used_opk_pub_b64=used_opk,
            )

            st = RatchetState.init_bob(rk, spk_dh_priv)

            h = rat["header"]
            hdr = Header(dh_pub_b64=h["dh_pub"], pn=h["pn"], n=h["n"], nonce_b64=h["nonce"])
            pt = st.decrypt(hdr, rat["ciphertext"]).decode("utf-8", errors="replace")

            save_session(frm, st)
            print(f"[{frm}] INIT: {pt}")
        else:
            st = load_session(frm)
            if st is None:
                print(f"[{frm}] MSG: (no session; missing init)")
                continue

            h = m["payload"]["header"]
            hdr = Header(dh_pub_b64=h["dh_pub"], pn=h["pn"], n=h["n"], nonce_b64=h["nonce"])
            pt = st.decrypt(hdr, m["payload"]["ciphertext"]).decode("utf-8", errors="replace")
            save_session(frm, st)
            print(f"[{frm}] {pt}")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("register")
    p.add_argument("username")
    p.add_argument("password")
    p.set_defaults(fn=cmd_register)

    p = sub.add_parser("login")
    p.add_argument("username")
    p.add_argument("password")
    p.set_defaults(fn=cmd_login)

    p = sub.add_parser("publish-keys")
    p.add_argument("--opk", type=int, default=10)
    p.set_defaults(fn=cmd_publish_keys)

    p = sub.add_parser("send")
    p.add_argument("to")
    p.add_argument("text")
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("inbox")
    p.set_defaults(fn=cmd_inbox)

    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
