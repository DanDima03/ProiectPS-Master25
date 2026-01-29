import os
import json
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

import requests

from crypto import (
    Identity, PreKeys, verify_spk_sig,
    x3dh_initiator, x3dh_responder,
    RatchetState, Header,
    ratchet_to_json, ratchet_from_json,
    b64e, b64d
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


# -----------------------
# Local state helpers
# -----------------------

DEFAULT_API = os.environ.get("SIGNALMINI_API", "http://localhost:8000")
DEFAULT_STATE_DIR = os.environ.get("SIGNALMINI_STATE", ".client_state")

def ensure_dir(state_dir: str):
    os.makedirs(state_dir, exist_ok=True)

def spath(state_dir: str, name: str) -> str:
    ensure_dir(state_dir)
    return os.path.join(state_dir, name)

def save_json(state_dir: str, fname: str, data: dict):
    with open(spath(state_dir, fname), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_json(state_dir: str, fname: str) -> dict:
    with open(spath(state_dir, fname), "r", encoding="utf-8") as f:
        return json.load(f)

def exists(state_dir: str, fname: str) -> bool:
    return os.path.exists(spath(state_dir, fname))

def sess_file(peer: str) -> str:
    return f"session_{peer}.json"

def load_session(state_dir: str, peer: str):
    if not exists(state_dir, sess_file(peer)):
        return None
    return ratchet_from_json(load_json(state_dir, sess_file(peer)))

def save_session(state_dir: str, peer: str, st: RatchetState):
    save_json(state_dir, sess_file(peer), ratchet_to_json(st))

def load_or_create_identity(state_dir: str) -> dict:
    if not exists(state_dir, "identity.json"):
        ident = Identity()
        data = {
            "ik_dh_priv": b64e(ident.ik_dh_priv.private_bytes_raw()),
            "ik_sign_priv": b64e(ident.ik_sign_priv.private_bytes_raw()),
            "ik_dh_pub": ident.ik_dh_pub_b64(),
            "ik_sign_pub": ident.ik_sign_pub_b64(),
        }
        save_json(state_dir, "identity.json", data)
    return load_json(state_dir, "identity.json")

def load_or_create_prekeys(state_dir: str, n_opk: int = 10) -> dict:
    if not exists(state_dir, "prekeys.json"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        idd = load_or_create_identity(state_dir)
        ik_sign = Ed25519PrivateKey.from_private_bytes(b64d(idd["ik_sign_priv"]))

        pre = PreKeys()
        pre.generate_opks(n_opk)
        spk_sig = pre.sign_spk(ik_sign)

        data = {
            "spk_dh_priv": b64e(pre.spk_dh_priv.private_bytes_raw()),
            "spk_dh_pub": pre.spk_dh_pub_b64(),
            "spk_sig": spk_sig,
            "opk_dh_privs": [b64e(k.private_bytes_raw()) for k in pre.opk_dh_privs],
            "opk_dh_pubs": pre.opk_dh_pubs_b64(),
        }
        save_json(state_dir, "prekeys.json", data)
    return load_json(state_dir, "prekeys.json")

def opk_take_by_pub(state_dir: str, opk_pub_b64: str):
    pk = load_or_create_prekeys(state_dir)
    for priv_b64, pub_b64 in zip(pk["opk_dh_privs"], pk["opk_dh_pubs"]):
        if pub_b64 == opk_pub_b64:
            return X25519PrivateKey.from_private_bytes(b64d(priv_b64))
    return None


# -----------------------
# HTTP helpers
# -----------------------

def headers_with_token(token: str | None) -> dict:
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}

def http_post(api: str, path: str, body: dict, token: str | None = None) -> dict:
    r = requests.post(f"{api}{path}", json=body, headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_put(api: str, path: str, body: dict, token: str | None = None) -> dict:
    r = requests.put(f"{api}{path}", json=body, headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_get(api: str, path: str, token: str | None = None) -> dict | list:
    r = requests.get(f"{api}{path}", headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()


# -----------------------
# GUI
# -----------------------

class SignalMiniGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SignalMini Client (GUI)")
        self.geometry("900x650")

        self.api_var = tk.StringVar(value=DEFAULT_API)
        self.state_var = tk.StringVar(value=DEFAULT_STATE_DIR)

        self.username_var = tk.StringVar(value="")
        self.token: str | None = None

        self.peer_var = tk.StringVar(value="bob")
        self.message_var = tk.StringVar(value="Salut!")

        self.opk_count_var = tk.IntVar(value=10)

        self.ui_queue: queue.Queue = queue.Queue()

        self._build_ui()
        self.after(100, self._drain_queue)

        self._try_load_session_user()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill=tk.X)

        ttk.Label(top, text="API URL:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.api_var, width=35).pack(side=tk.LEFT, padx=6)

        ttk.Label(top, text="STATE DIR:").pack(side=tk.LEFT, padx=(10,0))
        ttk.Entry(top, textvariable=self.state_var, width=25).pack(side=tk.LEFT, padx=6)

        ttk.Button(top, text="Load Local State", command=self._try_load_session_user).pack(side=tk.LEFT, padx=6)

        self.status = ttk.Label(self, text="Status: not logged in", padding=10)
        self.status.pack(fill=tk.X)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tabs
        self.tab_auth = ttk.Frame(nb, padding=10)
        self.tab_keys = ttk.Frame(nb, padding=10)
        self.tab_chat = ttk.Frame(nb, padding=10)

        nb.add(self.tab_auth, text="Auth")
        nb.add(self.tab_keys, text="Keys")
        nb.add(self.tab_chat, text="Chat")

        self._build_auth_tab()
        self._build_keys_tab()
        self._build_chat_tab()

    def _build_auth_tab(self):
        f = self.tab_auth

        row1 = ttk.Frame(f)
        row1.pack(fill=tk.X, pady=5)

        ttk.Label(row1, text="Username:").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.username_var, width=25).pack(side=tk.LEFT, padx=6)

        ttk.Label(row1, text="Password:").pack(side=tk.LEFT, padx=(10,0))
        self.pw_entry = ttk.Entry(row1, show="*", width=25)
        self.pw_entry.pack(side=tk.LEFT, padx=6)

        row2 = ttk.Frame(f)
        row2.pack(fill=tk.X, pady=5)

        ttk.Button(row2, text="Register", command=self._register_user).pack(side=tk.LEFT)
        ttk.Button(row2, text="Login", command=self._login).pack(side=tk.LEFT, padx=6)
        ttk.Button(row2, text="Logout (local)", command=self._logout_local).pack(side=tk.LEFT, padx=6)

        self.auth_log = ScrolledText(f, height=18)
        self.auth_log.pack(fill=tk.BOTH, expand=True, pady=(10,0))
        self._log(self.auth_log, "Auth tab ready.\n")

    def _build_keys_tab(self):
        f = self.tab_keys

        row = ttk.Frame(f)
        row.pack(fill=tk.X, pady=5)

        ttk.Label(row, text="OPK count to generate:").pack(side=tk.LEFT)
        ttk.Spinbox(row, from_=0, to=100, textvariable=self.opk_count_var, width=6).pack(side=tk.LEFT, padx=6)

        ttk.Button(row, text="Generate/Ensure Local Keys", command=self._ensure_local_keys).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Publish Keys to Server", command=self._publish_keys).pack(side=tk.LEFT, padx=6)

        self.keys_log = ScrolledText(f, height=22)
        self.keys_log.pack(fill=tk.BOTH, expand=True, pady=(10,0))
        self._log(self.keys_log, "Keys tab ready.\n")

    def _build_chat_tab(self):
        f = self.tab_chat

        row1 = ttk.Frame(f)
        row1.pack(fill=tk.X, pady=5)

        ttk.Label(row1, text="Peer username:").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.peer_var, width=25).pack(side=tk.LEFT, padx=6)

        ttk.Button(row1, text="Send", command=self._send_message).pack(side=tk.LEFT, padx=6)
        ttk.Button(row1, text="Refresh Inbox", command=self._refresh_inbox).pack(side=tk.LEFT, padx=6)

        row2 = ttk.Frame(f)
        row2.pack(fill=tk.X, pady=5)
        ttk.Label(row2, text="Message:").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.message_var, width=70).pack(side=tk.LEFT, padx=6)

        self.chat_log = ScrolledText(f, height=25)
        self.chat_log.pack(fill=tk.BOTH, expand=True, pady=(10,0))
        self._log(self.chat_log, "Chat tab ready.\n")

    # -----------------------
    # Logging + threading
    # -----------------------

    def _log(self, widget: ScrolledText, msg: str):
        widget.insert(tk.END, msg)
        widget.see(tk.END)

    def _run_bg(self, target, on_ok=None, on_err=None):
        def runner():
            try:
                res = target()
                if on_ok:
                    self.ui_queue.put(("ok", on_ok, res))
            except Exception as e:
                if on_err:
                    self.ui_queue.put(("err", on_err, e))
                else:
                    self.ui_queue.put(("err", None, e))
        threading.Thread(target=runner, daemon=True).start()

    def _drain_queue(self):
        try:
            while True:
                kind, fn, payload = self.ui_queue.get_nowait()
                if kind == "ok" and fn:
                    fn(payload)
                elif kind == "err":
                    if fn:
                        fn(payload)
                    else:
                        messagebox.showerror("Error", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    # -----------------------
    # State / auth
    # -----------------------

    def _try_load_session_user(self):
        sd = self.state_var.get().strip()
        if not sd:
            return
        try:
            if exists(sd, "token.json"):
                self.token = load_json(sd, "token.json").get("access_token")
            if exists(sd, "me.json"):
                self.username_var.set(load_json(sd, "me.json").get("username", ""))
            if self.token and self.username_var.get().strip():
                self.status.configure(text=f"Status: logged in as {self.username_var.get().strip()}")
            else:
                self.status.configure(text="Status: not logged in")
        except Exception as e:
            messagebox.showerror("Load state failed", str(e))

    def _logout_local(self):
        self.token = None
        self.status.configure(text="Status: not logged in (local)")
        self._log(self.auth_log, "Logged out locally (token cleared in memory).\n")

    def _register_user(self):
        api = self.api_var.get().strip()
        sd = self.state_var.get().strip()
        username = self.username_var.get().strip()
        password = self.pw_entry.get()

        if not username or not password:
            messagebox.showwarning("Missing", "Username/password required")
            return

        def work():
            return http_post(api, "/users/register", {"username": username, "password": password}, token=None)

        def ok(_):
            self._log(self.auth_log, f"Registered: {username}\n")

        def err(e):
            messagebox.showerror("Register failed", str(e))

        self._run_bg(work, ok, err)

    def _login(self):
        api = self.api_var.get().strip()
        sd = self.state_var.get().strip()
        username = self.username_var.get().strip()
        password = self.pw_entry.get()

        if not username or not password:
            messagebox.showwarning("Missing", "Username/password required")
            return

        def work():
            return http_post(api, "/users/login", {"username": username, "password": password}, token=None)

        def ok(tok):
            self.token = tok["access_token"]
            save_json(sd, "token.json", tok)
            save_json(sd, "me.json", {"username": username})
            self.status.configure(text=f"Status: logged in as {username}")
            self._log(self.auth_log, f"Login OK. Token saved to {sd}.\n")

        def err(e):
            messagebox.showerror("Login failed", str(e))

        self._run_bg(work, ok, err)

    # -----------------------
    # Keys
    # -----------------------

    def _ensure_local_keys(self):
        sd = self.state_var.get().strip()
        n = int(self.opk_count_var.get())
        try:
            load_or_create_identity(sd)
            load_or_create_prekeys(sd, n_opk=n)
            self._log(self.keys_log, f"Local keys ensured (OPK={n}). Stored in {sd}\n")
        except Exception as e:
            messagebox.showerror("Local keys error", str(e))

    def _publish_keys(self):
        api = self.api_var.get().strip()
        sd = self.state_var.get().strip()
        if not self.token:
            messagebox.showwarning("Auth", "Login first")
            return

        def work():
            idd = load_or_create_identity(sd)
            pk = load_or_create_prekeys(sd, n_opk=int(self.opk_count_var.get()))

            body = {
                "ik_dh_pub": idd["ik_dh_pub"],
                "ik_sign_pub": idd["ik_sign_pub"],
                "spk_dh_pub": pk["spk_dh_pub"],
                "spk_sig": pk["spk_sig"],
                "opk_dh_pubs": pk["opk_dh_pubs"],
            }
            return http_put(api, "/keys/bundle", body, token=self.token)

        def ok(resp):
            self._log(self.keys_log, f"Published keys OK: {resp}\n")

        def err(e):
            messagebox.showerror("Publish keys failed", str(e))

        self._run_bg(work, ok, err)

    # -----------------------
    # Chat: send + inbox
    # -----------------------

    def _send_message(self):
        api = self.api_var.get().strip()
        sd = self.state_var.get().strip()
        if not self.token:
            messagebox.showwarning("Auth", "Login first")
            return

        to = self.peer_var.get().strip()
        text = self.message_var.get()
        if not to or not text:
            messagebox.showwarning("Missing", "Peer + message required")
            return

        def work():
            idd = load_or_create_identity(sd)
            pk = load_or_create_prekeys(sd)

            st = load_session(sd, to)
            if st is None:
                # fetch bundle + verify signature
                bundle = http_get(api, f"/keys/bundle/{to}")
                verify_spk_sig(bundle["ik_sign_pub"], bundle["spk_dh_pub"], bundle["spk_sig"])

                alice_ik_dh_priv = X25519PrivateKey.from_private_bytes(b64d(idd["ik_dh_priv"]))
                rk, alice_eph_pub_b64, used_opk = x3dh_initiator(
                    alice_ik_dh_priv,
                    bundle["ik_dh_pub"],
                    bundle["spk_dh_pub"],
                    bundle.get("opk_dh_pub"),
                )

                st = RatchetState.init_alice(rk, bundle["spk_dh_pub"])
                hdr, ct_b64 = st.encrypt(text.encode("utf-8"))

                payload = {
                    "x3dh": {
                        "alice_ik_dh_pub": idd["ik_dh_pub"],
                        "alice_eph_pub": alice_eph_pub_b64,
                        "used_opk_pub": used_opk,
                    },
                    "ratchet": {
                        "header": {"dh_pub": hdr.dh_pub_b64, "pn": hdr.pn, "n": hdr.n, "nonce": hdr.nonce_b64},
                        "ciphertext": ct_b64,
                    },
                }
                resp = http_post(api, "/messages", {"to_username": to, "msg_type": "init", "payload": payload}, token=self.token)
                save_session(sd, to, st)
                return ("init", resp)

            # normal msg
            hdr, ct_b64 = st.encrypt(text.encode("utf-8"))
            payload = {
                "header": {"dh_pub": hdr.dh_pub_b64, "pn": hdr.pn, "n": hdr.n, "nonce": hdr.nonce_b64},
                "ciphertext": ct_b64,
            }
            resp = http_post(api, "/messages", {"to_username": to, "msg_type": "msg", "payload": payload}, token=self.token)
            save_session(sd, to, st)
            return ("msg", resp)

        def ok(res):
            kind, resp = res
            self._log(self.chat_log, f"[you -> {to}] ({kind}) {text}\n")
            self._log(self.chat_log, f"  server: {resp}\n")

        def err(e):
            messagebox.showerror("Send failed", str(e))

        self._run_bg(work, ok, err)

    def _refresh_inbox(self):
        api = self.api_var.get().strip()
        sd = self.state_var.get().strip()
        if not self.token:
            messagebox.showwarning("Auth", "Login first")
            return

        def work():
            idd = load_or_create_identity(sd)
            pk = load_or_create_prekeys(sd)

            me_ik_dh_priv = X25519PrivateKey.from_private_bytes(b64d(idd["ik_dh_priv"]))
            spk_dh_priv = X25519PrivateKey.from_private_bytes(b64d(pk["spk_dh_priv"]))

            msgs = http_get(api, "/messages/inbox", token=self.token)
            out = []
            for m in msgs:
                frm = m["from_username"]
                if m["msg_type"] == "init":
                    x3 = m["payload"]["x3dh"]
                    rat = m["payload"]["ratchet"]
                    used_opk = x3.get("used_opk_pub")
                    bob_opk_priv = opk_take_by_pub(sd, used_opk) if used_opk else None

                    rk = x3dh_responder(
                        bob_ik_dh_priv=me_ik_dh_priv,
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
                    save_session(sd, frm, st)
                    out.append((frm, "INIT", pt))
                else:
                    st = load_session(sd, frm)
                    if st is None:
                        out.append((frm, "MSG", "(no session; missing init)"))
                        continue
                    h = m["payload"]["header"]
                    hdr = Header(dh_pub_b64=h["dh_pub"], pn=h["pn"], n=h["n"], nonce_b64=h["nonce"])
                    pt = st.decrypt(hdr, m["payload"]["ciphertext"]).decode("utf-8", errors="replace")
                    save_session(sd, frm, st)
                    out.append((frm, "MSG", pt))
            return out

        def ok(items):
            if not items:
                self._log(self.chat_log, "(inbox empty)\n")
                return
            for frm, typ, text in items:
                self._log(self.chat_log, f"[{frm}] {typ}: {text}\n")

        def err(e):
            messagebox.showerror("Inbox failed", str(e))

        self._run_bg(work, ok, err)


if __name__ == "__main__":
    app = SignalMiniGUI()
    app.mainloop()
