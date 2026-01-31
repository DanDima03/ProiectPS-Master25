import os
import json
import time
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Tuple

import requests

from crypto import (
    Identity, PreKeys, verify_spk_sig,
    x3dh_initiator, x3dh_responder,
    RatchetState, Header,
    ratchet_to_json, ratchet_from_json,
    b64e, b64d
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


# =========================
# Paths / storage
# =========================

DEFAULT_API = os.environ.get("SIGNALMINI_API", "http://localhost:8000")

def base_app_dir() -> str:
    # Windows: %APPDATA%\SignalMini, else ~/.signalmini
    appdata = os.environ.get("APPDATA")
    if appdata:
        return os.path.join(appdata, "SignalMini")
    return os.path.join(os.path.expanduser("~"), ".signalmini")

def user_state_dir(username: str) -> str:
    return os.path.join(base_app_dir(), username)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def jpath(state_dir: str, name: str) -> str:
    ensure_dir(state_dir)
    return os.path.join(state_dir, name)

def save_json(state_dir: str, fname: str, data: dict):
    with open(jpath(state_dir, fname), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_json(state_dir: str, fname: str) -> dict:
    with open(jpath(state_dir, fname), "r", encoding="utf-8") as f:
        return json.load(f)

def exists(state_dir: str, fname: str) -> bool:
    return os.path.exists(jpath(state_dir, fname))

def sess_file(peer: str) -> str:
    return f"session_{peer}.json"

def load_session(state_dir: str, peer: str) -> Optional[RatchetState]:
    if not exists(state_dir, sess_file(peer)):
        return None
    return ratchet_from_json(load_json(state_dir, sess_file(peer)))

def save_session(state_dir: str, peer: str, st: RatchetState):
    save_json(state_dir, sess_file(peer), ratchet_to_json(st))

def hist_file(peer: str) -> str:
    return f"history_{peer}.json"

def load_history(state_dir: str, peer: str) -> list:
    if not exists(state_dir, hist_file(peer)):
        return []
    return load_json(state_dir, hist_file(peer))

def append_history(state_dir: str, peer: str, item: dict):
    hist = load_history(state_dir, peer)
    hist.append(item)
    save_json(state_dir, hist_file(peer), hist)

def list_known_peers(state_dir: str) -> List[str]:
    # peers from session_*.json and history_*.json
    if not os.path.isdir(state_dir):
        return []
    peers = set()
    for fn in os.listdir(state_dir):
        if fn.startswith("session_") and fn.endswith(".json"):
            peers.add(fn[len("session_"):-len(".json")])
        if fn.startswith("history_") and fn.endswith(".json"):
            peers.add(fn[len("history_"):-len(".json")])
    return sorted(peers)


# =========================
# UNREAD (badge) storage
# =========================

def unread_file() -> str:
    return "unread.json"

def load_unread(state_dir: str) -> dict:
    if not exists(state_dir, unread_file()):
        return {}
    return load_json(state_dir, unread_file())

def save_unread(state_dir: str, d: dict):
    save_json(state_dir, unread_file(), d)

def inc_unread(state_dir: str, peer: str, n: int = 1):
    d = load_unread(state_dir)
    d[peer] = int(d.get(peer, 0)) + n
    save_unread(state_dir, d)

def clear_unread(state_dir: str, peer: str):
    d = load_unread(state_dir)
    if peer in d:
        d.pop(peer, None)
        save_unread(state_dir, d)

def get_unread(state_dir: str, peer: str) -> int:
    d = load_unread(state_dir)
    return int(d.get(peer, 0))


# =========================
# Local key management
# =========================

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


# =========================
# HTTP
# =========================

def headers_with_token(token: Optional[str]) -> dict:
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}

def http_post(api: str, path: str, body: dict, token: Optional[str] = None) -> dict:
    r = requests.post(f"{api}{path}", json=body, headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_put(api: str, path: str, body: dict, token: Optional[str] = None) -> dict:
    r = requests.put(f"{api}{path}", json=body, headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()

def http_get(api: str, path: str, token: Optional[str] = None):
    r = requests.get(f"{api}{path}", headers=headers_with_token(token), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")
    return r.json()


# =========================
# UI components
# =========================

class Bubble(tk.Frame):
    def __init__(self, master, text: str, is_me: bool, timestamp: Optional[str] = None):
        super().__init__(master, bg=master["bg"])
        bubble_bg = "#DCF8C6" if is_me else "#FFFFFF"  # whatsapp-ish
        fg = "#111111"

        outer = tk.Frame(self, bg=master["bg"])
        outer.pack(fill=tk.X, padx=10, pady=3)

        anchor = "e" if is_me else "w"
        box = tk.Frame(outer, bg=bubble_bg, bd=0, highlightthickness=1, highlightbackground="#E0E0E0")
        box.pack(side=tk.RIGHT if is_me else tk.LEFT, anchor=anchor)

        msg = tk.Label(
            box, text=text, bg=bubble_bg, fg=fg, justify=tk.LEFT,
            wraplength=520, padx=10, pady=7, font=("Segoe UI", 10)
        )
        msg.pack(anchor="w")

        if timestamp:
            ts = tk.Label(box, text=timestamp, bg=bubble_bg, fg="#666666", padx=10, pady=0,
                          font=("Segoe UI", 8))
            ts.pack(anchor="e")


class ScrollableChat(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#EFEFEF")
        self.canvas = tk.Canvas(self, bg="#EFEFEF", highlightthickness=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.inner = tk.Frame(self.canvas, bg="#EFEFEF")
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._on_configure)
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.after(10, self.scroll_to_bottom)

    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self.inner_id, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def clear(self):
        for w in self.inner.winfo_children():
            w.destroy()

    def add_bubble(self, text: str, is_me: bool, timestamp: Optional[str] = None):
        b = Bubble(self.inner, text=text, is_me=is_me, timestamp=timestamp)
        b.pack(fill=tk.X)

    def scroll_to_bottom(self):
        self.canvas.yview_moveto(1.0)


# =========================
# Main App
# =========================

class SignalMiniWhatsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SignalMini Chat")
        self.geometry("1050x700")
        self.minsize(980, 650)

        self.api = DEFAULT_API
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.state_dir: Optional[str] = None

        self.selected_peer: Optional[str] = None
        self.poll_interval_sec = 2

        self.uiq: queue.Queue = queue.Queue()
        self._build_styles()
        self._build_layout()

        self.after(100, self._drain_uiq)
        threading.Thread(target=self._poller_loop, daemon=True).start()

    def _build_styles(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except:
            pass

    def _build_layout(self):
        root = ttk.Frame(self)
        root.pack(fill=tk.BOTH, expand=True)

        self.sidebar = ttk.Frame(root, width=300)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        self.main = ttk.Frame(root)
        self.main.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        top = ttk.Frame(self.sidebar, padding=10)
        top.pack(fill=tk.X)

        ttk.Label(top, text="SignalMini", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.lbl_status = ttk.Label(top, text="Not logged in", foreground="#555555")
        self.lbl_status.pack(anchor="w", pady=(3, 0))

        frm_auth = ttk.Frame(top)
        frm_auth.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(frm_auth, text="User").grid(row=0, column=0, sticky="w")
        self.ent_user = ttk.Entry(frm_auth)
        self.ent_user.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        ttk.Label(frm_auth, text="Pass").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.ent_pass = ttk.Entry(frm_auth, show="*")
        self.ent_pass.grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=(6, 0))

        frm_auth.columnconfigure(1, weight=1)

        frm_btn = ttk.Frame(top)
        frm_btn.pack(fill=tk.X, pady=(8, 0))

        ttk.Button(frm_btn, text="Register", command=self.register_user).pack(side=tk.LEFT)
        ttk.Button(frm_btn, text="Login", command=self.login_user).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm_btn, text="Keys", command=self.publish_keys_flow).pack(side=tk.LEFT, padx=6)

        ttk.Separator(self.sidebar).pack(fill=tk.X, pady=8)

        conv_top = ttk.Frame(self.sidebar, padding=(10, 0, 10, 10))
        conv_top.pack(fill=tk.X)

        self.search_var = tk.StringVar(value="")

        self.ent_search = ttk.Entry(conv_top, textvariable=self.search_var)
        self.ent_search.pack(fill=tk.X)
        self.ent_search.insert(0, "Search / add peer...")

        self.ent_search.bind("<FocusIn>", self._search_focus_in)
        self.ent_search.bind("<FocusOut>", self._search_focus_out)
        self.ent_search.bind("<Return>", self._add_peer_from_search)

        self.lst_peers = tk.Listbox(self.sidebar, height=30, activestyle="none")
        self.lst_peers.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.lst_peers.bind("<<ListboxSelect>>", self._on_peer_selected)

        self.search_var.trace_add("write", lambda *_: self.refresh_conversations())

        hdr = ttk.Frame(self.main, padding=10)
        hdr.pack(fill=tk.X)

        self.lbl_chat_title = ttk.Label(hdr, text="Select a chat", font=("Segoe UI", 12, "bold"))
        self.lbl_chat_title.pack(side=tk.LEFT)

        ttk.Button(hdr, text="Refresh", command=self.refresh_inbox).pack(side=tk.RIGHT)
        self.var_autorefresh = tk.BooleanVar(value=True)
        ttk.Checkbutton(hdr, text="Auto", variable=self.var_autorefresh).pack(side=tk.RIGHT, padx=8)

        ttk.Separator(self.main).pack(fill=tk.X)

        self.chat = ScrollableChat(self.main)
        self.chat.pack(fill=tk.BOTH, expand=True)

        bottom = ttk.Frame(self.main, padding=10)
        bottom.pack(fill=tk.X)

        self.msg_var = tk.StringVar(value="")
        self.ent_msg = ttk.Entry(bottom, textvariable=self.msg_var)
        self.ent_msg.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ent_msg.bind("<Return>", lambda e: self.send_message())

        ttk.Button(bottom, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=(10, 0))

    def _search_focus_in(self, event):
        if self.ent_search.get().strip() == "Search / add peer...":
            self.ent_search.delete(0, tk.END)

    def _search_focus_out(self, event):
        if not self.ent_search.get().strip():
            self.ent_search.insert(0, "Search / add peer...")

    def _add_peer_from_search(self, event=None):
        val = self.ent_search.get().strip()
        if not val or val == "Search / add peer...":
            return
        if self.state_dir:
            ensure_dir(self.state_dir)
            if not exists(self.state_dir, hist_file(val)):
                save_json(self.state_dir, hist_file(val), [])
            clear_unread(self.state_dir, val)
        self.refresh_conversations()
        self._select_peer(val)

    def _bg(self, fn, on_ok=None, on_err=None):
        def run():
            try:
                res = fn()
                if on_ok:
                    self.uiq.put(("ok", on_ok, res))
            except Exception as e:
                self.uiq.put(("err", on_err, e))
        threading.Thread(target=run, daemon=True).start()

    def _drain_uiq(self):
        try:
            while True:
                kind, cb, payload = self.uiq.get_nowait()
                if kind == "ok":
                    if cb:
                        cb(payload)
                else:
                    if cb:
                        cb(payload)
                    else:
                        messagebox.showerror("Error", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_uiq)

    # =========================
    # Auth / keys
    # =========================

    def register_user(self):
        user = self.ent_user.get().strip()
        pw = self.ent_pass.get()
        if not user or not pw:
            return messagebox.showwarning("Missing", "Username/password required")

        def work():
            return http_post(self.api, "/users/register", {"username": user, "password": pw})

        def ok(_):
            messagebox.showinfo("OK", f"Registered {user}. Now login.")

        def err(e):
            messagebox.showerror("Register failed", str(e))

        self._bg(work, ok, err)

    def login_user(self):
        user = self.ent_user.get().strip()
        pw = self.ent_pass.get()
        if not user or not pw:
            return messagebox.showwarning("Missing", "Username/password required")

        def work():
            return http_post(self.api, "/users/login", {"username": user, "password": pw})

        def ok(tok):
            self.token = tok["access_token"]
            self.username = user
            self.state_dir = user_state_dir(user)
            ensure_dir(self.state_dir)

            save_json(self.state_dir, "token.json", tok)
            save_json(self.state_dir, "me.json", {"username": user})

            self.lbl_status.config(text=f"Logged in: {user}\n{self.state_dir}")
            self.refresh_conversations()
            messagebox.showinfo("OK", f"Logged in as {user}\nState: {self.state_dir}")

        def err(e):
            messagebox.showerror("Login failed", str(e))

        self._bg(work, ok, err)

    def publish_keys_flow(self):
        if not self.token or not self.username or not self.state_dir:
            return messagebox.showwarning("Auth", "Login first")

        def work():
            idd = load_or_create_identity(self.state_dir)
            pk = load_or_create_prekeys(self.state_dir, n_opk=10)

            body = {
                "ik_dh_pub": idd["ik_dh_pub"],
                "ik_sign_pub": idd["ik_sign_pub"],
                "spk_dh_pub": pk["spk_dh_pub"],
                "spk_sig": pk["spk_sig"],
                "opk_dh_pubs": pk["opk_dh_pubs"],
            }
            return http_put(self.api, "/keys/bundle", body, token=self.token)

        def ok(resp):
            messagebox.showinfo("Keys", f"Published keys OK.\n{resp}")

        def err(e):
            messagebox.showerror("Keys publish failed", str(e))

        self._bg(work, ok, err)

    # =========================
    # Conversations / selection (with unread badge)
    # =========================

    def refresh_conversations(self):
        self.lst_peers.delete(0, tk.END)
        if not self.state_dir:
            return

        peers = list_known_peers(self.state_dir)
        q = self.search_var.get().strip()
        if q and q != "Search / add peer...":
            peers = [p for p in peers if q.lower() in p.lower()]

        for p in peers:
            unread = get_unread(self.state_dir, p)
            badge = "● " if unread > 0 else "  "

            hist = load_history(self.state_dir, p)
            preview = ""
            if hist:
                last = hist[-1]
                prefix = "You: " if last.get("me") else ""
                preview = f" — {prefix}{last.get('text','')[:28]}"

            self.lst_peers.insert(tk.END, f"{badge}{p}{preview}")

        if self.selected_peer:
            self._highlight_selected_peer_in_list()
        elif peers:
            self._select_peer(peers[0])

    def _highlight_selected_peer_in_list(self):
        if not self.selected_peer:
            return
        for i in range(self.lst_peers.size()):
            txt = self.lst_peers.get(i)
            if txt.startswith("● " + self.selected_peer) or txt.startswith("  " + self.selected_peer):
                self.lst_peers.selection_clear(0, tk.END)
                self.lst_peers.selection_set(i)
                self.lst_peers.activate(i)
                break

    def _on_peer_selected(self, event=None):
        if not self.lst_peers.curselection():
            return
        idx = self.lst_peers.curselection()[0]
        row = self.lst_peers.get(idx)

        # row format: "● peer — preview" OR "  peer — preview"
        row = row[2:]
        peer = row.split(" — ", 1)[0].strip()
        self._select_peer(peer)

    def _select_peer(self, peer: str):
        self.selected_peer = peer
        self.lbl_chat_title.config(text=peer)

        if self.state_dir:
            clear_unread(self.state_dir, peer)  # mark as read

        self._load_chat_history(peer)
        self.refresh_conversations()

    def _load_chat_history(self, peer: str):
        self.chat.clear()
        if not self.state_dir:
            return
        hist = load_history(self.state_dir, peer)
        for it in hist:
            self.chat.add_bubble(it["text"], is_me=it["me"], timestamp=it.get("ts"))
        self.chat.scroll_to_bottom()

    # =========================
    # Messaging
    # =========================

    def send_message(self):
        if not self.token or not self.username or not self.state_dir:
            return messagebox.showwarning("Auth", "Login first")
        peer = self.selected_peer
        if not peer:
            return messagebox.showwarning("Chat", "Select a peer")
        text = self.msg_var.get().strip()
        if not text:
            return

        append_history(self.state_dir, peer, {"me": True, "text": text, "ts": time.strftime("%H:%M")})
        self.chat.add_bubble(text, is_me=True, timestamp=time.strftime("%H:%M"))
        self.msg_var.set("")
        self.chat.scroll_to_bottom()
        self.refresh_conversations()

        def work():
            idd = load_or_create_identity(self.state_dir)
            load_or_create_prekeys(self.state_dir, n_opk=10)

            st = load_session(self.state_dir, peer)
            if st is None:
                bundle = http_get(self.api, f"/keys/bundle/{peer}")
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
                resp = http_post(self.api, "/messages",
                                 {"to_username": peer, "msg_type": "init", "payload": payload},
                                 token=self.token)
                save_session(self.state_dir, peer, st)
                return resp

            hdr, ct_b64 = st.encrypt(text.encode("utf-8"))
            payload = {
                "header": {"dh_pub": hdr.dh_pub_b64, "pn": hdr.pn, "n": hdr.n, "nonce": hdr.nonce_b64},
                "ciphertext": ct_b64,
            }
            resp = http_post(self.api, "/messages",
                             {"to_username": peer, "msg_type": "msg", "payload": payload},
                             token=self.token)
            save_session(self.state_dir, peer, st)
            return resp

        def err(e):
            messagebox.showerror("Send failed", str(e))

        self._bg(work, on_ok=None, on_err=err)

    def refresh_inbox(self):
        if not self.token or not self.username or not self.state_dir:
            return

        def work():
            idd = load_or_create_identity(self.state_dir)
            pk = load_or_create_prekeys(self.state_dir, n_opk=10)

            me_ik_dh_priv = X25519PrivateKey.from_private_bytes(b64d(idd["ik_dh_priv"]))
            spk_dh_priv = X25519PrivateKey.from_private_bytes(b64d(pk["spk_dh_priv"]))

            msgs = http_get(self.api, "/messages/inbox", token=self.token)
            decoded: List[Tuple[str, str]] = []

            for m in msgs:
                frm = m["from_username"]
                if m["msg_type"] == "init":
                    x3 = m["payload"]["x3dh"]
                    rat = m["payload"]["ratchet"]
                    used_opk = x3.get("used_opk_pub")
                    bob_opk_priv = opk_take_by_pub(self.state_dir, used_opk) if used_opk else None

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

                    save_session(self.state_dir, frm, st)
                    decoded.append((frm, pt))

                else:
                    st = load_session(self.state_dir, frm)
                    if st is None:
                        decoded.append((frm, "(no session; missing init)"))
                        continue
                    h = m["payload"]["header"]
                    hdr = Header(dh_pub_b64=h["dh_pub"], pn=h["pn"], n=h["n"], nonce_b64=h["nonce"])
                    pt = st.decrypt(hdr, m["payload"]["ciphertext"]).decode("utf-8", errors="replace")
                    save_session(self.state_dir, frm, st)
                    decoded.append((frm, pt))

            return decoded

        def ok(items):
            if not items:
                return

            for frm, text in items:
                append_history(self.state_dir, frm, {"me": False, "text": text, "ts": time.strftime("%H:%M")})

                if self.selected_peer == frm:
                    self.chat.add_bubble(text, is_me=False, timestamp=time.strftime("%H:%M"))
                    self.chat.scroll_to_bottom()
                    clear_unread(self.state_dir, frm)
                else:
                    inc_unread(self.state_dir, frm, 1)

            self.refresh_conversations()
            if not self.selected_peer and items:
                self._select_peer(items[0][0])

        def err(e):
            messagebox.showerror("Inbox failed", str(e))

        self._bg(work, ok, err)

    # =========================
    # Auto poller
    # =========================

    def _poller_loop(self):
        while True:
            time.sleep(self.poll_interval_sec)
            try:
                if self.var_autorefresh.get() and self.token and self.state_dir:
                    self.uiq.put(("ok", lambda _: self.refresh_inbox(), None))
            except:
                pass


if __name__ == "__main__":
    app = SignalMiniWhatsApp()
    app.mainloop()
