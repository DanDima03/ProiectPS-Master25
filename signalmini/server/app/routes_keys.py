from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone

from .db import get_db
from .models import User, UserKeys, OneTimePreKey
from .schemas import PublishKeysRequest, PreKeyBundleResponse
from .auth import get_current_user

router = APIRouter(prefix="/keys", tags=["keys"])

@router.put("/bundle")
def publish_bundle(
    req: PublishKeysRequest,
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    keys = db.query(UserKeys).filter(UserKeys.user_id == me.id).first()
    if not keys:
        keys = UserKeys(
            user_id=me.id,
            ik_dh_pub=req.ik_dh_pub,
            ik_sign_pub=req.ik_sign_pub,
            spk_dh_pub=req.spk_dh_pub,
            spk_sig=req.spk_sig,
        )
        db.add(keys)
        db.flush()
    else:
        keys.ik_dh_pub = req.ik_dh_pub
        keys.ik_sign_pub = req.ik_sign_pub
        keys.spk_dh_pub = req.spk_dh_pub
        keys.spk_sig = req.spk_sig

    # add OPKs (ignore duplicates)
    existing = {o.opk_dh_pub for o in keys.opks}
    for opk in req.opk_dh_pubs:
        if opk not in existing:
            db.add(OneTimePreKey(user_keys_id=keys.id, opk_dh_pub=opk, is_used=False))

    db.commit()
    return {"ok": True, "opk_total": len(keys.opks)}

@router.get("/bundle/{username}", response_model=PreKeyBundleResponse)
def get_bundle(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.keys:
        raise HTTPException(status_code=404, detail="User or keys not found")

    keys = user.keys

    # pick one unused OPK, mark used (best-effort minimal)
    opk = (
        db.query(OneTimePreKey)
        .filter(OneTimePreKey.user_keys_id == keys.id, OneTimePreKey.is_used == False)
        .order_by(OneTimePreKey.id.asc())
        .first()
    )
    opk_pub = None
    if opk:
        opk.is_used = True
        opk.used_at = datetime.now(timezone.utc)
        opk_pub = opk.opk_dh_pub
        db.commit()

    return PreKeyBundleResponse(
        username=username,
        ik_dh_pub=keys.ik_dh_pub,
        ik_sign_pub=keys.ik_sign_pub,
        spk_dh_pub=keys.spk_dh_pub,
        spk_sig=keys.spk_sig,
        opk_dh_pub=opk_pub,
    )
