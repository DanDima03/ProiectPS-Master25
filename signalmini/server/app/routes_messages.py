import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, Message
from .schemas import SendMessageRequest, InboxMessage
from .auth import get_current_user

router = APIRouter(prefix="/messages", tags=["messages"])

@router.post("")
def send_message(
    req: SendMessageRequest,
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    to = db.query(User).filter(User.username == req.to_username).first()
    if not to:
        raise HTTPException(status_code=404, detail="Recipient not found")

    msg = Message(
        sender_id=me.id,
        recipient_id=to.id,
        msg_type=req.msg_type,
        payload_json=json.dumps(req.payload),
    )
    db.add(msg)
    db.commit()
    return {"ok": True, "message_id": msg.id}

@router.get("/inbox", response_model=list[InboxMessage])
def inbox(
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msgs = (
        db.query(Message)
        .filter(Message.recipient_id == me.id, Message.retrieved == False)
        .order_by(Message.id.asc())
        .all()
    )

    out: list[InboxMessage] = []
    for m in msgs:
        from_user = db.query(User).filter(User.id == m.sender_id).first()
        out.append(
            InboxMessage(
                id=m.id,
                from_username=from_user.username if from_user else "unknown",
                msg_type=m.msg_type,
                payload=json.loads(m.payload_json),
                created_at=str(m.created_at),
            )
        )

    # mark retrieved
    for m in msgs:
        m.retrieved = True
        m.retrieved_at = datetime.now(timezone.utc)
    db.commit()

    return out
