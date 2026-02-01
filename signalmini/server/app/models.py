from sqlalchemy import String, Integer, Boolean, ForeignKey, DateTime, Text, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())

    keys = relationship("UserKeys", back_populates="user", uselist=False)

class UserKeys(Base):
    __tablename__ = "user_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    # public keys are stored as base64url strings
    ik_dh_pub: Mapped[str] = mapped_column(Text)
    ik_sign_pub: Mapped[str] = mapped_column(Text)

    spk_dh_pub: Mapped[str] = mapped_column(Text)
    spk_sig: Mapped[str] = mapped_column(Text)

    user = relationship("User", back_populates="keys")
    opks = relationship("OneTimePreKey", back_populates="user_keys", cascade="all, delete-orphan")

class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"
    __table_args__ = (UniqueConstraint("user_keys_id", "opk_dh_pub", name="uq_user_opk"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_keys_id: Mapped[int] = mapped_column(ForeignKey("user_keys.id"), index=True)

    opk_dh_pub: Mapped[str] = mapped_column(Text)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    used_at: Mapped[str] = mapped_column(DateTime(timezone=True), nullable=True)

    user_keys = relationship("UserKeys", back_populates="opks")

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    msg_type: Mapped[str] = mapped_column(String(16))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())

    retrieved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    retrieved_at: Mapped[str] = mapped_column(DateTime(timezone=True), nullable=True)
