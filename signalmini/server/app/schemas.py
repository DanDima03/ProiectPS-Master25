from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=4, max_length=128)

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class PublishKeysRequest(BaseModel):
    ik_dh_pub: str
    ik_sign_pub: str
    spk_dh_pub: str
    spk_sig: str
    opk_dh_pubs: List[str] = []

class PreKeyBundleResponse(BaseModel):
    username: str
    ik_dh_pub: str
    ik_sign_pub: str
    spk_dh_pub: str
    spk_sig: str
    opk_dh_pub: Optional[str] = None

class SendMessageRequest(BaseModel):
    to_username: str
    msg_type: str
    payload: Dict[str, Any]

class InboxMessage(BaseModel):
    id: int
    from_username: str
    msg_type: str
    payload: Dict[str, Any]
    created_at: str
