from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional


# ─── Auth ───────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserOut(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Hash Records ────────────────────────────────────────────────────────────

class HashRecordOut(BaseModel):
    id: int
    filename: str
    hash_value: str
    file_size: Optional[float] = None
    created_at: datetime
    metadata_json: Optional[str] = None
    created_at_internal: Optional[datetime] = None
    modified_at_internal: Optional[datetime] = None
    is_original: Optional[bool] = None
    originality_score: Optional[float] = None
    originality_breakdown: Optional[str] = None
    ai_forensic_summary: Optional[str] = None
    ai_originality_score: Optional[float] = None

    class Config:
        from_attributes = True


class HashResponse(BaseModel):
    filename: str
    hash_value: str
    file_size: Optional[float] = None
    record_id: int
    metadata_json: Optional[str] = None
    created_at_internal: Optional[datetime] = None
    modified_at_internal: Optional[datetime] = None
    is_original: Optional[bool] = None
    originality_score: Optional[float] = None
    originality_breakdown: Optional[str] = None
    ai_forensic_summary: Optional[str] = None
    ai_originality_score: Optional[float] = None
