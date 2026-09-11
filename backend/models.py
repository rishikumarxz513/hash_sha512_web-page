from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    hashes = relationship("HashRecord", back_populates="owner", cascade="all, delete-orphan")


class HashRecord(Base):
    __tablename__ = "hash_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String, nullable=False)
    hash_value = Column(String, nullable=False)
    file_size = Column(Float, nullable=True)  # size in bytes
    created_at = Column(DateTime, default=datetime.utcnow)

    # ─── Metadata fields ─────────────────────────────────────────
    metadata_json = Column(Text, nullable=True)
    created_at_internal = Column(DateTime, nullable=True)
    modified_at_internal = Column(DateTime, nullable=True)
    is_original = Column(Boolean, nullable=True)

    # ─── Originality & Scoring fields ─────────────────────────────
    originality_score = Column(Float, nullable=True)
    originality_breakdown = Column(Text, nullable=True)

    # ─── Virus scan fields ────────────────────────────────────────
    virus_scan_status = Column(String, nullable=True)
    virus_scan_details = Column(Text, nullable=True)

    # ─── AI Forensic Analysis fields ─────────────────────────────
    ai_forensic_summary = Column(Text, nullable=True)
    ai_originality_score = Column(Float, nullable=True)

    owner = relationship("User", back_populates="hashes")
