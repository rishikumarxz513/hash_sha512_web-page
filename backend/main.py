import hashlib
import json
import io
from typing import List

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect

import models
import schemas
from database import Base, engine, get_db
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)
from metadata_extractor import extract_metadata
from ai_analyzer import analyze_metadata
# ─── Create all tables ────────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ─── Migrate existing tables (add missing columns) ───────────────────────────
_MIGRATION_COLUMNS = {
    "hash_records": [
        ("metadata_json", "TEXT"),
        ("created_at_internal", "DATETIME"),
        ("modified_at_internal", "DATETIME"),
        ("is_original", "BOOLEAN"),
        ("originality_score", "FLOAT"),
        ("originality_breakdown", "TEXT"),
        ("virus_scan_status", "VARCHAR"),
        ("virus_scan_details", "TEXT"),
        ("ai_forensic_summary", "TEXT"),
        ("ai_originality_score", "FLOAT"),
    ]
}

def _run_migrations():
    """Add missing columns to existing tables (safe for SQLite)."""
    inspector = inspect(engine)
    with engine.connect() as conn:
        for table, columns in _MIGRATION_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for col_name, col_type in columns:
                if col_name not in existing:
                    try:
                        conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"
                        ))
                    except Exception:
                        pass  # column may already exist in some edge cases
        conn.commit()

_run_migrations()

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="HashVault API",
    description="SHA-512 File Hashing & Storage API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins for easier setup; lock this down to your render frontend URL later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Auth Endpoints ───────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=schemas.Token, status_code=status.HTTP_201_CREATED)
def register(user_data: schemas.UserRegister, db: Session = Depends(get_db)):
    """Create a new user account."""
    existing = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    if len(user_data.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters",
        )
    new_user = models.User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={"sub": new_user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/auth/login", response_model=schemas.Token)
def login(user_data: schemas.UserLogin, db: Session = Depends(get_db)):
    """Login and receive a JWT access token."""
    user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user


# ─── File/Hash Endpoints ──────────────────────────────────────────────────────

@app.post("/api/files/hash", response_model=schemas.HashResponse)
async def hash_file(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Upload a file, compute its SHA-512 hash in-memory, extract metadata,
    store the record, and return the hash + metadata. The file itself is
    NOT saved to disk.
    """
    content = await file.read()
    file_size = len(content)

    # Compute SHA-512 (primary hash)
    h512 = hashlib.sha512()
    h512.update(content)
    hash_result = h512.hexdigest()

    # Extract metadata (in-memory only)
    meta = extract_metadata(content, file.filename or "unknown")

    # AI Forensic Analysis — call NVIDIA API
    ai_result = {"forensic_summary": None, "ai_originality_score": None}
    try:
        # Build a metadata dict for the AI
        meta_parsed = None
        try:
            meta_parsed = json.loads(meta["metadata_json"]) if meta["metadata_json"] else {}
        except Exception:
            meta_parsed = {}

        ai_input = {
            "filename": file.filename,
            "mime_type": meta_parsed.get("mime_type", ""),
            "file_size": file_size,
            "created_at_internal": str(meta["created_at_internal"]) if meta["created_at_internal"] else None,
            "modified_at_internal": str(meta["modified_at_internal"]) if meta["modified_at_internal"] else None,
            "hash_value": hash_result,
            "originality_score": meta["originality_score"],
            "extra": meta_parsed.get("extra", {}),
        }
        ai_result = analyze_metadata(ai_input)
    except Exception as e:
        # AI failure should not block the upload
        import logging
        logging.getLogger(__name__).error(f"AI analysis error: {e}")

    # Store record in DB
    record = models.HashRecord(
        user_id=current_user.id,
        filename=file.filename,
        hash_value=hash_result,
        file_size=float(file_size),
        metadata_json=meta["metadata_json"],
        created_at_internal=meta["created_at_internal"],
        modified_at_internal=meta["modified_at_internal"],
        is_original=meta["is_original"],
        originality_score=meta["originality_score"],
        originality_breakdown=meta["originality_breakdown"],
        ai_forensic_summary=ai_result.get("forensic_summary"),
        ai_originality_score=ai_result.get("ai_originality_score"),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return schemas.HashResponse(
        filename=file.filename,
        hash_value=hash_result,
        file_size=float(file_size),
        record_id=record.id,
        metadata_json=meta["metadata_json"],
        created_at_internal=meta["created_at_internal"],
        modified_at_internal=meta["modified_at_internal"],
        is_original=meta["is_original"],
        originality_score=meta["originality_score"],
        originality_breakdown=meta["originality_breakdown"],
        ai_forensic_summary=ai_result.get("forensic_summary"),
        ai_originality_score=ai_result.get("ai_originality_score"),
    )


@app.get("/api/files/hashes", response_model=List[schemas.HashRecordOut])
def get_hashes(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
):
    """Get this user's hash history, newest first."""
    records = (
        db.query(models.HashRecord)
        .filter(models.HashRecord.user_id == current_user.id)
        .order_by(models.HashRecord.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return records


@app.delete("/api/files/hashes/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_hash(
    record_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a hash record by ID (must belong to current user)."""
    record = (
        db.query(models.HashRecord)
        .filter(
            models.HashRecord.id == record_id,
            models.HashRecord.user_id == current_user.id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
    db.delete(record)
    db.commit()


@app.get("/api/stats")
def get_stats(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get aggregate stats for the current user."""
    records = (
        db.query(models.HashRecord)
        .filter(models.HashRecord.user_id == current_user.id)
        .all()
    )
    total_files = len(records)
    total_bytes = sum(r.file_size or 0 for r in records)
    return {
        "total_files": total_files,
        "total_bytes": total_bytes,
    }


@app.get("/")
def root():
    return {"message": "HashVault API is running. Visit /docs for the API reference."}
