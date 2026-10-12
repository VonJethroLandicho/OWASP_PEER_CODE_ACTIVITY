"""
SecureNotes API  —  Week 13 Security Lab (STUDENT VERSION - FIXED)
Web Systems and Technologies

A tiny notes service: users register, log in, and keep private notes.
Secured against the OWASP Top 10 (2025) vulnerabilities.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# Fix A02 (Security Misconfiguration): Load secret from environment variable
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123-change-in-production")

# Fix A02 (Security Misconfiguration): Restrict CORS from wildcard '*' to trusted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


# --- security helpers (standard library only) ------------------------------
def hash_password(password: str, salt: str = None) -> str:
    """Fix A04: Hash password with salt using PBKDF2."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
    return f"{salt}${hashed}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Fix A04: Safely verify password using constant-time comparison."""
    try:
        salt, expected_hash = stored_hash.split("$", 1)
        calc_hash = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt.encode(), 100000).hex()
        return hmac.compare_digest(calc_hash, expected_hash)
    except Exception:
        return False


def create_token(user_id: int) -> str:
    """Fix A07: Create signed, expiring token using HMAC-SHA256."""
    expires = int(time.time()) + 3600  # 1 hour expiration
    payload = f"{user_id}:{expires}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_token(token: str):
    """Fix A07: Verify token signature and expiry."""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None
        user_id_str, expires_str, sig = parts
        payload = f"{user_id_str}:{expires_str}"
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(expires_str) < int(time.time()):
            return None
        return int(user_id_str)
    except Exception:
        return None


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # Fix A04: Store passwords hashed and salted instead of plaintext
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (hash_password("admin123"),))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice', ?, 0)", (hash_password("alicepass"),))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('bob', ?, 0)", (hash_password("bobpass"),))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    """Fix A07: Authenticate caller using signed, expiring token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.replace("Bearer ", "").strip()
    user_id = verify_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="User not found")
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    """Fix A02: Handle errors safely without leaking internal stack traces."""
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=500,
        content={"error": "An internal server error occurred"},
    )


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    # Fix A04: Hash password before storing in database
    hashed_pw = hash_password(creds.password)
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hashed_pw),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # Fix A05: Parameterized query prevents SQL injection
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    # Fix A04 & A07: Verify salted hash and return uniform error without leaking account existence
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # Fix A07: Return signed expiring token instead of predictable integer ID
    return {"token": create_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT id, owner_id, title, body FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute("SELECT id, owner_id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    # Fix A01: Broken Access Control (prevent IDOR) - ensure caller owns the note
    if row["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this note")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    # Fix A10: Exceptional Conditions - fail closed on permission check
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    # Avoid returning sensitive password hashes
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}

