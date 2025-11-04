import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Complaint as ComplaintSchema, Session as SessionSchema

app = FastAPI(title="Pothole Complaint Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${pw_hash}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, pw_hash = stored.split("$")
    except ValueError:
        return False
    test = hashlib.sha256((salt + password).encode()).hexdigest()
    return secrets.compare_digest(test, pw_hash)

def create_session(user_id: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    session = SessionSchema(user_id=user_id, token=token, role=role, expires_at=datetime.now(timezone.utc) + timedelta(days=7))
    create_document("session", session)
    return token

def get_user_by_email(email: str) -> Optional[dict]:
    users = get_documents("user", {"email": email.lower()}, limit=1)
    return users[0] if users else None

class SignupRequest(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class OfficialLoginRequest(BaseModel):
    email: EmailStr
    password: str

class ComplaintCreateRequest(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    location: str
    description: str
    photo: Optional[str] = None

class ComplaintUpdateRequest(BaseModel):
    status: Optional[Literal['Pending', 'In Progress', 'Resolved']] = None
    remarks: Optional[str] = None

# Auth helpers

def get_current_session(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    sessions = get_documents("session", {"token": token}, limit=1)
    if not sessions:
        raise HTTPException(status_code=401, detail="Invalid token")
    sess = sessions[0]
    # If expires_at exists, ensure not expired
    exp = sess.get("expires_at")
    if exp and isinstance(exp, str):
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            exp_dt = None
        if exp_dt and exp_dt < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token expired")
    return sess

# Routes

@app.get("/")
def read_root():
    return {"message": "Pothole Complaint API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response

# Authentication

@app.post("/auth/citizen/signup")
def citizen_signup(payload: SignupRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = hash_password(payload.password)
    user = UserSchema(full_name=payload.full_name, email=payload.email.lower(), phone=payload.phone, password_hash=password_hash, role='citizen')
    user_id = create_document("user", user)
    token = create_session(user_id, 'citizen')
    return {"token": token, "user": {"id": user_id, "full_name": user.full_name, "email": user.email, "phone": user.phone, "role": user.role}}

@app.post("/auth/citizen/login")
def citizen_login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")) or user.get("role") != 'citizen':
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user.get("_id")), 'citizen')
    return {"token": token, "user": {"id": str(user.get("_id")), "full_name": user.get("full_name"), "email": user.get("email"), "phone": user.get("phone"), "role": user.get("role")}}

@app.post("/auth/official/login")
def official_login(payload: OfficialLoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")) or user.get("role") != 'official':
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user.get("_id")), 'official')
    return {"token": token, "user": {"id": str(user.get("_id")), "full_name": user.get("full_name"), "email": user.get("email"), "phone": user.get("phone"), "role": user.get("role")}}

@app.get("/auth/me")
def auth_me(session: dict = Depends(get_current_session)):
    if not session:
        return {"authenticated": False}
    try:
        user = db["user"].find_one({"_id": ObjectId(session.get("user_id"))})
    except Exception:
        user = None
    return {"authenticated": True, "role": session.get("role"), "user": {"id": str(user.get("_id")) if user else None, "full_name": user.get("full_name") if user else None}}

# Complaints

@app.post("/complaints")
def create_complaint(payload: ComplaintCreateRequest):
    # Generate complaint ID
    suffix = secrets.token_hex(4).upper()
    complaint_id = f"PH-{suffix}"
    comp = ComplaintSchema(
        id=complaint_id,
        status='Pending',
        remarks=None,
        full_name=payload.full_name,
        email=payload.email.lower(),
        phone=payload.phone,
        location=payload.location,
        description=payload.description,
        photo=payload.photo
    )
    create_document("complaint", comp)
    return {"id": complaint_id, "status": comp.status}

@app.get("/complaints/track")
def track_complaint(id: Optional[str] = None, phone: Optional[str] = None):
    if not id and not phone:
        raise HTTPException(status_code=400, detail="Provide id or phone")
    query = {}
    if id:
        query["id"] = id
    if phone:
        query["phone"] = phone
    results = get_documents("complaint", query, limit=20)
    return [{
        "id": c.get("id"),
        "status": c.get("status"),
        "remarks": c.get("remarks"),
        "full_name": c.get("full_name"),
        "phone": c.get("phone"),
        "location": c.get("location"),
        "description": c.get("description"),
        "photo": c.get("photo"),
        "created_at": c.get("created_at"),
    } for c in results]

@app.get("/complaints")
def list_complaints(session: dict = Depends(get_current_session)):
    if not session or session.get("role") != 'official':
        raise HTTPException(status_code=403, detail="Officials only")
    items = get_documents("complaint", {}, limit=100)
    items.sort(key=lambda x: x.get("created_at", datetime.now()), reverse=True)
    return items

@app.patch("/complaints/{complaint_id}")
def update_complaint(complaint_id: str, payload: ComplaintUpdateRequest, session: dict = Depends(get_current_session)):
    if not session or session.get("role") != 'official':
        raise HTTPException(status_code=403, detail="Officials only")
    update_fields = {}
    if payload.status is not None:
        update_fields["status"] = payload.status
    if payload.remarks is not None:
        update_fields["remarks"] = payload.remarks
    if not update_fields:
        raise HTTPException(status_code=400, detail="No updates provided")
    update_fields["updated_at"] = datetime.now(timezone.utc)
    res = db["complaint"].find_one_and_update({"id": complaint_id}, {"$set": update_fields})
    if not res:
        raise HTTPException(status_code=404, detail="Complaint not found")
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
