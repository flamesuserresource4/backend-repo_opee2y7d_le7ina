from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List
from datetime import datetime

# Users collection
class User(BaseModel):
    full_name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    phone: str = Field(..., description="Phone number")
    password_hash: str = Field(..., description="Hashed password")
    role: Literal['citizen', 'official'] = Field('citizen', description="User role")
    avatar_url: Optional[str] = Field(None, description="Optional avatar image URL")

# Session tokens collection
class Session(BaseModel):
    user_id: str
    token: str
    role: Literal['citizen', 'official']
    expires_at: Optional[datetime] = None

# Complaints collection
class Complaint(BaseModel):
    id: str = Field(..., description="Public complaint ID e.g. PH-XXXXXXXX")
    status: Literal['Pending', 'In Progress', 'Resolved'] = Field('Pending', description="Complaint status")
    remarks: Optional[str] = Field(None, description="Official remarks")

    full_name: str
    email: EmailStr
    phone: str

    location: str
    description: str
    photo: Optional[str] = Field(None, description="Base64 Data URL or remote URL of the uploaded image")

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
