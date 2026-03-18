from pydantic import BaseModel
from typing import Optional

class AskRequest(BaseModel):
    question: str

class SignupRequest(BaseModel):
    username: str
    password: str
    full_name: str = None
    email: str = None
    role: str  


class LoginRequest(BaseModel):
    username: str
    password: str
