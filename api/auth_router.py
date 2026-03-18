from fastapi import APIRouter, HTTPException, status, Depends
from models.pydantic_models import SignupRequest, LoginRequest
from services.user_service import create_user, authenticate_user
from fastapi.security import OAuth2PasswordRequestForm
from core.security import create_access_token
from datetime import timedelta

router = APIRouter()


@router.post("/signup")
def signup(user: SignupRequest):
    try:
        return create_user(user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
def login(credentials: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    access_token = create_access_token(
        {"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=30)
    )
    return {"access_token": access_token, "token_type": "bearer"}





