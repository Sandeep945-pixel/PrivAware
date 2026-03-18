from db.db import db
from core.security import hash_password, verify_password
from db.db import users_collection


users_db = {}


def create_user(user):
    print("🔧 Creating user:", user.dict()) 
    if users_collection.find_one({"username": user.username}):
        raise ValueError("Username already exists.")

    user.password = hash_password(user.password)
    users_collection.insert_one(user.dict())
    return {"message": "User created successfully"}


def authenticate_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        return None
    return user



