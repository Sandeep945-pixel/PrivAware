from fastapi import Depends, APIRouter, HTTPException, UploadFile, File
from jose import jwt, JWTError
from core.security import oauth2_scheme, SECRET_KEY
from models.pydantic_models import AskRequest
from services.model_handle import get_model_response_with_attention, sanity_check
from db.db import input_response_collection 
import time
import pandas as pd
import os

router = APIRouter()

@router.post("/ask")
async def ask_question(request: AskRequest, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        role = payload.get("role")
        username = payload.get("sub")

        if not role or not username:
            raise HTTPException(status_code=403, detail="Invalid token payload")

        modified_question = f"{role}: {request.question}"

        start_time = time.time()

        # model_outputs = get_model_response_with_attention(modified_question, role)
        model_outputs = get_model_response_with_attention(modified_question, role, username)
        total_time = round(time.time() - start_time, 2)
        
        input_response_collection.insert_one({
            "username": username,
            "role": role,
            "original_question": request.question,
            "injected_query": modified_question,
            "model_response": model_outputs["model_response"],
            "sanitized_response": model_outputs["sanitized_response"],
            "mongo_query_raw": model_outputs.get("mongo_query_raw", {}),     
            "mongo_query_rbac": model_outputs.get("mongo_query_rbac", {}),
            "final_response": model_outputs["final_response"],
            "inference_time": total_time,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        return {
            "final_response": model_outputs["final_response"]
        }

    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
