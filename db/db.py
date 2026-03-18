from pymongo import MongoClient
from core.config import MONGO_URI


client = MongoClient("")
db = client["LLM_Privacy_updated"]
collection = db["Privacy_updated"]
input_response_collection = db["Input_response"]
users_collection = db["Users"]
