import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Your Cloud MongoDB connection string
    MONGO_URI = "mongodb+srv://vedant_chaudhari_:LFMDOqhG9i7tqZsA@cluster0.wfkjxlq.mongodb.net/argus?retryWrites=true&w=majority&tls=true&ssl=true"

    # Database Name
    DB_NAME = "argus_db"

    # Collections
    USERS_COLLECTION = "users"
    SCANS_COLLECTION = "scans"
