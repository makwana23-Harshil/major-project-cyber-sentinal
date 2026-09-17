import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)

# Access the main database
db = client.cyber_sentinel

def serialize_doc(doc):
    """Helper to convert MongoDB's _id to a string for JSON serialization"""
    if doc and '_id' in doc:
        doc['id'] = str(doc['_id'])
        del doc['_id']
    return doc