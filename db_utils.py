import os
from pymongo import MongoClient
from bson import ObjectId
from flask_login import UserMixin
from flask import session

# Lazy connect reduces background threads until first use
client = MongoClient(os.getenv("MONGODB_URI"), connect=False)
db = client[os.getenv("MONGODB_DBNAME", "talktotext_db")]

users_col = db['users_col']
meetings_col = db['meetings_col']

def get_db():
    return db

class User(UserMixin):
    def __init__(self, id, username, fullname=None):
        self.id = id
        self.username = username
        self.fullname = fullname

def load_user(user_id):
    print(f"load_user called with user_id: {user_id}, type: {type(user_id)}")
    user = None
    try:
        oid = ObjectId(user_id)
        print(f"Converted to ObjectId: {oid}")
        user = users_col.find_one({'_id': oid})
        print(f"Query result by _id: {user}")
    except Exception as e:
        print(f"ObjectId conversion error: {e}")

    # Fallback via session username (optional)
    if not user:
        username_from_session = session.get('username')
        print(f"Session username: {username_from_session}")
        if username_from_session:
            user = users_col.find_one({'username': username_from_session})

    if user:
        print(f"Loaded user: {user['username']}, ID: {str(user['_id'])}")
        return User(str(user['_id']), user['username'], user.get('fullname'))

    print(f"No user found - Check Atlas for ID {user_id}")
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp3', 'wav', 'mp4'}

# Expose a safe closer for graceful shutdown
def close_mongo_client():
    try:
        client.close()
    except Exception:
        pass
