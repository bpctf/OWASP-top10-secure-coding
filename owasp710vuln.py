from fastapi import FastAPI, HTTPException, status, Depends, Header, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from pydantic import BaseModel

from slowapi.extension import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import argon2
import jwt
import os
import sqlite3

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

password_hasher = argon2.PasswordHasher()

SECRET_ENCODE_KEY = os.getenv("SECRET_KEY")

ALG = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def init_db():
    BOB_PASS = os.getenv("BOB_PASS")
    connection = sqlite3.connect("vuln.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, role TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (1, 'bob', 'admin', ?)", (password_hasher.hash(BOB_PASS),))
    connection.commit()
    connection.close()

init_db()

def get_db():
    db = sqlite3.connect("vuln.db")
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    user: str
    password: str

def username_query(username: str, db: sqlite3.Connection):
    try:
        username_query = "SELECT * FROM users WHERE username = ?"
        cursor = db.cursor()
        cursor.execute(username_query, (username,))
        return cursor
    except sqlite3.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error {str(err)}")

@app.post("/register")
@limiter.limit("2/minute")
def register(request: Request, creds: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    cursor = username_query(creds.user, db)
    user_info = cursor.fetchone()
    if user_info:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
    cursor.execute("INSERT INTO users (username, role, password) VALUES (?, 'user', ?)", (creds.user, password_hasher.hash(creds.password),))
    db.commit()

@app.post("/login")
@limiter.limit("2/minute")
def login(request: Request, db: sqlite3.Connection = Depends(get_db), login_data: OAuth2PasswordRequestForm = Depends()):
    query = "SELECT * FROM users WHERE username = ?"
    cursor = db.cursor()
    
    cursor.execute(query, (login_data.username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username")
    
    user_id, username, role, stored_hash = user
    
    try:
        password_hasher.verify(stored_hash, login_data.password)
            
        if password_hasher.check_needs_rehash(stored_hash):
            rehash = password_hasher.hash(login_data.password)
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (rehash, user_id,))
            db.commit()

    except argon2.exceptions.VerifyMismatchError:
             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    payload = {
        "username": username,
        "is_admin": role
    }

    token = jwt.encode(payload, SECRET_ENCODE_KEY, algorithm=ALG)

    return {"success": True, "access_token": token, "token_type": "bearer", "user": {"username": username} }

@app.get("/admin")
def admin(token: str = Depends(oauth2_scheme)):
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    if decoded_token['is_admin'] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not an admin")
    return {"message": "Welcome to the admin panel."}

