import sqlite3
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from slowapi.extension import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import argon2
import os

app = FastAPI()

# Initialize our limiter and use the user's IP address.
limiter = Limiter(key_func=get_remote_address)

# Register the limiter with FastAPI
app.state.limiter = limiter

# Register an exception handler for our rate limiter.
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initializing Argon2id's secure password hasher.
password_hasher = argon2.PasswordHasher()

def init_db():
    """ Function to create and initialize our database on startup of the application.
    """
    ALICE_PASS = os.getenv("ALICE_PASS")
    BOB_PASS = os.getenv("BOB_PASS")
    
    connection = sqlite3.connect("secure.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (1, 'alice', 'user', ?)", (password_hasher.hash(ALICE_PASS),))
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (2, 'bob', 'admin', ?)", (password_hasher.hash(BOB_PASS),))
    connection.commit()
    connection.close()

# Call our database initialization function.
init_db()

def get_db():
    db = sqlite3.connect("secure.db")
    try:
        yield db
    finally:
        db.close()

class LoginRequest(BaseModel):
    """ Pydantic model to validate login credentials supplied by the user to the JSON body request.
    """
    user: str
    password: str

@app.post("/login")
@limiter.limit("2/minute")
def login(request: Request, creds: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """ Login endpoint for our application which simulates a login by a user.

        Args:
            request (Request): The raw HTTP request sent by the user's web browser. Used for our rate limiter.
            creds (LoginRequest): Uses our pydantic LoginRequest class to validate the information from the JSON body request.
            db (sqlite3.Connection): Depends on our get_db() function to get an active database connection to query.

        Returns:
            dict: Returns a dict object with user information and whether we were successful or not.
    """
    # Secure query.
    query_secure = "SELECT * FROM users WHERE username = ?"
    
    cursor = db.cursor() 

    # Execute secure query.
    cursor.execute(query_secure, (creds.user,))
    
    user = cursor.fetchone()

    http_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
     
    if not user:
        raise http_exception
    
    # Assign data from our database to variables. We won't be needing role.
    user_id, username, _, stored_hash = user
    
    # Use Argon2id's exception to catch the mismatch exception.
    try:
        # Verify the password input the user matches the one in the database.
        password_hasher.verify(stored_hash, creds.password)
        
        # Check if the password needs to be rehashed. If it does then rehash it and set it into the database.
        if password_hasher.check_needs_rehash(stored_hash):
            rehash = password_hasher.hash(creds.password)
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (rehash, user_id,))
            db.commit()
    
    # If passwords don't match throw an exception and let the user know.
    except argon2.exceptions.VerifyMismatchError:
        raise http_exception

    return {"success": True, "user": {"user_id": user_id, "username": username} }


