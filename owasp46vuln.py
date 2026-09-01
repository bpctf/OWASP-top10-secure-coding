import sqlite3
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel

app = FastAPI()

def init_db():
    connection = sqlite3.connect("vuln.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (1, 'alice', 'user', '123')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (2, 'bob', 'admin', 'admin123')")
    connection.commit()
    connection.close()

init_db()

def get_db():
    db = sqlite3.connect("vuln.db")
    try:
        yield db
    finally:
        db.close()

class LoginRequest(BaseModel):
    user: str
    password: str

@app.post("/login")
def login(creds: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    query = f"SELECT * FROM users WHERE username = '{creds.user}'"
    cursor = db.cursor()
    
    cursor.execute(query)
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username")
    
    user_id, username, _, password = user
    
    if password != creds.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    return {"success": True, "user": {"user_id": user_id, "username": username} }


