from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel

from slowapi.extension import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import argon2
import jwt
import logging
import os
import sqlite3

# Setup a basic logging config that will append to our log file.
logging.basicConfig(
    filename='owasp710.log', # Name of the log file.
    filemode='a', # The mode; 'a' means we're appending to the file without removing previous entries.
    format = '%(asctime)s - %(levelname)s - %(message)s', # The format the message is logged: time - logging level - message.
    level=logging.INFO # The minimum logging level to log.
)

app = FastAPI()

# Initialize our limiter and use the user's IP address.
limiter = Limiter(key_func=get_remote_address)

# Register the limiter with FastAPI
app.state.limiter = limiter

# Key to encode our JWT token.
SECRET_ENCODE_KEY = os.getenv("SECRET_KEY")

# The encode algorithm to use. We use HS256 over RS256 because this is just a single simple program.
# If different independent services need to decode a payload then you use RS256.
ALG = "HS256"

# This tells FastAPI that we need a bearer token and it will exchange credentials for a token in the defined endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def handle_rate_limit_exceeded(request: Request, exc: RateLimitExceeded):
    """ Custom handler for when a user tries to exceed the rate limit.

        Raises:
            HTTPException: 
                429: Raises a 429 too many requests exception if rate limit is attempted to be exceeded.
    """
    client_ip = request.client.host if request.client else "Unknown IP"
    logging.warning(f"Rate limit exceeded by {client_ip} on endpoint {request.url.path}")

    raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Too many requests made. Please try again in 2 minutes. {str(exc)}")

# Register an exception handler for our rate limiter.
app.add_exception_handler(RateLimitExceeded, handle_rate_limit_exceeded)

# Initializing Argon2id's secure password hasher.
password_hasher = argon2.PasswordHasher()

def init_db():
    """ Function to create and initialize our database on startup of the application.

        Raises:
            sqlite3.DatabaseError: Catch and raise a database error if the database encounters a database specific error.
            Exception: Catch and raise any general errors that get encountered.
    """
    BOB_PASS = os.getenv("BOB_PASS")

    if not BOB_PASS:
        logging.error("Cannot find environment variable for BOB_PASS")
        raise ValueError("Missing environment variable BOB_PASS")
    
    connection = None
    try:
        connection = sqlite3.connect("secure.db")
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, role TEXT, password TEXT)")
        cursor.execute("INSERT OR IGNORE INTO users (id, username, role, password) VALUES (1, 'bob', 'admin', ?)", (password_hasher.hash(BOB_PASS),))
        connection.commit()
    except sqlite3.Error as err:
        if connection:
            connection.rollback()
        logging.error(f"Database encountered an error on intialization {str(err)}")
        raise sqlite3.DatabaseError("Database encountered an error. Rolling back additions")
    except Exception as ex:
        logging.error(f"Database encountered an unexpected exception {str(ex)}")
        raise Exception("Database encountered an unexpected error")
    finally:
        if connection:
            connection.close()

# Call our database initialization function.
init_db()

def get_db():
    """ Connect to our database, hold it open, and then close it when our function ends. 
    """
    db = sqlite3.connect("secure.db")
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    """ Pydantic model to validate registration credentials supplied by the user to the JSON body request.
    """
    user: str
    password: str

def username_query(username: str, db: sqlite3.Connection):
    """ Helper function to return a Cursor object which allows us to access our username query.

        Args:
            username (str): The username to query our database with.
            db (sqlite3.Connection): Connection to our database.

        Returns:
            Cursor: Return a Cursor object created from our database.

        Raises:
            HTTPException: 
                500: If an error occurs with our database return a 500 internal server error.
    """
    try:
        username_query = "SELECT * FROM users WHERE username = ?"
        cursor = db.cursor()
        cursor.execute(username_query, (username,))
        return cursor
    except sqlite3.Error as err:
        logging.error(f"Database query has encountered an error {str(err)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error")

@app.post("/register")
@limiter.limit("2/minute")
def register(request: Request, creds: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    """ Register endpoint for our application which simulates a user registration form.

        Args:
            request (Request): The raw HTTP request sent by the user's web browser. Used for our rate limiter.
            creds (RegisterRequest): Uses our pydantic RegisterRequest class to validate the information from the JSON body request.
            db (sqlite3.Connection): Depends on our get_db() function to get an active database connection to query.
        
        Returns:
            dict: Returns a dict object with user information and whether registration was successful or not.
        
        Raises:
            HTTPException:
                409: An HTTP 409 conflict exception is raised if a user with the same name already exists.
                400: An HTTP 400 bad request is raised if password requirements are not met.
    """
    cursor = username_query(creds.user, db)
    request_ip = request.client.host if request.client else "Unknown IP"
    
    user_info = cursor.fetchone()
    if user_info:
        logging.warning(f"User {creds.user} already exists request from {request_ip}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
    
    if len(creds.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be 8 or more characters long. Please try again.")

    if creds.password in ['12345678', '123456789', '1234567890', 'password', 'qwerty12', 'qwerty123']:
        logging.error(f"User {creds.user} tried to create a common password from {request.client.host if request.client else 'Unknown IP'}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too common, please select another password")

    cursor.execute("INSERT INTO users (username, role, password) VALUES (?, 'user', ?)", (creds.user, password_hasher.hash(creds.password),))
    db.commit()
    
    logging.info("User {creds.user} created by {request_ip}")
    return {"message": "Registration successful", "user": {"username": creds.user} }

@app.post("/login")
@limiter.limit("2/minute")
def login(request: Request, db: sqlite3.Connection = Depends(get_db), login_data: OAuth2PasswordRequestForm = Depends()):
    """ Login endpoint for our application which simulates a login by a user.

        Args:
            request (Request): The raw HTTP request sent by the user's web browser. Used for our rate limiter.
            creds (LoginRequest): Uses our pydantic LoginRequest class to validate the information from the JSON body request.
            db (sqlite3.Connection): Depends on our get_db() function to get an active database connection to query.

        Returns:
            dict: Returns a dict object with user information and whether we were successful or not.
        
        Raises:
            HTTPException: 
                401: A 401 unauthorized exception is raised if an issue with the login arises.
            ValueError: Missing the secret key for signing our token.
    """
    # Secure query.
    query_secure = "SELECT * FROM users WHERE username = ?"
    
    cursor = db.cursor() 

    # Execute secure query.
    cursor.execute(query_secure, (login_data.username,))
    
    user = cursor.fetchone()

    http_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
     
    if not user:
        logging.error(f"Wrong username submitted from {request.client.host if request.client else "Unknown IP"}")
        raise http_exception
    
    # Assign data from our database to variables. We won't be needing role.
    user_id, username, role, stored_hash = user
    
    print(user_id, username, role, stored_hash)

    # Use Argon2id's exception to catch the mismatch exception.
    try:
        # Verify the password input the user matches the one in the database.
        password_hasher.verify(stored_hash, login_data.password)
        
        # Check if the password needs to be rehashed. If it does then rehash it and set it into the database.
        if password_hasher.check_needs_rehash(stored_hash):
            rehash = password_hasher.hash(login_data.password)
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (rehash, user_id,))
            db.commit()
    
    # If passwords don't match throw an exception and let the user know.
    except argon2.exceptions.VerifyMismatchError:
        logging.error(f"Wrong password for {username} submitted from {request.client.host if request.client else "Unknown IP"}")
        raise http_exception

    payload = {
        "username": username,
        "is_admin": role,
        "expiration": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    }
    
    if not SECRET_ENCODE_KEY:
        logging.error("Missing 'SECRET_KEY' to encode jwt")
        raise ValueError("Missing 'SECRET_KEY' to encode jwt")

    token = jwt.encode(payload, SECRET_ENCODE_KEY, algorithm=ALG)
    
    logging.info(f"User {username} logged in successfully from {request.client.host if request.client else "Unknown IP"}")

    return {"success": True, "access_token": token, "token_type": "bearer", "user": {"user_id": user_id, "username": username} }

@app.get("/admin")
def admin(token: str = Depends(oauth2_scheme)):
    """ Admin endpoint to check if the user has admin privileges or not.

        Returns:
            dict: Returns a message if the user is an admin.

        Raises:
            HTTPException: 
                403: Raise a 403 forbidden error if the user is not an admin.
                401: Raise a 401 unauthorized error if the token is invalid.
    """
    try:
        decoded_token = jwt.decode(token, SECRET_ENCODE_KEY, algorithms=[ALG])
        
        is_admin = decoded_token['is_admin']
        username = decoded_token['username']
        
        if not is_admin:
            logging.error("is_admin not present in decoded token")
            raise ValueError("Malformed token.")

        if not username:
            logging.error("username not present in decoded token")
            raise ValueError("Malformed token.")
        
        if decoded_token['is_admin'].lower() != "admin":
            logging.error(f"Non admin user {decoded_token['username']} attempted to access the admin page")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not an admin")

        logging.info(f"User {username} accessed admin panel.")

        return {"message": "Welcome to the admin panel."}
    
    # Raise an expired signature exception if the timer from our payload has gone over.
    # This is automatically handled by JWT.
    except jwt.ExpiredSignatureError as expse:
        logging.error(f"Token signature expired: {str(expse)}")
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Token has expired. Please login again",
            headers = {"WWW-Authenticate": "Bearer"}
        )
    
    # Raise an invalid token exception is something else goes wrong.
    except jwt.InvalidTokenError as ite:
        logging.error(f"Invalid token {str(ite)}")
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Could not validate credentials",
            headers = {"WWW-Authenticate": "Bearer"},
        )

